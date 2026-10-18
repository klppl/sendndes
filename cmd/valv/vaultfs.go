package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"github.com/klppl/valv/core"
	"golang.org/x/sys/unix"
)

var errExists = errors.New("already exists")

// errNotRegular: a vault path is a symlink, FIFO, device or directory.
var errNotRegular = errors.New("not a regular file")

// maxConfigSize caps how much of vault.json is read (SPEC 4.2).
const maxConfigSize = 4096

// What a signal handler must undo: temp files that exist right now, and
// hooks such as restoring the terminal or removing directories init created.
var cleanup = struct {
	sync.Mutex
	temps map[string]func()
	hooks map[int]func()
	next  int
}{temps: map[string]func(){}, hooks: map[int]func(){}}

// registerTemp records a temp file and how to remove it (relative to the
// directory handle it was created in).
func registerTemp(p string, remove func()) {
	cleanup.Lock()
	cleanup.temps[p] = remove
	cleanup.Unlock()
}

func unregisterTemp(p string) {
	cleanup.Lock()
	delete(cleanup.temps, p)
	cleanup.Unlock()
}

// addCleanupHook registers f to run on a handled signal, after temp files are
// removed. Hooks run newest first. The returned function unregisters f.
func addCleanupHook(f func()) (remove func()) {
	cleanup.Lock()
	id := cleanup.next
	cleanup.next++
	cleanup.hooks[id] = f
	cleanup.Unlock()
	return func() {
		cleanup.Lock()
		delete(cleanup.hooks, id)
		cleanup.Unlock()
	}
}

// runCleanup removes every registered temp file, then runs the hooks.
func runCleanup() {
	cleanup.Lock()
	defer cleanup.Unlock()
	for p, remove := range cleanup.temps {
		remove()
		delete(cleanup.temps, p)
	}
	ids := make([]int, 0, len(cleanup.hooks))
	for id := range cleanup.hooks {
		ids = append(ids, id)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ids)))
	for _, id := range ids {
		cleanup.hooks[id]()
		delete(cleanup.hooks, id)
	}
}

// handledSignals are cleaned up after and exit with 128 + the signal number
// (SPEC 8). SIGKILL cannot be handled.
var handledSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// installSignalCleanup runs runCleanup and exits on a handled signal. The
// returned function uninstalls the handler.
func installSignalCleanup(exit func(int)) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, handledSignals...)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-ch:
			runCleanup()
			exit(128 + int(sig.(syscall.Signal)))
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// display quotes a name that has characters a terminal would not show
// plainly (control, format and bidi characters). Used for every name from
// metadata and from the host's directory listings.
func display(p string) string {
	for _, r := range p {
		if !unicode.IsPrint(r) {
			return strconv.Quote(p)
		}
	}
	return p
}

// vaultFile is an object or inbox file found in the vault.
type vaultFile struct {
	rel  string // "/"-separated path relative to the scanned root (for reports and openFileRel)
	name string // final component
	id   core.FileID
}

// scan is the result of walking a vault directory (SPEC 4.1, 8).
type scan struct {
	objects     []vaultFile
	inbox       []vaultFile
	partial     []string // displayable paths of *.part files: incomplete writes
	junk        []string // displayable paths of OS junk (SPEC 8): notes only
	unexpected  []string // "displayable path: reason"
	symlinkDirs []string // "displayable path: symlinked directory in vault"
}

// junkNames are the OS junk names of SPEC 8, plus the "._" prefix.
var junkNames = map[string]bool{
	".DS_Store": true, ".Spotlight-V100": true, ".Trashes": true, ".fseventsd": true,
	"Thumbs.db": true, "desktop.ini": true, ".localized": true,
}

// isJunk reports whether a directory entry is OS junk: a listed name (or a
// "._" name) that is a regular file or a real directory. Junk is never
// opened, and a junk directory is not scanned.
func isJunk(e os.DirEntry) bool {
	name := e.Name()
	return (junkNames[name] || strings.HasPrefix(name, "._")) && (e.Type().IsRegular() || e.Type().IsDir())
}

const symlinkedDir = "symlinked directory in vault"

// dirProblems lists symlinked (or non-directory) objects/, inbox/ and
// objects/xx/ entries under the vault handle, checked without following
// symlinks (SPEC 8).
func dirProblems(v *dirHandle) []string {
	var probs []string
	for _, name := range []string{core.ObjectsDir, core.InboxDir} {
		st, err := v.lstat(name)
		switch {
		case err != nil:
		case st.Mode&unix.S_IFMT == unix.S_IFLNK:
			probs = append(probs, name+": "+symlinkedDir)
		case st.Mode&unix.S_IFMT != unix.S_IFDIR:
			probs = append(probs, name+": not a directory")
		}
	}
	o, err := v.openSub(core.ObjectsDir)
	if err != nil {
		return probs
	}
	defer o.Close()
	entries, err := o.list()
	if err != nil {
		return probs
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 && isPrefixDir(e.Name()) {
			probs = append(probs, display(path.Join(core.ObjectsDir, e.Name()))+": "+symlinkedDir)
		}
	}
	return probs
}

// requireRealDirs refuses a vault with a symlinked directory (SPEC 8).
func requireRealDirs(v *dirHandle) error {
	if probs := dirProblems(v); len(probs) > 0 {
		return errors.New(probs[0])
	}
	return nil
}

// scanVault lists a vault's files through its handle and sorts out anything
// that does not belong. It does not open or decrypt files, and does not
// descend into symlinked directories (they are listed in symlinkDirs).
func scanVault(v *dirHandle) (*scan, error) {
	s := &scan{symlinkDirs: dirProblems(v)}
	root, err := v.list()
	if err != nil {
		return nil, err
	}
	for _, e := range root {
		name := e.Name()
		symlink := e.Type()&os.ModeSymlink != 0
		switch {
		case name == core.ConfigFile && e.Type().IsRegular():
		case (name == core.ObjectsDir || name == core.InboxDir) && symlink:
			// reported by dirProblems
		case name == core.ObjectsDir && e.IsDir():
			if err := s.scanObjects(v); err != nil {
				return nil, err
			}
		case name == core.InboxDir && e.IsDir():
			in, err := v.openSub(core.InboxDir)
			if err != nil {
				return nil, err
			}
			files, err := scanInboxDir(in, core.InboxDir)
			in.Close()
			if err != nil {
				return nil, err
			}
			s.inbox = files.inbox
			s.partial = append(s.partial, files.partial...)
			s.junk = append(s.junk, files.junk...)
			s.unexpected = append(s.unexpected, files.unexpected...)
		case isJunk(e):
			s.junk = append(s.junk, display(name))
		default:
			s.classifyOther(name, e)
		}
	}
	sort.Slice(s.objects, func(i, j int) bool { return s.objects[i].rel < s.objects[j].rel })
	sort.Slice(s.inbox, func(i, j int) bool { return s.inbox[i].rel < s.inbox[j].rel })
	return s, nil
}

func (s *scan) classifyOther(rel string, e os.DirEntry) {
	if strings.HasSuffix(rel, core.PartSuffix) && e.Type().IsRegular() {
		s.partial = append(s.partial, display(rel))
		return
	}
	s.unexpected = append(s.unexpected, display(rel)+": unexpected file")
}

func isPrefixDir(name string) bool {
	return len(name) == 2 && strings.Trim(name, "0123456789abcdef") == ""
}

func (s *scan) scanObjects(v *dirHandle) error {
	o, err := v.openSub(core.ObjectsDir)
	if err != nil {
		return err
	}
	defer o.Close()
	entries, err := o.list()
	if err != nil {
		return err
	}
	for _, e := range entries {
		rel := path.Join(core.ObjectsDir, e.Name())
		switch {
		case isJunk(e):
			s.junk = append(s.junk, display(rel))
			continue
		case e.Type()&os.ModeSymlink != 0 && isPrefixDir(e.Name()):
			continue // reported by dirProblems
		case !e.IsDir() || !isPrefixDir(e.Name()):
			s.classifyOther(rel, e)
			continue
		}
		xx, err := o.openSub(e.Name())
		if err != nil {
			s.unexpected = append(s.unexpected, display(rel)+": "+err.Error())
			continue
		}
		files, err := xx.list()
		xx.Close()
		if err != nil {
			return err
		}
		for _, f := range files {
			frel := path.Join(rel, f.Name())
			if isJunk(f) {
				s.junk = append(s.junk, display(frel))
				continue
			}
			if !f.Type().IsRegular() || strings.HasSuffix(f.Name(), core.PartSuffix) {
				s.classifyOther(frel, f)
				continue
			}
			id, err := core.ParseObjectPath(frel)
			if err != nil {
				s.unexpected = append(s.unexpected, display(frel)+": "+err.Error())
				continue
			}
			s.objects = append(s.objects, vaultFile{frel, f.Name(), id})
		}
	}
	return nil
}

// scanInboxDir lists inbox files through the handle d; relPrefix is used in
// reports and is the prefix of each file's rel.
func scanInboxDir(d *dirHandle, relPrefix string) (*scan, error) {
	s := &scan{}
	entries, err := d.list()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		rel := path.Join(relPrefix, e.Name())
		if isJunk(e) {
			s.junk = append(s.junk, display(rel))
			continue
		}
		if !e.Type().IsRegular() || strings.HasSuffix(e.Name(), core.PartSuffix) {
			s.classifyOther(rel, e)
			continue
		}
		id, err := core.ParseInboxName(e.Name())
		if err != nil {
			s.unexpected = append(s.unexpected, display(rel)+": "+err.Error())
			continue
		}
		s.inbox = append(s.inbox, vaultFile{rel, e.Name(), id})
	}
	return s, nil
}

func readObjectInfo(v *dirHandle, f vaultFile, keys *core.VaultKeys) (core.ObjectInfo, error) {
	r, size, err := v.openFileRel(f.rel)
	if err != nil {
		return core.ObjectInfo{}, err
	}
	defer r.Close()
	return core.ReadObjectInfo(r, size, f.id, keys)
}

func fmtProblem(rel string, err error) string {
	return fmt.Sprintf("%s: %v", display(rel), err)
}
