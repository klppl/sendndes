package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"github.com/klppl/valv/core"
)

var errExists = errors.New("already exists")

// errNotRegular: a vault path is a symlink, FIFO, device or directory.
var errNotRegular = errors.New("not a regular file")

// maxConfigSize caps how much of vault.json is read (SPEC 4.2).
const maxConfigSize = 4096

// openRegular opens a vault file for reading. It never follows a symlink,
// never blocks on a FIFO, and refuses anything but a regular file.
func openRegular(p string) (*os.File, int64, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, 0, errNotRegular
		}
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, 0, errNotRegular
	}
	return f, st.Size(), nil
}

// readConfig reads a vault.json-sized file: regular, at most 4096 bytes.
func readConfig(p string) ([]byte, error) {
	f, _, err := openRegular(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", core.ConfigFile, maxConfigSize)
	}
	return data, nil
}

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
	rel string // "/"-separated path relative to the vault root
	abs string
	id  core.FileID
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
// objects/xx/ entries, checked without following symlinks (SPEC 8).
func dirProblems(dir string) []string {
	var probs []string
	for _, name := range []string{core.ObjectsDir, core.InboxDir} {
		st, err := os.Lstat(filepath.Join(dir, name))
		switch {
		case err != nil:
		case st.Mode()&os.ModeSymlink != 0:
			probs = append(probs, name+": "+symlinkedDir)
		case !st.IsDir():
			probs = append(probs, name+": not a directory")
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, core.ObjectsDir))
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
func requireRealDirs(dir string) error {
	if probs := dirProblems(dir); len(probs) > 0 {
		return errors.New(probs[0])
	}
	return nil
}

// scanVault lists a vault's files and sorts out anything that does not
// belong. It does not open or decrypt anything, and does not descend into
// symlinked directories (they are listed in symlinkDirs).
func scanVault(dir string) (*scan, error) {
	s := &scan{symlinkDirs: dirProblems(dir)}
	root, err := os.ReadDir(dir)
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
			if err := s.scanObjects(dir); err != nil {
				return nil, err
			}
		case name == core.InboxDir && e.IsDir():
			if err := s.scanInbox(dir); err != nil {
				return nil, err
			}
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

func (s *scan) scanObjects(dir string) error {
	entries, err := os.ReadDir(filepath.Join(dir, core.ObjectsDir))
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
		files, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(rel)))
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
			s.objects = append(s.objects, vaultFile{frel, filepath.Join(dir, filepath.FromSlash(frel)), id})
		}
	}
	return nil
}

func (s *scan) scanInbox(dir string) error {
	files, err := scanInboxDir(filepath.Join(dir, core.InboxDir), core.InboxDir)
	if err != nil {
		return err
	}
	s.inbox = files.inbox
	s.partial = append(s.partial, files.partial...)
	s.junk = append(s.junk, files.junk...)
	s.unexpected = append(s.unexpected, files.unexpected...)
	return nil
}

// scanInboxDir lists inbox files in dir; relPrefix is used in reports.
func scanInboxDir(dir, relPrefix string) (*scan, error) {
	s := &scan{}
	entries, err := os.ReadDir(dir)
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
		s.inbox = append(s.inbox, vaultFile{rel, filepath.Join(dir, e.Name()), id})
	}
	return s, nil
}

func readObjectInfo(f vaultFile, keys *core.VaultKeys) (core.ObjectInfo, error) {
	r, size, err := openRegular(f.abs)
	if err != nil {
		return core.ObjectInfo{}, err
	}
	defer r.Close()
	return core.ReadObjectInfo(r, size, f.id, keys)
}

func fmtProblem(rel string, err error) string {
	return fmt.Sprintf("%s: %v", display(rel), err)
}
