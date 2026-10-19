package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"github.com/klppl/valv/core"
	"golang.org/x/sys/unix"
)

var (
	errExists     = errors.New("already exists")
	errNotRegular = errors.New("not a regular file")
)

var partFileRE = regexp.MustCompile(`^\.valv-[0-9a-f]{16}\.part$`)

// junkNames are the OS junk names of SPEC 8, plus the "._" prefix.
var junkNames = map[string]bool{
	".DS_Store": true, ".Spotlight-V100": true, ".Trashes": true, ".fseventsd": true,
	"Thumbs.db": true, "desktop.ini": true, ".localized": true,
}

func isJunk(e os.DirEntry) bool {
	name := e.Name()
	return (junkNames[name] || strings.HasPrefix(name, "._")) && (e.Type().IsRegular() || e.Type().IsDir())
}

func isPartFile(e os.DirEntry) bool {
	return partFileRE.MatchString(e.Name()) && e.Type().IsRegular()
}

func display(p string) string {
	for _, r := range p {
		if !unicode.IsPrint(r) {
			return strconv.Quote(p)
		}
	}
	return p
}

// dirHandle is an open directory. Every read and write happens relative to it,
// so the directory opened at startup is never resolved by path again (SPEC 8).
type dirHandle struct {
	f    *os.File
	path string // for messages only; never resolved again
}

func (d *dirHandle) fd() int { return int(d.f.Fd()) }

func (d *dirHandle) Close() error { return d.f.Close() }

// openInboxDir opens the Mode B inbox directory once with no-follow, checks
// that it is not a vault root (no vault.json or objects/), removes any stale
// .valv-*.part files from an earlier crash, and warns about unrecognized files.
func openInboxDir(p string, stderr io.Writer) (*dirHandle, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			if st, lerr := os.Lstat(p); lerr == nil && st.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%s is a symlink; give the real inbox directory", display(p))
			}
			return nil, fmt.Errorf("%s is not a directory", display(p))
		}
		return nil, err
	}
	d := &dirHandle{f: f, path: p}
	entries, err := d.list()
	if err != nil {
		d.Close()
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if name == core.ConfigFile || name == core.ObjectsDir {
			d.Close()
			return nil, fmt.Errorf("%s contains %s; refuse to run Mode B server on a vault root", display(p), name)
		}
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case isPartFile(e):
			_ = d.unlink(name)
		case isJunk(e):
		case e.Type().IsRegular():
			if _, err := core.ParseInboxName(name); err != nil && stderr != nil {
				fmt.Fprintf(stderr, "valvd: warning: unexpected file in inbox directory (ignored): %s\n", display(name))
			}
		default:
			if stderr != nil {
				fmt.Fprintf(stderr, "valvd: warning: unexpected entry in inbox directory (ignored): %s\n", display(name))
			}
		}
	}
	return d, nil
}

// list returns d's entries through a duped descriptor so it is safe to call
// concurrently.
func (d *dirHandle) list() ([]os.DirEntry, error) {
	fd, err := unix.Openat(d.fd(), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), d.path)
	defer f.Close()
	return f.ReadDir(-1)
}

func (d *dirHandle) lstat(name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(d.fd(), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}

func (d *dirHandle) openFile(name string) (*os.File, int64, error) {
	fd, err := unix.Openat(d.fd(), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, 0, errNotRegular
		}
		return nil, 0, &fs.PathError{Op: "open", Path: filepath.Join(d.path, name), Err: err}
	}
	f := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
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

func (d *dirHandle) unlink(name string) error {
	return unix.Unlinkat(d.fd(), name, 0)
}

// listInboxIDs returns sorted hex file_ids of all valid regular .inb files in
// d, and the total count of .inb + .part entries for quota checking.
func (d *dirHandle) listInboxIDs() (ids []string, activeFiles int, err error) {
	entries, err := d.list()
	if err != nil {
		return nil, 0, err
	}
	ids = []string{}
	for _, e := range entries {
		if isJunk(e) {
			continue
		}
		if isPartFile(e) {
			activeFiles++
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		id, err := core.ParseInboxName(e.Name())
		if err != nil {
			continue
		}
		activeFiles++
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	return ids, activeFiles, nil
}

func createTempAt(d *dirHandle) (string, *os.File, error) {
	for range 8 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", nil, err
		}
		name := ".valv-" + hex.EncodeToString(b[:]) + core.PartSuffix
		fd, err := unix.Openat(d.fd(), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, &fs.PathError{Op: "create", Path: filepath.Join(d.path, name), Err: err}
		}
		return name, os.NewFile(uintptr(fd), filepath.Join(d.path, name)), nil
	}
	return "", nil, errors.New("could not create a temp file")
}

func moveNoReplaceAt(d *dirHandle, tmp, name string) error {
	err := unix.Linkat(d.fd(), tmp, d.fd(), name, 0)
	if err == nil {
		_ = d.unlink(tmp)
		return nil
	}
	if errors.Is(err, unix.EEXIST) {
		return errExists
	}
	if _, serr := d.lstat(name); serr == nil {
		return errExists
	}
	return unix.Renameat(d.fd(), tmp, d.fd(), name)
}

// writeInboxAt writes a sealed inbox file to a .valv-<16 hex>.part temp file in d,
// syncs and verifies it by reopening through d, then moves it to <id>.inb
// without replacing an existing file.
func writeInboxAt(d *dirHandle, reg *tempRegistry, fill func(w io.Writer) (core.FileID, int64, error)) (id core.FileID, err error) {
	tmp, f, err := createTempAt(d)
	if err != nil {
		return core.FileID{}, err
	}
	reg.register(tmp, func() { _ = d.unlink(tmp) })
	defer reg.unregister(tmp)
	defer func() {
		if err != nil {
			if f != nil {
				_ = f.Close()
			}
			_ = d.unlink(tmp)
		}
	}()
	id, written, err := fill(f)
	if err != nil {
		return core.FileID{}, err
	}
	if err = f.Sync(); err != nil {
		return core.FileID{}, err
	}
	err = f.Close()
	f = nil
	if err != nil {
		return core.FileID{}, err
	}
	// Reopen through the directory handle to verify the written regular file.
	r, size, err := d.openFile(tmp)
	if err != nil {
		return core.FileID{}, err
	}
	_ = r.Close()
	if size != written {
		err = errors.New("temp file size mismatch on read-back")
		return core.FileID{}, err
	}
	finalName := core.InboxName(id)
	if err = moveNoReplaceAt(d, tmp, finalName); err != nil {
		return core.FileID{}, err
	}
	_ = d.f.Sync()
	return id, nil
}

// tempRegistry tracks active .part files and cleanup hooks for signal handling.
type tempRegistry struct {
	mu    sync.Mutex
	temps map[string]func()
	hooks []func()
}

func newTempRegistry() *tempRegistry {
	return &tempRegistry{temps: map[string]func(){}}
}

func (r *tempRegistry) register(name string, remove func()) {
	r.mu.Lock()
	r.temps[name] = remove
	r.mu.Unlock()
}

func (r *tempRegistry) unregister(name string) {
	r.mu.Lock()
	delete(r.temps, name)
	r.mu.Unlock()
}

func (r *tempRegistry) addHook(fn func()) {
	r.mu.Lock()
	r.hooks = append(r.hooks, fn)
	r.mu.Unlock()
}

func (r *tempRegistry) cleanupAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, remove := range r.temps {
		remove()
		delete(r.temps, name)
	}
	for i := len(r.hooks) - 1; i >= 0; i-- {
		r.hooks[i]()
	}
	r.hooks = nil
}

var handledSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

func installSignalCleanup(reg *tempRegistry, exit func(int)) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, handledSignals...)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-ch:
			reg.cleanupAll()
			exit(128 + int(sig.(syscall.Signal)))
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
