package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/klppl/valv/core"
	"golang.org/x/sys/unix"
)

// dirHandle is an open directory. Every write happens relative to one, so the
// directory that was checked is the directory that is written (SPEC 8).
type dirHandle struct {
	f    *os.File
	path string // for messages only; never resolved again
}

func (d *dirHandle) fd() int { return int(d.f.Fd()) }

func (d *dirHandle) Close() error { return d.f.Close() }

// openDir opens a directory path as the OS resolves it: symlinks and ".."
// (also ".." after a symlink) are resolved physically, never lexically.
func openDir(p string) (*dirHandle, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	return &dirHandle{f: f, path: p}, nil
}

// openVaultDir opens a vault directory once, at the start of a command
// (SPEC 8): no-follow, so a vault path whose last component is a symlink is
// refused.
func openVaultDir(p string) (*dirHandle, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// Linux reports a symlink as ELOOP, macOS (with O_DIRECTORY) as
		// ENOTDIR; lstat only tells the two cases apart for the message.
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			if st, lerr := os.Lstat(p); lerr == nil && st.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%s is a symlink; give the real vault directory", display(p))
			}
			return nil, fmt.Errorf("%s is not a directory", display(p))
		}
		return nil, err
	}
	return &dirHandle{f: f, path: p}, nil
}

// list returns d's entries, read through a fresh handle on d so it can be
// called repeatedly. Only Name and Type may be used: Info would resolve paths.
func (d *dirHandle) list() ([]os.DirEntry, error) {
	fd, err := unix.Openat(d.fd(), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), d.path)
	defer f.Close()
	return f.ReadDir(-1)
}

// identity returns the device and inode of the open directory.
func (d *dirHandle) identity() (devIno, error) {
	var st unix.Stat_t
	if err := unix.Fstat(d.fd(), &st); err != nil {
		return devIno{}, err
	}
	return identity(&st), nil
}

// openFileRel opens the regular file at a "/"-separated path relative to d,
// opening each directory on the way without following symlinks.
func (d *dirHandle) openFileRel(rel string) (*os.File, int64, error) {
	parts := strings.Split(rel, "/")
	cur := d
	for _, p := range parts[:len(parts)-1] {
		h, err := cur.openSub(p)
		if cur != d {
			cur.Close()
		}
		if err != nil {
			return nil, 0, err
		}
		cur = h
	}
	if cur != d {
		defer cur.Close()
	}
	return cur.openFile(parts[len(parts)-1])
}

// readConfig reads vault.json through d: a regular file of at most 4096 bytes.
func (d *dirHandle) readConfig() ([]byte, error) {
	f, _, err := d.openFile(core.ConfigFile)
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

// openSub opens the directory name inside d without following a symlink.
func (d *dirHandle) openSub(name string) (*dirHandle, error) {
	fd, err := unix.Openat(d.fd(), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%s: %s", display(filepath.Join(d.path, name)), symlinkedDir)
		}
		return nil, &fs.PathError{Op: "open", Path: filepath.Join(d.path, name), Err: err}
	}
	return &dirHandle{f: os.NewFile(uintptr(fd), filepath.Join(d.path, name)), path: filepath.Join(d.path, name)}, nil
}

// mkdirSub creates the directory name inside d (mode 0700) unless it exists,
// then opens it without following a symlink. created reports a new directory.
func (d *dirHandle) mkdirSub(name string) (h *dirHandle, created bool, err error) {
	err = unix.Mkdirat(d.fd(), name, 0o700)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, false, &fs.PathError{Op: "mkdir", Path: filepath.Join(d.path, name), Err: err}
	}
	h, oerr := d.openSub(name)
	return h, err == nil, oerr
}

// lstat stats name inside d without following a symlink.
func (d *dirHandle) lstat(name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(d.fd(), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}

// openFile opens the regular file name inside d for reading: no symlinks, no
// blocking on a FIFO.
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

// unlink removes the file name inside d.
func (d *dirHandle) unlink(name string) error { return unix.Unlinkat(d.fd(), name, 0) }

type devIno struct{ dev, ino uint64 }

func identity(st *unix.Stat_t) devIno { return devIno{uint64(st.Dev), uint64(st.Ino)} }

// within reports whether d is the directory with identity v or below it. It
// walks up from the open handle through ".." to the file system root, so no
// path is resolved (SPEC 5.4).
func (d *dirHandle) within(v devIno) (bool, error) {
	cur, err := unix.Dup(d.fd())
	if err != nil {
		return false, err
	}
	for {
		var st unix.Stat_t
		if err := unix.Fstat(cur, &st); err != nil {
			unix.Close(cur)
			return false, err
		}
		if identity(&st) == v {
			unix.Close(cur)
			return true, nil
		}
		parent, err := unix.Openat(cur, "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		unix.Close(cur)
		if err != nil {
			return false, err
		}
		var pst unix.Stat_t
		if err := unix.Fstat(parent, &pst); err != nil {
			unix.Close(parent)
			return false, err
		}
		if identity(&pst) == identity(&st) { // ".." of the root is the root
			unix.Close(parent)
			return false, nil
		}
		cur = parent
	}
}

// splitPath splits a user path into its directory part and final name
// without cleaning it, so ".." keeps its physical meaning.
func splitPath(p string) (dir, name string) {
	i := strings.LastIndexByte(p, '/')
	switch {
	case i < 0:
		return ".", p
	case i == 0:
		return "/", p[1:]
	}
	return p[:i], p[i+1:]
}

var (
	errOutputIsDir = errors.New("the output path is a directory; give a file name")
	errInsideVault = errors.New("refusing to write inside the vault directory; choose another output location with -o")
)

// openOutput opens the directory an output file will be written in and
// checks it before anything is created (SPEC 5.4): the final name must be a
// file name, must not resolve to an existing directory, and the directory
// must not be the vault directory (identity vault) or inside it.
func openOutput(out string, vault devIno) (*dirHandle, string, error) {
	dir, name := splitPath(out)
	if name == "" || name == "." || name == ".." {
		return nil, "", errOutputIsDir
	}
	d, err := openOutputDir(dir, vault)
	if err != nil {
		return nil, "", err
	}
	if err := checkOutputName(d, name); err != nil {
		d.Close()
		return nil, "", err
	}
	return d, name, nil
}

// openOutputDir opens an output directory and refuses it if it is the vault
// directory or inside it.
func openOutputDir(dir string, vault devIno) (*dirHandle, error) {
	d, err := openDir(dir)
	if err != nil {
		return nil, err
	}
	if err := checkOutside(d, vault); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// checkOutside walks up from the open handle and refuses if it reaches the
// vault directory.
func checkOutside(d *dirHandle, vault devIno) error {
	inside, err := d.within(vault)
	if err != nil {
		return err
	}
	if inside {
		return errInsideVault
	}
	return nil
}

// checkOutputName refuses an output name that is an existing directory.
func checkOutputName(d *dirHandle, name string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd(), name, &st, 0); err == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
		return errOutputIsDir
	}
	return nil
}

// writeOpts control writeAt.
type writeOpts struct {
	overwrite bool                 // replace an existing name
	mtime     *time.Time           // set on the file before it is moved into place
	check     func(*os.File) error // verify the finished temp file, reopened through the handle
	// beforeRename runs immediately before the temp file is moved into place.
	beforeRename func() error
}

// writeAt writes name inside d through a temp file in d: fill writes the
// content, the file is synced, reopened through d and checked, then moved
// into place with renameat (or linkat when it must not replace anything).
// On any error, or on a handled signal, the temp file is removed. An
// existing symlink or hard link at name is replaced, never followed.
func writeAt(d *dirHandle, name string, opts writeOpts, fill func(io.Writer) error) (err error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return fmt.Errorf("invalid file name %q", name)
	}
	if !opts.overwrite {
		if _, err := d.lstat(name); err == nil {
			return errExists
		}
	}
	tmp, f, err := createTempAt(d)
	if err != nil {
		return err
	}
	key := filepath.Join(d.path, tmp)
	registerTemp(key, func() { d.unlink(tmp) })
	defer unregisterTemp(key)
	defer func() {
		if err != nil {
			if f != nil {
				f.Close()
			}
			d.unlink(tmp)
		}
	}()
	if err = fill(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	f = nil
	if err != nil {
		return err
	}
	if opts.mtime != nil {
		ts := []unix.Timespec{unix.NsecToTimespec(time.Now().UnixNano()), unix.NsecToTimespec(opts.mtime.UnixNano())}
		if err = unix.UtimesNanoAt(d.fd(), tmp, ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
	}
	if opts.check != nil {
		r, _, err := d.openFile(tmp)
		if err != nil {
			return err
		}
		err = opts.check(r)
		r.Close()
		if err != nil {
			return err
		}
	}
	if opts.beforeRename != nil {
		if err = opts.beforeRename(); err != nil {
			return err
		}
	}
	if opts.overwrite {
		err = unix.Renameat(d.fd(), tmp, d.fd(), name)
	} else {
		err = moveNoReplaceAt(d, tmp, name)
	}
	if err != nil {
		return err
	}
	d.f.Sync()
	return nil
}

// createTempAt makes a temp file in d named .valv-<16 hex>.part: exclusive,
// never through a symlink, mode 0600 (SPEC 8).
func createTempAt(d *dirHandle) (string, *os.File, error) {
	for range 8 {
		var b [8]byte
		rand.Read(b[:])
		name := ".valv-" + hex.EncodeToString(b[:]) + core.PartSuffix
		fd, err := unix.Openat(d.fd(), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, &fs.PathError{Op: "create", Path: filepath.Join(d.path, name), Err: err}
		}
		// L10: a live temp file is locked for as long as it is open, so a concurrent
		// run's stale-file cleanup can tell it from a leftover.
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			unix.Close(fd)
			d.unlink(name)
			return "", nil, &fs.PathError{Op: "lock", Path: filepath.Join(d.path, name), Err: err}
		}
		return name, os.NewFile(uintptr(fd), filepath.Join(d.path, name)), nil
	}
	return "", nil, errors.New("could not create a temp file")
}

// staleTempAge is how old (by mtime) an unlocked .valv-*.part file must be before cleanup
// removes it.
const staleTempAge = 10 * time.Minute

// removeIfStale deletes the temp file name in d only if it is a regular file, older than
// staleTempAge, and nobody holds its advisory lock (a running valv process keeps its temp
// file locked while it is open). It reports whether it deleted the file.
func (d *dirHandle) removeIfStale(name string) bool {
	fd, err := unix.Openat(d.fd(), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close() // also drops the lock
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || time.Since(st.ModTime()) < staleTempAge {
		return false
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return false // somebody is writing it right now
	}
	return d.unlink(name) == nil
}

// moveNoReplaceAt moves tmp to name inside d unless name exists. A hard link
// makes the check atomic; without hard links it falls back to
// check-then-rename.
func moveNoReplaceAt(d *dirHandle, tmp, name string) error {
	err := unix.Linkat(d.fd(), tmp, d.fd(), name, 0)
	if err == nil {
		d.unlink(tmp)
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

// objectsDirFor opens objects/<prefix> under the vault handle for writing,
// creating it if needed, without following symlinks at any step (SPEC 8).
func objectsDirFor(v *dirHandle, id core.FileID) (*dirHandle, string, error) {
	o, err := v.openSub(core.ObjectsDir)
	if err != nil {
		return nil, "", err
	}
	defer o.Close()
	s := id.String()
	xx, _, err := o.mkdirSub(s[:2])
	if err != nil {
		return nil, "", err
	}
	return xx, s + core.ObjectExt, nil
}
