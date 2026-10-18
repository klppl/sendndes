package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klppl/valv/core"
)

// writeAtomic writes dst through dst.part: fill writes the content, the file
// is synced, mtime is set if given, then it is renamed into place. On any
// error the .part file is removed and nothing is left behind. Unless
// overwrite is set, an existing dst is an error.
func writeAtomic(dst string, overwrite bool, mtime *time.Time, fill func(io.Writer) error) (err error) {
	if !overwrite {
		if _, err := os.Lstat(dst); err == nil {
			return errExists
		}
	}
	part := dst + core.PartSuffix
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if err != nil {
			if !closed {
				f.Close()
			}
			os.Remove(part)
		}
	}()
	if err = fill(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	closed = true
	if err = f.Close(); err != nil {
		return err
	}
	if mtime != nil {
		if err = os.Chtimes(part, time.Now(), *mtime); err != nil {
			return err
		}
	}
	if !overwrite {
		if _, statErr := os.Lstat(dst); statErr == nil {
			return errExists
		}
	}
	if err = os.Rename(part, dst); err != nil {
		return err
	}
	syncDir(filepath.Dir(dst))
	return nil
}

var errExists = errors.New("the output file already exists (use --force to replace it)")

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// vaultFile is an object or inbox file found in the vault.
type vaultFile struct {
	rel string // "/"-separated path relative to the vault root
	abs string
	id  core.FileID
}

// scan is the result of walking a vault directory (SPEC 4.1, 8).
type scan struct {
	objects    []vaultFile
	inbox      []vaultFile
	partial    []string // *.part files: incomplete writes
	unexpected []string // "rel: reason"
}

// scanVault lists a vault's files and sorts out anything that does not
// belong. It does not decrypt anything.
func scanVault(dir string) (*scan, error) {
	s := &scan{}
	root, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range root {
		name := e.Name()
		switch {
		case name == core.ConfigFile && e.Type().IsRegular():
		case name == core.ObjectsDir && e.IsDir():
			if err := s.scanObjects(dir); err != nil {
				return nil, err
			}
		case name == core.InboxDir && e.IsDir():
			if err := s.scanInbox(dir); err != nil {
				return nil, err
			}
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
		s.partial = append(s.partial, rel)
		return
	}
	s.unexpected = append(s.unexpected, rel+": unexpected file")
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
		if !e.IsDir() || !isPrefixDir(e.Name()) {
			s.classifyOther(rel, e)
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		for _, f := range files {
			frel := path.Join(rel, f.Name())
			if !f.Type().IsRegular() || strings.HasSuffix(f.Name(), core.PartSuffix) {
				s.classifyOther(frel, f)
				continue
			}
			id, err := core.ParseObjectPath(frel)
			if err != nil {
				s.unexpected = append(s.unexpected, frel+": "+err.Error())
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
		if !e.Type().IsRegular() || strings.HasSuffix(e.Name(), core.PartSuffix) {
			s.classifyOther(rel, e)
			continue
		}
		id, err := core.ParseInboxName(e.Name())
		if err != nil {
			s.unexpected = append(s.unexpected, rel+": "+err.Error())
			continue
		}
		s.inbox = append(s.inbox, vaultFile{rel, filepath.Join(dir, e.Name()), id})
	}
	return s, nil
}

// openSized opens a file and returns it with its size.
func openSized(p string) (*os.File, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func readObjectInfo(f vaultFile, keys *core.VaultKeys) (core.ObjectInfo, error) {
	r, size, err := openSized(f.abs)
	if err != nil {
		return core.ObjectInfo{}, err
	}
	defer r.Close()
	return core.ReadObjectInfo(r, size, f.id, keys)
}

// readPrefix returns up to the first n bytes of a file.
func readPrefix(p string, n int) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, n)
	k, err := io.ReadFull(f, b)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return b[:k], nil
}

func fmtProblem(rel string, err error) string {
	return fmt.Sprintf("%s: %v", rel, err)
}
