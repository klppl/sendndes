package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/klppl/valv/core"
	"golang.org/x/text/unicode/norm"
)

func (a *app) cmdInit(args []string) error {
	fs := a.flags("init", false, true)
	pos, err := parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := pos[0]
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	pass, err := a.newPassphrase()
	if err != nil {
		return err
	}
	data, keys, recoveryKey, err := core.CreateVault(pass)
	if err != nil {
		return err
	}
	defer keys.Wipe()

	// Show the recovery key before anything is written (SPEC 4.3).
	if _, err := fmt.Fprintf(a.stdout, "Recovery key (shown once; store it offline):\n\n  %s\n\n", recoveryKey); err != nil {
		return fmt.Errorf("could not write the recovery key (%v); vault not created", err)
	}
	if a.interactive() {
		if err := a.confirmRecoveryKey(&keys.VK); err != nil {
			return fmt.Errorf("%w; vault not created", err)
		}
	}

	// Create the directories and write vault.json last. Until vault.json is
	// in place, an error or a handled signal removes exactly the directories
	// created here (SPEC 4.3).
	var created []string
	removeCreated := func() {
		for i := len(created) - 1; i >= 0; i-- {
			os.Remove(created[i]) // only empty directories; never anything else
		}
	}
	unhook := addCleanupHook(func() { removeCreated() })
	defer unhook()
	for _, d := range []string{dir, filepath.Join(dir, core.ObjectsDir), filepath.Join(dir, core.InboxDir)} {
		made, err := mkdirTracked(d)
		created = append(created, made...)
		if err != nil {
			removeCreated()
			return err
		}
	}
	cfgPath := filepath.Join(dir, core.ConfigFile)
	check := configChecker(pass, keys)
	err = writeAtomic(cfgPath, writeOpts{check: func(tmp string) error {
		if initTestHook != nil {
			if err := initTestHook(tmp); err != nil {
				return err
			}
		}
		return check(tmp)
	}}, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
	if err != nil {
		removeCreated()
		return fmt.Errorf("writing %s: %w; vault not created", core.ConfigFile, err)
	}
	unhook() // vault.json is committed: keep the directories from now on
	if _, err := fmt.Fprintf(a.stdout, "Created vault in %s. Unlock self-check passed.\n", dir); err != nil {
		return err
	}
	return nil
}

// initTestHook, if set (only by tests), runs inside init once the vault.json
// temp file exists and before it is committed.
var initTestHook func(tmp string) error

// mkdirTracked creates dir and any missing parents, mode 0700, and returns
// the directories it created, outermost first.
func mkdirTracked(dir string) ([]string, error) {
	var missing []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		missing = append(missing, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	var created []string
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o700); err != nil {
			return created, err
		}
		created = append(created, missing[i])
	}
	return created, nil
}

// configChecker returns a writeAtomic check that reads the temp vault.json
// back, unlocks it with pass and requires the expected VK (SPEC 4.4).
func configChecker(pass string, want *core.VaultKeys) func(string) error {
	return func(tmp string) error {
		data, err := readConfig(tmp)
		if err != nil {
			return err
		}
		c, err := core.ParseConfig(data)
		if err != nil {
			return err
		}
		got, err := core.Unlock(c, pass)
		if err != nil {
			return fmt.Errorf("written vault.json does not unlock: %w", err)
		}
		defer got.Wipe()
		if subtle.ConstantTimeCompare(got.VK[:], want.VK[:]) != 1 {
			return errors.New("written vault.json unlocks to a different key")
		}
		return nil
	}
}

func (a *app) cmdAdd(args []string) error {
	fs := a.flags("add", true, false)
	dirFlag := fs.String("dir", "", "folder inside the vault")
	nameFlag := fs.String("name", "", "file name inside the vault")
	pos, err := parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	src, err := os.OpenFile(pos[0], os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	before, err := src.Stat()
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", display(pos[0]))
	}
	name := *nameFlag
	if name == "" {
		name = filepath.Base(pos[0])
	}
	obj, err := core.PrepareObject(core.Metadata{
		Name:  name,
		Dir:   *dirFlag,
		MTime: before.ModTime().UnixNano(),
		MIME:  mimeType(name),
		Rev:   1,
	})
	if err != nil {
		return fmt.Errorf("%w (names must be non-empty, without / or NUL, not . or ..; --dir has no leading or trailing /)", err)
	}
	defer obj.Wipe()
	dir := a.vaultDir()
	if err := requireRealDirs(dir); err != nil {
		return err
	}
	keys, err := a.unlock(dir)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	dst := filepath.Join(dir, filepath.FromSlash(core.ObjectPath(obj.ID())))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	err = writeAtomic(dst, writeOpts{}, func(w io.Writer) error {
		return encryptSource(w, obj, keys, src, before)
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stdout, obj.ID())
	return err
}

// encryptSource encrypts src into w and then checks that src did not change
// while it was read (SPEC 5.4). This narrows the race; it cannot close it.
func encryptSource(w io.Writer, obj *core.NewObject, keys *core.VaultKeys, src *os.File, before os.FileInfo) error {
	bw := bufio.NewWriterSize(w, core.StoredChunkSize)
	if err := obj.Encrypt(bw, keys, src); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	after, err := src.Stat()
	if err != nil {
		return err
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return errors.New("the file changed while it was being read; nothing added")
	}
	return nil
}

// mimeType guesses a media type from the extension, without parameters.
func mimeType(name string) string {
	t := mime.TypeByExtension(filepath.Ext(name))
	if t == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(t)
	if err != nil {
		return ""
	}
	return mt
}

func logicalPath(m core.Metadata) string {
	if m.Dir == "" {
		return m.Name
	}
	return m.Dir + "/" + m.Name
}

func (a *app) cmdLs(args []string) error {
	fs := a.flags("ls", true, false)
	dirFlag := fs.String("dir", "", "only list this folder and its subfolders")
	if _, err := parse(fs, args, 0, 0); err != nil {
		return err
	}
	filter := norm.NFC.String(strings.Trim(*dirFlag, "/"))
	dir := a.vaultDir()
	if err := requireRealDirs(dir); err != nil {
		return err
	}
	keys, err := a.unlock(dir)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	s, err := scanVault(dir)
	if err != nil {
		return err
	}
	type row struct {
		path string
		info core.ObjectInfo
	}
	var rows []row
	problems := len(s.unexpected)
	for _, u := range s.unexpected {
		fmt.Fprintf(a.stderr, "warning: %s\n", u)
	}
	for _, f := range s.objects {
		info, err := readObjectInfo(f, keys)
		if err != nil {
			problems++
			fmt.Fprintf(a.stderr, "warning: %s\n", fmtProblem(f.rel, err))
			continue
		}
		d := norm.NFC.String(info.Meta.Dir)
		if filter != "" && d != filter && !strings.HasPrefix(d, filter+"/") {
			continue
		}
		rows = append(rows, row{logicalPath(info.Meta), info})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].path != rows[j].path {
			return rows[i].path < rows[j].path
		}
		return rows[i].info.ID.String() < rows[j].info.ID.String()
	})
	w := bufio.NewWriter(a.stdout)
	for _, r := range rows {
		mt := time.Unix(0, r.info.Meta.MTime).Format("2006-01-02 15:04:05")
		fmt.Fprintf(w, "%s  %12d  %s  %s\n", r.info.ID, r.info.PlaintextSize, mt, display(r.path))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if problems > 0 {
		return fmt.Errorf("%d problem(s) while listing; run valv verify", problems)
	}
	return nil
}

// openedTarget is an object opened once for get (review L3).
type openedTarget struct {
	f      vaultFile
	file   *os.File
	reader *core.ObjectReader
}

func (t *openedTarget) close() {
	t.reader.Close()
	t.file.Close()
}

func (a *app) cmdGet(args []string) error {
	fs := a.flags("get", true, false)
	out := fs.String("o", "", "output file, or - for stdout")
	force := fs.Bool("force", false, "replace an existing output file")
	unverified := fs.Bool("unverified-stream", false, "allow -o - (plaintext before authentication finishes)")
	pos, err := parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if *out == "-" && !*unverified {
		return errors.New("-o - writes plaintext before the file is authenticated; add --unverified-stream to accept that")
	}
	dir := a.vaultDir()
	if err := requireRealDirs(dir); err != nil {
		return err
	}
	if *out != "" && *out != "-" {
		if err := checkOutsideVault(*out, dir); err != nil {
			return err
		}
		if !*force {
			if _, err := os.Lstat(*out); err == nil {
				return errOutputExists
			}
		}
	}
	keys, err := a.unlock(dir)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	t, err := a.openTarget(dir, pos[0], keys)
	if err != nil {
		return err
	}
	defer t.close()
	meta := t.reader.Info().Meta

	if *out == "-" {
		// Plaintext goes out as it is decrypted; on error the output so far
		// is not trustworthy and the exit status says so.
		bw := bufio.NewWriterSize(a.stdout, core.ChunkSize)
		if err := t.reader.DecryptTo(bw); err != nil {
			return fmt.Errorf("%s: %w (output so far is invalid)", display(t.f.rel), err)
		}
		return bw.Flush()
	}
	dst := *out
	if dst == "" {
		if err := checkDefaultName(meta.Name); err != nil {
			return err
		}
		dst = meta.Name
		if err := checkOutsideVault(dst, dir); err != nil {
			return err
		}
	}
	mtime := time.Unix(0, meta.MTime)
	err = writeAtomic(dst, writeOpts{overwrite: *force, mtime: &mtime}, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, core.ChunkSize)
		if err := t.reader.DecryptTo(bw); err != nil {
			return err
		}
		return bw.Flush()
	})
	if errors.Is(err, errExists) {
		return errOutputExists
	}
	if err != nil {
		return fmt.Errorf("%s: %w", display(t.f.rel), err)
	}
	return nil
}

var errOutputExists = errors.New("the output file already exists (use --force to replace it)")

// checkDefaultName decides whether a stored name may be used as the output
// file name without an explicit -o (SPEC 5.4).
func checkDefaultName(name string) error {
	bad := len(name) > 200 || name == core.ConfigFile || strings.HasPrefix(name, ".") ||
		strings.HasPrefix(name, " ") || strings.HasSuffix(name, " ")
	for _, r := range name {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == '\\' || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			bad = true
		}
	}
	if bad {
		return errors.New("the stored name is not safe to use as a file name here; pass -o <path>")
	}
	return nil
}

// checkOutsideVault refuses an output path that is an existing directory, or
// whose temp-file directory is the vault directory or inside it, following
// symlinks (SPEC 5.4). Directories are compared by identity, so
// case-insensitive file systems are handled.
func checkOutsideVault(out, vault string) error {
	if st, err := os.Stat(out); err == nil && st.IsDir() {
		return errors.New("the output path is an existing directory; give a file name")
	}
	vst, err := os.Stat(vault)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	outDir, err := filepath.EvalSymlinks(tempDirFor(abs))
	if err != nil {
		return err
	}
	for d := outDir; ; d = filepath.Dir(d) {
		if st, err := os.Stat(d); err == nil && os.SameFile(st, vst) {
			return errors.New("refusing to write inside the vault directory; choose another output location with -o")
		}
		if filepath.Dir(d) == d {
			return nil
		}
	}
}

// openTarget resolves a file_id or a path inside the vault and opens the
// object once.
func (a *app) openTarget(dir, arg string, keys *core.VaultKeys) (*openedTarget, error) {
	open := func(f vaultFile) (*openedTarget, error) {
		file, size, err := openRegular(f.abs)
		if err != nil {
			return nil, err
		}
		r, err := core.OpenObject(file, size, f.id, keys)
		if err != nil {
			file.Close()
			return nil, err
		}
		return &openedTarget{f, file, r}, nil
	}
	if id, err := core.ParseFileID(arg); err == nil {
		rel := core.ObjectPath(id)
		t, err := open(vaultFile{rel, filepath.Join(dir, filepath.FromSlash(rel)), id})
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no object with id %s", id)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		return t, nil
	}
	want := norm.NFC.String(strings.Trim(arg, "/"))
	s, err := scanVault(dir)
	if err != nil {
		return nil, err
	}
	var matches []*openedTarget
	unreadable := 0
	for _, f := range s.objects {
		t, err := open(f)
		if err != nil {
			unreadable++
			continue
		}
		if norm.NFC.String(logicalPath(t.reader.Info().Meta)) == want {
			matches = append(matches, t)
		} else {
			t.close()
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		if unreadable > 0 {
			return nil, fmt.Errorf("no such file (%d object(s) could not be read; run valv verify)", unreadable)
		}
		return nil, errors.New("no such file")
	default:
		ids := make([]string, len(matches))
		for i, m := range matches {
			ids[i] = m.f.id.String()
			m.close()
		}
		return nil, fmt.Errorf("%d files have this path; use an id: %s", len(matches), strings.Join(ids, ", "))
	}
}

func (a *app) cmdIngest(args []string) error {
	fs := a.flags("ingest", true, false)
	inboxFlag := fs.String("inbox", "", "inbox directory (default <vault>/inbox)")
	if _, err := parse(fs, args, 0, 0); err != nil {
		return err
	}
	dir := a.vaultDir()
	if err := requireRealDirs(dir); err != nil {
		return err
	}
	inboxDir := *inboxFlag
	if inboxDir == "" {
		inboxDir = filepath.Join(dir, core.InboxDir)
	}
	keys, err := a.unlock(dir)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	s, err := scanInboxDir(inboxDir, inboxDir)
	if err != nil {
		return err
	}
	var ingested, already, failed int
	report := func(msg string) {
		failed++
		fmt.Fprintf(a.stderr, "error: %s\n", msg)
	}
	for _, u := range s.unexpected {
		report(u + " (kept)")
	}
	for _, f := range s.inbox {
		result, err := ingestOne(dir, f, keys)
		switch {
		case errors.Is(err, core.ErrAuth):
			report(fmt.Sprintf("%s: not authentic (made without this vault's K_auth, or damaged): %v (inbox file kept)", display(f.rel), err))
		case err != nil:
			report(fmtProblem(f.rel, err) + " (inbox file kept)")
		case result == "already":
			already++
		default:
			ingested++
		}
	}
	fmt.Fprintf(a.stdout, "ingested %d, already ingested %d, failed %d\n", ingested, already, failed)
	if failed > 0 {
		return fmt.Errorf("%d inbox file(s) could not be ingested", failed)
	}
	return nil
}

// ingestOne ingests one inbox file (SPEC 6.3). The inbox file is deleted
// only after the object has been read back from its final path and fully
// authenticated, or when the existing object is its ingest result.
func ingestOne(dir string, f vaultFile, keys *core.VaultKeys) (string, error) {
	rel := core.ObjectPath(f.id)
	dst := filepath.Join(dir, filepath.FromSlash(rel))
	in, inSize, err := openRegular(f.abs)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if _, err := os.Lstat(dst); err == nil {
		obj, objSize, err := openRegular(dst)
		if err != nil {
			return "", fmt.Errorf("%w: existing %s: %v", core.ErrConflict, rel, err)
		}
		defer obj.Close()
		if err := core.CheckAlreadyIngested(in, inSize, obj, objSize, f.id, keys); err != nil {
			return "", err
		}
		in.Close()
		return "already", os.Remove(f.abs)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	err = writeAtomic(dst, writeOpts{}, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, core.StoredChunkSize)
		if _, err := core.IngestInbox(bufio.NewReaderSize(in, core.StoredChunkSize), inSize, f.id, keys, bw); err != nil {
			return err
		}
		return bw.Flush()
	})
	if err != nil {
		return "", err
	}
	// Read the object back from its final path before deleting the inbox file.
	if err := verifyObjectFile(dst, f.id, keys); err != nil {
		os.Remove(dst)
		return "", fmt.Errorf("read-back of %s failed, object removed: %w", rel, err)
	}
	in.Close()
	return "ingested", os.Remove(f.abs)
}

func verifyObjectFile(p string, id core.FileID, keys *core.VaultKeys) error {
	r, size, err := openRegular(p)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = core.VerifyObject(bufio.NewReaderSize(r, core.StoredChunkSize), size, id, keys)
	return err
}

func (a *app) cmdVerify(args []string) error {
	fs := a.flags("verify", true, false)
	if _, err := parse(fs, args, 0, 0); err != nil {
		return err
	}
	dir := a.vaultDir()
	keys, err := a.unlock(dir)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	s, err := scanVault(dir)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(a.stdout)
	defer w.Flush()
	problems := 0
	problem := func(msg string) {
		problems++
		fmt.Fprintf(w, "FAIL  %s\n", msg)
	}
	for _, d := range s.symlinkDirs {
		problem(d)
	}
	for _, u := range s.unexpected {
		problem(u)
	}
	// Paths that differ only in normalization form coexist (SPEC 5.2).
	byNFC := map[string]map[string]bool{}
	check := func(f vaultFile, verify func(io.Reader, int64) (core.Metadata, error)) {
		r, size, err := openRegular(f.abs)
		var meta core.Metadata
		if err == nil {
			meta, err = verify(bufio.NewReaderSize(r, core.StoredChunkSize), size)
			r.Close()
		}
		switch {
		case errors.Is(err, core.ErrAuth) && strings.HasPrefix(f.rel, core.InboxDir+"/"):
			problem(fmtProblem(f.rel, fmt.Errorf("not authentic or damaged: %w", err)))
		case err != nil:
			problem(fmtProblem(f.rel, err))
		case !meta.IsNFC():
			fmt.Fprintf(w, "warn  %s: name or dir is not NFC (readable; written by another tool?)\n", display(f.rel))
		}
	}
	for _, f := range s.objects {
		check(f, func(r io.Reader, size int64) (core.Metadata, error) {
			meta, err := core.VerifyObject(r, size, f.id, keys)
			if err == nil {
				p := logicalPath(meta)
				k := norm.NFC.String(p)
				if byNFC[k] == nil {
					byNFC[k] = map[string]bool{}
				}
				byNFC[k][p] = true
			}
			return meta, err
		})
	}
	for k, forms := range byNFC {
		if len(forms) > 1 {
			fmt.Fprintf(w, "warn  %d files have paths that differ only in Unicode normalization (%s); get them by id\n", len(forms), display(k))
		}
	}
	for _, f := range s.inbox {
		check(f, func(r io.Reader, size int64) (core.Metadata, error) {
			return core.VerifyInbox(r, size, f.id, keys)
		})
	}
	for _, p := range s.partial {
		fmt.Fprintf(w, "note  %s: incomplete write (ignored)\n", p)
	}
	for _, j := range s.junk {
		fmt.Fprintf(w, "note  %s: OS junk (ignored)\n", j)
	}
	fmt.Fprintf(w, "checked %d object(s) and %d inbox file(s): %d problem(s)\n", len(s.objects), len(s.inbox), problems)
	if err := w.Flush(); err != nil {
		return err
	}
	if problems > 0 {
		return fmt.Errorf("verify found %d problem(s)", problems)
	}
	return nil
}

func (a *app) cmdPasswd(args []string) error {
	fs := a.flags("passwd", true, true)
	if _, err := parse(fs, args, 0, 0); err != nil {
		return err
	}
	dir := a.vaultDir()
	keys, err := a.unlock(dir)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	pass, err := a.newPassphrase()
	if err != nil {
		return err
	}
	data, err := core.ChangePassphrase(keys, pass)
	if err != nil {
		return err
	}
	if err := a.replaceConfig(dir, data, pass, keys); err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stdout, "Passphrase changed.")
	return err
}

// replaceConfig writes vault.json through a temp file that is read back and
// unlocked before it replaces the old one. No backup is kept (SPEC 4.4).
func (a *app) replaceConfig(dir string, data []byte, pass string, keys *core.VaultKeys) error {
	return writeAtomic(filepath.Join(dir, core.ConfigFile), writeOpts{overwrite: true, check: configChecker(pass, keys)}, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func (a *app) cmdRecover(args []string) error {
	fs := a.flags("recover", false, true)
	force := fs.Bool("force", false, "replace an existing vault.json")
	unverifiedKey := fs.Bool("unverified-key", false, "write vault.json even if nothing in the vault can confirm the key")
	pos, err := parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := pos[0]
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := requireRealDirs(dir); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, core.ConfigFile)); err == nil && !*force {
		return errors.New("vault.json exists; use --force to replace it")
	}
	rk, err := a.readSecret("Recovery key: ")
	if err != nil {
		return err
	}
	vk, err := core.DecodeRecoveryKey(rk)
	if err != nil {
		return err
	}
	defer clear(vk[:])
	s, err := scanVault(dir)
	if err != nil {
		return err
	}
	samples := recoverySamples(s)

	// SPEC 4.5: check the key before asking for a passphrase.
	v, err := core.CheckRecoveryKey(rk, samples)
	switch {
	case errors.Is(err, core.ErrKeyUnverifiable) && !*unverifiedKey:
		return fmt.Errorf("%w; nothing written (pass --unverified-key to write vault.json anyway)", err)
	case errors.Is(err, core.ErrKeyUnverifiable):
		fmt.Fprintf(a.stderr, "warning: %s; writing anyway because of --unverified-key\n", oneLine(err.Error()))
	case err != nil:
		return fmt.Errorf("%w; nothing written", err)
	case v == core.ChecksumOnly:
		fmt.Fprintln(a.stderr, "warning: the vault has no objects or inbox files, so only the recovery key's checksum vouches for it")
	}
	if (v == core.Unverifiable || v == core.ChecksumOnly) && a.interactive() {
		if err := a.confirmRecoveryKey(&vk); err != nil {
			return fmt.Errorf("%w; nothing written", err)
		}
	}
	pass, err := a.newPassphrase()
	if err != nil {
		return err
	}
	data, v, err := core.RecoverVault(rk, pass, samples, *unverifiedKey)
	if err != nil {
		return fmt.Errorf("%w; nothing written", err)
	}
	c, _ := core.ParseConfig(data)
	keys, err := core.Unlock(c, pass)
	if err != nil {
		return fmt.Errorf("rebuilt vault.json does not unlock: %w", err)
	}
	defer keys.Wipe()
	if err := a.replaceConfig(dir, data, pass, keys); err != nil {
		return err
	}
	how := map[core.Verification]string{
		core.VerifiedByObject: "verified against an object",
		core.VerifiedByInbox:  "verified against an inbox file",
		core.Unverifiable:     "NOT verified (--unverified-key)",
		core.ChecksumOnly:     "checked by its checksum only",
	}[v]
	_, err = fmt.Fprintf(a.stdout, "vault.json rebuilt from the recovery key (%s).\n", how)
	return err
}

// recoverySamples reads the start of every object and inbox file. A file
// that cannot be opened still counts, as an unreadable one (SPEC 4.5).
func recoverySamples(s *scan) core.RecoverySamples {
	var out core.RecoverySamples
	for _, f := range s.objects {
		p, size := readPrefix(f.abs, 86)
		out.Objects = append(out.Objects, core.ObjectSample{Prefix: p, Size: size, ID: f.id})
	}
	for _, f := range s.inbox {
		p, size := readPrefix(f.abs, core.InboxSamplePrefixMax)
		out.Inbox = append(out.Inbox, core.InboxSample{Prefix: p, Size: size, ID: f.id})
	}
	return out
}

// readPrefix returns up to the first n bytes of a regular vault file and its
// size, or nothing if it cannot be read.
func readPrefix(p string, n int) ([]byte, int64) {
	r, size, err := openRegular(p)
	if err != nil {
		return nil, 0
	}
	defer r.Close()
	b := make([]byte, n)
	k, err := io.ReadFull(r, b)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, 0
	}
	return b[:k], size
}

func (a *app) cmdServerConfig(args []string) error {
	fs := a.flags("server-config", true, false)
	if _, err := parse(fs, args, 0, 0); err != nil {
		return err
	}
	keys, err := a.unlock(a.vaultDir())
	if err != nil {
		return err
	}
	defer keys.Wipe()
	// A redirect to a regular file gets mode 0600 before the secret is written.
	if f, ok := a.stdout.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode().IsRegular() {
			if err := f.Chmod(0o600); err != nil {
				return fmt.Errorf("could not restrict the output file to mode 0600: %w", err)
			}
		}
	}
	fmt.Fprintln(a.stderr, "warning: k_auth is a secret. Give it only to the inbox server: anyone holding it can add files that ingest accepts as authentic, and it cannot be rotated in v1. It cannot decrypt anything.")
	b64 := base64.StdEncoding
	_, err = fmt.Fprintf(a.stdout, "inbox_pub: %s\nk_auth: %s\n", b64.EncodeToString(keys.InboxPub[:]), b64.EncodeToString(keys.InboxAuth[:]))
	return err
}
