package main

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/klppl/valv/core"
	"golang.org/x/text/unicode/norm"
)

func (a *app) cmdInit(args []string) error {
	fs := a.flags("init", false)
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
	for _, d := range []string{dir, filepath.Join(dir, core.ObjectsDir), filepath.Join(dir, core.InboxDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	cfgPath := filepath.Join(dir, core.ConfigFile)
	if err := writeAtomic(cfgPath, false, nil, func(w io.Writer) error { _, err := w.Write(data); return err }); err != nil {
		return err
	}
	// Self-check on what is on disk before showing the recovery key.
	if err := selfCheck(cfgPath, pass, keys); err != nil {
		os.Remove(cfgPath)
		return fmt.Errorf("self-check failed, vault not created: %w", err)
	}
	fmt.Fprintf(a.stdout, "Created vault in %s\n\nRecovery key (shown once; store it offline):\n\n  %s\n\n", dir, recoveryKey)
	fmt.Fprintln(a.stdout, "Unlock self-check passed.")
	return nil
}

// selfCheck reads vault.json back from disk, unlocks it with pass and checks
// it gives the expected VK.
func selfCheck(cfgPath, pass string, want *core.VaultKeys) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	c, err := core.ParseConfig(data)
	if err != nil {
		return err
	}
	got, err := core.Unlock(c, pass)
	if err != nil {
		return err
	}
	defer got.Wipe()
	if subtle.ConstantTimeCompare(got.VK[:], want.VK[:]) != 1 {
		return errors.New("vault.json unlocks to a different key")
	}
	return nil
}

func (a *app) cmdAdd(args []string) error {
	fs := a.flags("add", true)
	dirFlag := fs.String("dir", "", "folder inside the vault")
	nameFlag := fs.String("name", "", "file name inside the vault")
	pos, err := parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	src, err := os.Open(pos[0])
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", pos[0])
	}
	name := *nameFlag
	if name == "" {
		name = filepath.Base(pos[0])
	}
	obj, err := core.PrepareObject(core.Metadata{
		Name:  name,
		Dir:   *dirFlag,
		MTime: st.ModTime().UnixNano(),
		MIME:  mimeType(name),
		Rev:   1,
	})
	if err != nil {
		return fmt.Errorf("%w (names must be non-empty, without / or NUL, not . or ..; --dir has no leading or trailing /)", err)
	}
	defer obj.Wipe()
	dir := a.vaultDir()
	keys, err := a.unlock(dir)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	dst := filepath.Join(dir, filepath.FromSlash(core.ObjectPath(obj.ID())))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	err = writeAtomic(dst, false, nil, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, core.StoredChunkSize)
		if err := obj.Encrypt(bw, keys, src); err != nil {
			return err
		}
		return bw.Flush()
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, obj.ID())
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

// display quotes a path that has characters a terminal would not show plainly.
func display(p string) string {
	for _, r := range p {
		if !unicode.IsPrint(r) {
			return strconv.Quote(p)
		}
	}
	return p
}

func (a *app) cmdLs(args []string) error {
	fs := a.flags("ls", true)
	dirFlag := fs.String("dir", "", "only list this folder and its subfolders")
	if _, err := parse(fs, args, 0, 0); err != nil {
		return err
	}
	filter := norm.NFC.String(strings.Trim(*dirFlag, "/"))
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
		d := info.Meta.Dir
		if filter != "" && d != filter && !strings.HasPrefix(d, filter+"/") {
			continue
		}
		rows = append(rows, row{logicalPath(info.Meta), info})
	}
	sortRows := func(i, j int) bool {
		if rows[i].path != rows[j].path {
			return rows[i].path < rows[j].path
		}
		return rows[i].info.ID.String() < rows[j].info.ID.String()
	}
	sort.Slice(rows, sortRows)
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

func (a *app) cmdGet(args []string) error {
	fs := a.flags("get", true)
	out := fs.String("o", "", "output file, or - for stdout (default: the file's name in the current directory)")
	force := fs.Bool("force", false, "replace an existing output file")
	pos, err := parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if *out != "" && *out != "-" && !*force {
		if _, err := os.Lstat(*out); err == nil {
			return errExists
		}
	}
	dir := a.vaultDir()
	keys, err := a.unlock(dir)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	f, info, err := a.findObject(dir, pos[0], keys)
	if err != nil {
		return err
	}
	decrypt := func(w io.Writer) error {
		r, size, err := openSized(f.abs)
		if err != nil {
			return err
		}
		defer r.Close()
		_, err = core.DecryptObject(r, size, f.id, keys, w)
		return err
	}
	if *out == "-" {
		// Plaintext goes out as it is decrypted; on error the output so far
		// is not trustworthy and the exit code says so.
		bw := bufio.NewWriterSize(a.stdout, core.ChunkSize)
		if err := decrypt(bw); err != nil {
			return fmt.Errorf("%s: %w (output so far is invalid)", f.rel, err)
		}
		return bw.Flush()
	}
	dst := *out
	if dst == "" {
		dst = info.Meta.Name
	}
	mtime := time.Unix(0, info.Meta.MTime)
	err = writeAtomic(dst, *force, &mtime, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, core.ChunkSize)
		if err := decrypt(bw); err != nil {
			return err
		}
		return bw.Flush()
	})
	if err != nil && !errors.Is(err, errExists) {
		return fmt.Errorf("%s: %w", f.rel, err)
	}
	return err
}

// findObject resolves a file_id or a path inside the vault.
func (a *app) findObject(dir, arg string, keys *core.VaultKeys) (vaultFile, core.ObjectInfo, error) {
	if id, err := core.ParseFileID(arg); err == nil {
		rel := core.ObjectPath(id)
		f := vaultFile{rel, filepath.Join(dir, filepath.FromSlash(rel)), id}
		info, err := readObjectInfo(f, keys)
		if errors.Is(err, os.ErrNotExist) {
			return f, info, fmt.Errorf("no object with id %s", id)
		}
		if err != nil {
			return f, info, fmt.Errorf("%s: %w", rel, err)
		}
		return f, info, nil
	}
	want := norm.NFC.String(strings.Trim(arg, "/"))
	s, err := scanVault(dir)
	if err != nil {
		return vaultFile{}, core.ObjectInfo{}, err
	}
	var matches []vaultFile
	var infos []core.ObjectInfo
	unreadable := 0
	for _, f := range s.objects {
		info, err := readObjectInfo(f, keys)
		if err != nil {
			unreadable++
			continue
		}
		if logicalPath(info.Meta) == want {
			matches = append(matches, f)
			infos = append(infos, info)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], infos[0], nil
	case 0:
		if unreadable > 0 {
			return vaultFile{}, core.ObjectInfo{}, fmt.Errorf("no such file (%d object(s) could not be read; run valv verify)", unreadable)
		}
		return vaultFile{}, core.ObjectInfo{}, errors.New("no such file")
	default:
		ids := make([]string, len(matches))
		for i, m := range matches {
			ids[i] = m.id.String()
		}
		return vaultFile{}, core.ObjectInfo{}, fmt.Errorf("%d files have this path; use an id: %s", len(matches), strings.Join(ids, ", "))
	}
}

func (a *app) cmdIngest(args []string) error {
	fs := a.flags("ingest", true)
	inboxFlag := fs.String("inbox", "", "inbox directory (default <vault>/inbox)")
	if _, err := parse(fs, args, 0, 0); err != nil {
		return err
	}
	dir := a.vaultDir()
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
// only after a verified ingest, or when the existing object is its ingest
// result.
func ingestOne(dir string, f vaultFile, keys *core.VaultKeys) (string, error) {
	dst := filepath.Join(dir, filepath.FromSlash(core.ObjectPath(f.id)))
	in, inSize, err := openSized(f.abs)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if _, err := os.Lstat(dst); err == nil {
		obj, objSize, err := openSized(dst)
		if err != nil {
			return "", err
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
	err = writeAtomic(dst, false, nil, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, core.StoredChunkSize)
		if _, err := core.IngestInbox(bufio.NewReaderSize(in, core.StoredChunkSize), inSize, f.id, keys, bw); err != nil {
			return err
		}
		return bw.Flush()
	})
	if err != nil {
		return "", err
	}
	in.Close()
	return "ingested", os.Remove(f.abs)
}

func (a *app) cmdVerify(args []string) error {
	fs := a.flags("verify", true)
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
	for _, u := range s.unexpected {
		problem(u)
	}
	check := func(f vaultFile, verify func(io.Reader, int64) error) {
		r, size, err := openSized(f.abs)
		if err == nil {
			err = verify(bufio.NewReaderSize(r, core.StoredChunkSize), size)
			r.Close()
		}
		if err != nil {
			problem(fmtProblem(f.rel, err))
		}
	}
	for _, f := range s.objects {
		check(f, func(r io.Reader, size int64) error {
			_, err := core.DecryptObject(r, size, f.id, keys, io.Discard)
			return err
		})
	}
	for _, f := range s.inbox {
		check(f, func(r io.Reader, size int64) error {
			_, err := core.VerifyInbox(r, size, f.id, keys)
			return err
		})
	}
	for _, p := range s.partial {
		fmt.Fprintf(w, "note  %s: incomplete write (ignored)\n", p)
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
	fs := a.flags("passwd", true)
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
	cfgPath := filepath.Join(dir, core.ConfigFile)
	if err := writeAtomic(cfgPath, true, nil, func(w io.Writer) error { _, err := w.Write(data); return err }); err != nil {
		return err
	}
	if err := selfCheck(cfgPath, pass, keys); err != nil {
		return fmt.Errorf("vault.json was replaced but does not unlock: %w", err)
	}
	fmt.Fprintln(a.stdout, "Passphrase changed.")
	return nil
}

func (a *app) cmdRecover(args []string) error {
	fs := a.flags("recover", false)
	force := fs.Bool("force", false, "replace an existing vault.json")
	pos, err := parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := pos[0]
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	cfgPath := filepath.Join(dir, core.ConfigFile)
	if _, err := os.Lstat(cfgPath); err == nil && !*force {
		return errors.New("vault.json exists; use --force to replace it")
	}
	rk, err := a.readSecret("Recovery key: ")
	if err != nil {
		return err
	}
	if _, err := core.DecodeRecoveryKey(rk); err != nil {
		return err
	}
	s, err := scanVault(dir)
	if err != nil {
		return err
	}
	var prefixes [][]byte
	for _, f := range s.objects {
		if p, err := readPrefix(f.abs, 82); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	if len(s.objects) > 0 && len(prefixes) == 0 {
		return errors.New("no object could be read to check the recovery key; nothing written")
	}
	pass, err := a.newPassphrase()
	if err != nil {
		return err
	}
	data, checked, err := core.RecoverVault(rk, pass, prefixes)
	if err != nil {
		return fmt.Errorf("%w; nothing written", err)
	}
	if !checked {
		fmt.Fprintln(a.stderr, "warning: the vault has no objects, so the recovery key could not be checked")
	}
	if err := writeAtomic(cfgPath, true, nil, func(w io.Writer) error { _, err := w.Write(data); return err }); err != nil {
		return err
	}
	c, _ := core.ParseConfig(data)
	keys, err := core.Unlock(c, pass)
	if err != nil {
		return fmt.Errorf("rebuilt vault.json does not unlock: %w", err)
	}
	defer keys.Wipe()
	if err := selfCheck(cfgPath, pass, keys); err != nil {
		return fmt.Errorf("rebuilt vault.json does not unlock: %w", err)
	}
	fmt.Fprintln(a.stdout, "vault.json rebuilt from the recovery key.")
	return nil
}
