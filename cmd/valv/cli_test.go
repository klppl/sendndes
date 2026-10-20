package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/klppl/valv/core"
)

// The tests run the real CLI as a child process: the test binary re-executes
// itself with VALV_TEST_RUN_MAIN=1 and runs main.
func TestMain(m *testing.M) {
	if os.Getenv("VALV_TEST_RUN_MAIN") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

type result struct {
	stdout, stderr string
	code           int
}

type runOpt func(*exec.Cmd)

func inDir(dir string) runOpt { return func(c *exec.Cmd) { c.Dir = dir } }

// valvIn runs the CLI with stdin as its standard input.
func valvIn(t *testing.T, stdin string, opts []runOpt, args ...string) result {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	env := []string{"VALV_TEST_RUN_MAIN=1"}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "VALV_") {
			env = append(env, e)
		}
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	for _, o := range opts {
		o(cmd)
	}
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{out.String(), errb.String(), code}
}

func valv(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	return valvIn(t, stdin, nil, args...)
}

func ok(t *testing.T, r result) result {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	return r
}

// fails checks a failure that ends in exactly one "valv: " line (review I4).
func fails(t *testing.T, r result) result {
	t.Helper()
	if r.code == 0 {
		t.Fatalf("succeeded, want failure\nstdout: %s", r.stdout)
	}
	lines := strings.Split(strings.TrimSpace(r.stderr), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "valv: ") || strings.Contains(r.stderr, "valv: valv:") {
		t.Fatalf("not a single one-line valv: error: %q", r.stderr)
	}
	return r
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustID(t *testing.T, s string) core.FileID {
	t.Helper()
	id, err := core.ParseFileID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func notExist(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s exists", p)
		}
	}
}

// noTemps fails if a temp file is left anywhere under root.
func noTemps(t *testing.T, root string) {
	t.Helper()
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".part") {
			t.Errorf("leftover temp file %s", p)
		}
		return nil
	})
}

var recoveryKeyRE = regexp.MustCompile(`[A-Z2-7]{4}(-[A-Z2-7]{4}){13}`)

const pw = "correct horse battery\n"

// testVault is a vault made with init in a temp directory.
type testVault struct {
	t           *testing.T
	tmp, dir    string
	work        string
	recoveryKey string
	pass        string
}

func newVault(t *testing.T) *testVault {
	t.Helper()
	tmp := t.TempDir()
	v := &testVault{t: t, tmp: tmp, dir: filepath.Join(tmp, "vault"), work: filepath.Join(tmp, "work"), pass: pw}
	os.Mkdir(v.work, 0o700)
	r := ok(t, valv(t, pw, "init", "--passphrase-stdin", v.dir))
	v.recoveryKey = recoveryKeyRE.FindString(r.stdout)
	if v.recoveryKey == "" {
		t.Fatalf("init printed no recovery key: %s", r.stdout)
	}
	return v
}

// args puts the common flags after the command name.
func (v *testVault) args(args ...string) []string {
	return append([]string{args[0], "--vault", v.dir, "--passphrase-stdin"}, args[1:]...)
}

func (v *testVault) run(args ...string) result {
	v.t.Helper()
	return valv(v.t, v.pass, v.args(args...)...)
}

func (v *testVault) runIn(dir string, args ...string) result {
	v.t.Helper()
	return valvIn(v.t, v.pass, []runOpt{inDir(dir)}, v.args(args...)...)
}

// add writes data to a work file and adds it; returns the file_id.
func (v *testVault) add(name string, data []byte, extra ...string) string {
	v.t.Helper()
	src := filepath.Join(v.work, "src-"+name)
	os.WriteFile(src, data, 0o600)
	r := ok(v.t, v.run(append([]string{"add", src, "--name", name}, extra...)...))
	return strings.TrimSpace(r.stdout)
}

func (v *testVault) objectPath(id string) string {
	return filepath.Join(v.dir, filepath.FromSlash(core.ObjectPath(mustID(v.t, id))))
}

// serverConfig runs server-config and parses inbox_pub and K_auth.
func (v *testVault) serverConfig() (inboxPub, kAuth [core.KeySize]byte) {
	v.t.Helper()
	r := ok(v.t, v.run("server-config"))
	if !strings.Contains(r.stderr, "secret") {
		v.t.Fatalf("server-config gave no warning: %s", r.stderr)
	}
	for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
		k, val, _ := strings.Cut(line, ": ")
		b, err := base64.StdEncoding.DecodeString(val)
		if err != nil || len(b) != core.KeySize {
			v.t.Fatalf("server-config line %q", line)
		}
		switch k {
		case "inbox_pub":
			copy(inboxPub[:], b)
		case "k_auth":
			copy(kAuth[:], b)
		default:
			v.t.Fatalf("server-config line %q", line)
		}
	}
	return
}

// seal writes an inbox file into the vault's inbox, sealed with kAuth.
func (v *testVault) seal(kAuth [core.KeySize]byte, meta core.Metadata, data []byte) (core.FileID, string) {
	v.t.Helper()
	inboxPub, _ := v.serverConfig()
	var buf bytes.Buffer
	id, err := core.SealInbox(&buf, inboxPub, kAuth, meta, bytes.NewReader(data))
	if err != nil {
		v.t.Fatal(err)
	}
	p := filepath.Join(v.dir, "inbox", core.InboxName(id))
	os.WriteFile(p, buf.Bytes(), 0o600)
	return id, p
}

func TestCLIEndToEnd(t *testing.T) {
	v := newVault(t)
	for _, p := range []string{"vault.json", "objects", "inbox"} {
		if _, err := os.Stat(filepath.Join(v.dir, p)); err != nil {
			t.Fatal(err)
		}
	}
	fails(t, valv(t, pw, "init", "--passphrase-stdin", v.dir))

	// Passphrase must not come from a non-terminal stdin without the flag.
	r := fails(t, valv(t, pw, "ls", "--vault", v.dir))
	if !strings.Contains(r.stderr, "--passphrase-stdin") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	fails(t, valv(t, "wrong passphrase\n", v.args("ls")...))

	// add, several sizes, mtime preserved
	type added struct {
		id, path string
		data     []byte
		mtime    time.Time
	}
	var files []added
	names := []string{"empty.bin", "one.bin", "chunk.bin", "Räksmörgås.txt"}
	for i, n := range []int{0, 1, core.ChunkSize, 3*core.ChunkSize + 5} {
		src := filepath.Join(v.work, names[i])
		data := randBytes(n)
		os.WriteFile(src, data, 0o600)
		mt := time.Date(2001, 2, 3, 4, 5, 6, 789000000, time.UTC).Add(time.Duration(i) * time.Hour)
		os.Chtimes(src, mt, mt)
		r := ok(t, v.run("add", src, "--dir", "Docs/2026"))
		id := strings.TrimSpace(r.stdout)
		mustID(t, id)
		files = append(files, added{id, "Docs/2026/" + names[i], data, mt})
	}
	files = append(files, added{v.add("renamed.txt", []byte("top level")), "renamed.txt", []byte("top level"), time.Time{}})
	src := filepath.Join(v.work, "x.txt")
	os.WriteFile(src, []byte("x"), 0o600)
	fails(t, v.run("add", src, "--dir", "/abs"))
	fails(t, v.run("add", src, "--name", ".."))
	fails(t, v.run("add", filepath.Join(v.work, "missing")))

	// ls
	r = ok(t, v.run("ls"))
	for _, f := range files {
		if !strings.Contains(r.stdout, f.id) || !strings.Contains(r.stdout, f.path) {
			t.Fatalf("ls misses %s\n%s", f.path, r.stdout)
		}
	}
	r = ok(t, v.run("ls", "--dir", "Docs"))
	if strings.Contains(r.stdout, "renamed.txt") || strings.Count(r.stdout, "\n") != 4 {
		t.Fatalf("ls --dir Docs:\n%s", r.stdout)
	}

	// get by id and by path: bytes and mtime
	outDir := filepath.Join(v.work, "out")
	os.Mkdir(outDir, 0o700)
	for i, f := range files {
		out := filepath.Join(outDir, f.id)
		arg := f.id
		if i%2 == 1 {
			arg = f.path
		}
		ok(t, v.run("get", arg, "-o", out))
		if !bytes.Equal(mustRead(t, out), f.data) {
			t.Fatalf("get %s: content differs", arg)
		}
		if st, _ := os.Stat(out); !f.mtime.IsZero() && !st.ModTime().Equal(f.mtime) {
			t.Fatalf("get %s: mtime %v, want %v", arg, st.ModTime(), f.mtime)
		}
	}
	// An NFD path argument finds the NFC name.
	ok(t, v.run("get", "Docs/2026/Räksmörgås.txt", "-o", filepath.Join(outDir, "nfd")))
	// Refuse to overwrite; --force replaces.
	out := filepath.Join(outDir, "keep")
	os.WriteFile(out, []byte("keep me"), 0o600)
	fails(t, v.run("get", files[1].id, "-o", out))
	if string(mustRead(t, out)) != "keep me" {
		t.Fatal("existing output was changed")
	}
	ok(t, v.run("get", files[1].id, "-o", out, "--force"))
	// Default output: the stored name, in the current directory.
	cwd := filepath.Join(v.work, "cwd")
	os.Mkdir(cwd, 0o700)
	ok(t, v.runIn(cwd, "get", files[4].id))
	if string(mustRead(t, filepath.Join(cwd, "renamed.txt"))) != "top level" {
		t.Fatal("default output name")
	}
	fails(t, v.run("get", "no/such/file", "-o", filepath.Join(outDir, "none")))

	// ingest a genuine inbox file (sealed with server-config's K_auth)
	_, kAuth := v.serverConfig()
	inboxData := randBytes(core.ChunkSize + 77)
	inID, inboxFile := v.seal(kAuth, core.Metadata{Name: "scan.pdf", Dir: "Inbox", MTime: 1, MIME: "application/pdf"}, inboxData)
	sealed := mustRead(t, inboxFile)
	r = ok(t, v.run("ingest"))
	if !strings.Contains(r.stdout, "ingested 1") {
		t.Fatalf("ingest: %s", r.stdout)
	}
	notExist(t, inboxFile)
	ok(t, v.run("get", inID.String(), "-o", filepath.Join(outDir, "scan.pdf")))
	if !bytes.Equal(mustRead(t, filepath.Join(outDir, "scan.pdf")), inboxData) {
		t.Fatal("ingested content differs")
	}
	// Ingest again after a lost delete: idempotent, inbox file removed.
	os.WriteFile(inboxFile, sealed, 0o600)
	r = ok(t, v.run("ingest"))
	if !strings.Contains(r.stdout, "already ingested 1") {
		t.Fatalf("re-ingest: %s", r.stdout)
	}
	notExist(t, inboxFile)
	// A damaged inbox file is kept and nothing is written.
	badID, badInbox := v.seal(kAuth, core.Metadata{Name: "bad.bin", MTime: 1}, randBytes(2*core.ChunkSize))
	bad := mustRead(t, badInbox)
	bad[len(bad)-3] ^= 1
	os.WriteFile(badInbox, bad, 0o600)
	fails(t, v.run("ingest"))
	if _, err := os.Stat(badInbox); err != nil {
		t.Fatal("damaged inbox file was deleted")
	}
	notExist(t, v.objectPath(badID.String()))
	r = fails(t, v.run("verify"))
	if !strings.Contains(r.stdout, core.InboxName(badID)) {
		t.Fatalf("verify did not name the bad inbox file:\n%s", r.stdout)
	}
	os.Remove(badInbox)

	// verify: good vault, then a flipped byte
	r = ok(t, v.run("verify"))
	if !strings.Contains(r.stdout, "0 problem(s)") {
		t.Fatalf("verify: %s", r.stdout)
	}
	objPath := v.objectPath(files[3].id)
	orig := mustRead(t, objPath)
	flipped := bytes.Clone(orig)
	flipped[len(flipped)/2] ^= 0x40
	os.WriteFile(objPath, flipped, 0o600)
	r = fails(t, v.run("verify"))
	if !strings.Contains(r.stdout, files[3].id) {
		t.Fatalf("verify did not name the object:\n%s", r.stdout)
	}
	// get fails and leaves nothing behind
	out = filepath.Join(outDir, "tampered.out")
	fails(t, v.run("get", files[3].id, "-o", out))
	notExist(t, out)
	os.WriteFile(objPath, orig, 0o600)
	ok(t, v.run("verify"))

	// stray file, uppercase name, renamed object
	stray := filepath.Join(v.dir, "objects", "conflicted copy.obj")
	os.WriteFile(stray, []byte("x"), 0o600)
	r = fails(t, v.run("verify"))
	if !strings.Contains(r.stdout, "conflicted copy.obj") {
		t.Fatalf("verify did not report the stray file:\n%s", r.stdout)
	}
	os.Remove(stray)
	upper := filepath.Join(filepath.Dir(objPath), strings.ToUpper(files[3].id)+".obj")
	os.Rename(objPath, upper)
	fails(t, v.run("verify"))
	var otherID core.FileID
	rand.Read(otherID[:])
	otherPath := filepath.Join(v.dir, filepath.FromSlash(core.ObjectPath(otherID)))
	os.MkdirAll(filepath.Dir(otherPath), 0o700)
	os.Rename(upper, otherPath)
	r = fails(t, v.run("verify"))
	if !strings.Contains(r.stdout, "does not match") {
		t.Fatalf("verify did not report the id mismatch:\n%s", r.stdout)
	}
	os.Rename(otherPath, objPath)
	os.Remove(filepath.Dir(otherPath))
	ok(t, v.run("verify"))

	// passwd: only the new passphrase works
	pw2 := "a new passphrase\n"
	ok(t, valv(t, pw+pw2, v.args("passwd")...))
	fails(t, valv(t, pw, v.args("ls")...))
	v.pass = pw2
	ok(t, v.run("ls"))

	// recover after deleting vault.json
	cfgPath := filepath.Join(v.dir, "vault.json")
	fails(t, valv(t, v.recoveryKey+"\nrecovered passphrase\n", "recover", "--passphrase-stdin", v.dir)) // exists, no --force
	os.Remove(cfgPath)
	var wrong [core.KeySize]byte
	rand.Read(wrong[:])
	fails(t, valv(t, core.EncodeRecoveryKey(wrong)+"\nrecovered passphrase\n", "recover", "--passphrase-stdin", v.dir))
	notExist(t, cfgPath)
	pw3 := "recovered passphrase\n"
	ok(t, valv(t, strings.ToLower(v.recoveryKey)+"\n"+pw3, "recover", "--passphrase-stdin", v.dir))
	fails(t, valv(t, pw2, v.args("ls")...))
	v.pass = pw3
	r = ok(t, v.run("ls"))
	if !strings.Contains(r.stdout, files[3].path) {
		t.Fatalf("ls after recover:\n%s", r.stdout)
	}
	ok(t, v.run("verify"))
	noTemps(t, v.tmp)
}

// Review H1 (PoC): ingest, restore the inbox file, flip a bit in the object's
// meta_blob, ingest again. Must be a conflict that keeps the inbox file.
func TestReviewH1IngestKeepsInboxWhenObjectMetadataDamaged(t *testing.T) {
	v := newVault(t)
	_, kAuth := v.serverConfig()
	id, inboxFile := v.seal(kAuth, core.Metadata{Name: "only-copy.txt", MTime: 1}, []byte("precious"))
	sealed := mustRead(t, inboxFile)
	ok(t, v.run("ingest"))
	os.WriteFile(inboxFile, sealed, 0o600)
	obj := v.objectPath(id.String())
	data := mustRead(t, obj)
	data[86+12+3] ^= 1 // meta_blob ciphertext
	os.WriteFile(obj, data, 0o600)
	r := fails(t, v.run("ingest"))
	if !strings.Contains(r.stderr, "conflict") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	if !bytes.Equal(mustRead(t, inboxFile), sealed) {
		t.Fatal("inbox file was deleted or changed")
	}
}

// Review H2 (PoC): the host knows inbox_pub and seals a file with a name and
// content of its choice. Ingest must reject it as not authentic and keep it.
func TestReviewH2ForgedInboxRejected(t *testing.T) {
	v := newVault(t)
	var forgedKey [core.KeySize]byte
	rand.Read(forgedKey[:])
	id, inboxFile := v.seal(forgedKey, core.Metadata{Name: "vault.json", MTime: 1}, []byte("hi"))
	r := fails(t, v.run("ingest"))
	if !strings.Contains(r.stderr, "not authentic") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	if _, err := os.Stat(inboxFile); err != nil {
		t.Fatal("forged inbox file was deleted")
	}
	notExist(t, v.objectPath(id.String()))
	r = fails(t, v.run("verify"))
	if !strings.Contains(r.stdout, "not authentic") {
		t.Fatalf("verify: %s", r.stdout)
	}
	noTemps(t, v.tmp)
}

// Review H3 (PoC): a file named vault.json must never overwrite the vault's
// vault.json, with or without --force, and get never writes into the vault.
func TestReviewH3GetNeverWritesIntoVault(t *testing.T) {
	v := newVault(t)
	_, kAuth := v.serverConfig()
	id, _ := v.seal(kAuth, core.Metadata{Name: "vault.json", MTime: 1}, []byte("hi"))
	ok(t, v.run("ingest"))
	cfg := mustRead(t, filepath.Join(v.dir, "vault.json"))
	for _, extra := range [][]string{nil, {"--force"}} {
		fails(t, v.runIn(v.dir, append([]string{"get", id.String()}, extra...)...))
		fails(t, v.runIn(v.dir, append([]string{"get", "vault.json"}, extra...)...))
	}
	// Explicit -o into the vault, a subfolder of it, or through a symlink.
	fails(t, v.run("get", id.String(), "-o", filepath.Join(v.dir, "vault.json"), "--force"))
	fails(t, v.run("get", id.String(), "-o", filepath.Join(v.dir, "objects", "x")))
	link := filepath.Join(v.work, "link")
	os.Symlink(v.dir, link)
	fails(t, v.run("get", id.String(), "-o", filepath.Join(link, "vault.json"), "--force"))
	if !bytes.Equal(mustRead(t, filepath.Join(v.dir, "vault.json")), cfg) {
		t.Fatal("vault.json changed")
	}
	// The default name vault.json is refused even outside the vault; -o works.
	fails(t, v.runIn(v.work, "get", id.String()))
	ok(t, v.run("get", id.String(), "-o", filepath.Join(v.work, "renamed")))
	ok(t, v.run("verify"))
}

// Review H3: default-name sanitization. Get by id with -o works for any name.
func TestReviewH3DefaultNameSanitization(t *testing.T) {
	v := newVault(t)
	_, kAuth := v.serverConfig()
	for _, name := range []string{
		"esc\x1b[31m.txt", "tab\there", "del\x7f", `back\slash`, "rtl‮gpj.exe", "iso⁦x",
		" leading", "trailing ", strings.Repeat("a", 201), "vault.json",
	} {
		id, _ := v.seal(kAuth, core.Metadata{Name: name, MTime: 1}, []byte("data"))
		ok(t, v.run("ingest"))
		r := fails(t, v.runIn(v.work, "get", id.String()))
		if !strings.Contains(r.stderr, "-o") {
			t.Fatalf("%q: %s", name, r.stderr)
		}
		out := filepath.Join(v.work, "out-"+id.String())
		ok(t, v.run("get", id.String(), "-o", out))
		if string(mustRead(t, out)) != "data" {
			t.Fatalf("%q: content", name)
		}
	}
	// A 200-byte name is still fine.
	id, _ := v.seal(kAuth, core.Metadata{Name: strings.Repeat("b", 200), MTime: 1}, []byte("ok"))
	ok(t, v.run("ingest"))
	ok(t, v.runIn(v.work, "get", id.String()))
	// ls quotes names a terminal would interpret.
	r := ok(t, v.run("ls"))
	if strings.Contains(r.stdout, "\x1b") || strings.Contains(r.stdout, "‮") {
		t.Fatalf("ls printed raw control characters: %q", r.stdout)
	}
	noTemps(t, v.tmp)
}

// Review H4 (PoC): recover on an empty vault with a wrong key used to be
// accepted. A typo is now caught by the checksum.
func TestReviewH4RecoverChecksum(t *testing.T) {
	v := newVault(t)
	cfg := filepath.Join(v.dir, "vault.json")
	os.Remove(cfg)
	flat := strings.ReplaceAll(v.recoveryKey, "-", "")
	c := byte('A')
	if flat[7] == 'A' {
		c = 'B'
	}
	typo := flat[:7] + string(c) + flat[8:]
	r := fails(t, valv(t, typo+"\nnew passphrase!\n", "recover", "--passphrase-stdin", v.dir))
	if !strings.Contains(r.stderr, "typo") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	fails(t, valv(t, strings.Repeat("AAAA-", 13)+"AAAA\nnew passphrase!\n", "recover", "--passphrase-stdin", v.dir))
	notExist(t, cfg)
	// The real key on an empty vault works, with a warning.
	r = ok(t, valv(t, v.recoveryKey+"\nnew passphrase!\n", "recover", "--passphrase-stdin", v.dir))
	if !strings.Contains(r.stderr, "checksum") {
		t.Fatalf("no empty-vault warning: %s", r.stderr)
	}
}

// Review M1 (PoC): init with an unwritable stdout must fail and create
// nothing, because the recovery key could not be shown.
func TestReviewM1InitFailsWhenKeyCannotBeShown(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "vault")
	devnull, err := os.Open(os.DevNull) // read-only: every write fails
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	r := valvIn(t, pw, []runOpt{func(c *exec.Cmd) { c.Stdout = devnull }}, "init", "--passphrase-stdin", dir)
	if r.code == 0 {
		t.Fatal("init succeeded without showing the recovery key")
	}
	notExist(t, filepath.Join(dir, "vault.json"))
	// The directory can be used again.
	ok(t, valv(t, pw, "init", "--passphrase-stdin", dir))
}

// Review M3: -o - needs --unverified-stream.
func TestReviewM3StdoutNeedsFlag(t *testing.T) {
	v := newVault(t)
	id := v.add("a.txt", []byte("streamed"))
	r := fails(t, v.run("get", id, "-o", "-"))
	if r.stdout != "" || !strings.Contains(r.stderr, "--unverified-stream") {
		t.Fatalf("stdout %q, stderr %s", r.stdout, r.stderr)
	}
	r = ok(t, v.run("get", id, "-o", "-", "--unverified-stream"))
	if r.stdout != "streamed" {
		t.Fatalf("stdout: %q", r.stdout)
	}
}

// Review M2 and M6: a 252-byte output name used to fail because "<name>.part"
// exceeded NAME_MAX; temp names are now short and fixed-length.
func TestReviewM2LongOutputName(t *testing.T) {
	v := newVault(t)
	id := v.add("a.txt", []byte("long"))
	out := filepath.Join(v.work, strings.Repeat("n", 252))
	ok(t, v.run("get", id, "-o", out))
	if string(mustRead(t, out)) != "long" {
		t.Fatal("content")
	}
}

// Review M6: names from the host's directory listings are quoted, so escape
// sequences never reach the terminal.
func TestReviewM6HostNamesQuoted(t *testing.T) {
	v := newVault(t)
	evil := filepath.Join(v.dir, "objects", "\x1b]0;pwned\x07.obj")
	os.WriteFile(evil, []byte("x"), 0o600)
	evilInbox := filepath.Join(v.dir, "inbox", "\x1b[2Jclear.inb")
	os.WriteFile(evilInbox, []byte("x"), 0o600)
	for _, r := range []result{fails(t, v.run("verify")), fails(t, v.run("ls")), fails(t, v.run("ingest"))} {
		if strings.Contains(r.stdout+r.stderr, "\x1b") || strings.Contains(r.stdout+r.stderr, "\x07") {
			t.Fatalf("raw escape reached the output: %q %q", r.stdout, r.stderr)
		}
	}
	if _, err := os.Stat(evilInbox); err != nil {
		t.Fatal("stray inbox file removed")
	}
}

// Review L4: a FIFO at an object path must not hang get or verify; symlinks
// are refused; vault.json is capped at 4096 bytes.
func TestReviewL4RegularFilesOnly(t *testing.T) {
	v := newVault(t)
	var id core.FileID
	rand.Read(id[:])
	fifo := filepath.Join(v.dir, filepath.FromSlash(core.ObjectPath(id)))
	os.MkdirAll(filepath.Dir(fifo), 0o700)
	if err := mkfifo(fifo); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan result, 1)
	go func() { done <- valv(t, v.pass, v.args("get", id.String(), "-o", filepath.Join(v.work, "out"))...) }()
	select {
	case r := <-done:
		fails(t, r)
	case <-time.After(20 * time.Second):
		t.Fatal("get hung on a FIFO")
	}
	fails(t, v.run("verify"))
	os.Remove(fifo)

	// Symlinked object.
	real := v.add("real.txt", []byte("real"))
	target := v.objectPath(real)
	rand.Read(id[:])
	link := filepath.Join(v.dir, filepath.FromSlash(core.ObjectPath(id)))
	os.MkdirAll(filepath.Dir(link), 0o700)
	os.Symlink(target, link)
	fails(t, v.run("get", id.String(), "-o", filepath.Join(v.work, "out2")))
	fails(t, v.run("verify"))
	os.Remove(link)
	os.Remove(filepath.Dir(link))

	// Oversized vault.json.
	cfg := filepath.Join(v.dir, "vault.json")
	orig := mustRead(t, cfg)
	os.WriteFile(cfg, append(bytes.Clone(orig), bytes.Repeat([]byte(" "), 5000)...), 0o600)
	r := fails(t, v.run("ls"))
	if !strings.Contains(r.stderr, "4096") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	os.WriteFile(cfg, orig, 0o600)
	ok(t, v.run("verify"))
}

// Review L5: minimum passphrase length with an override, and exactly one
// line ending stripped from --passphrase-stdin input.
func TestReviewL5Passphrases(t *testing.T) {
	tmp := t.TempDir()
	r := fails(t, valv(t, "short\n", "init", "--passphrase-stdin", filepath.Join(tmp, "a")))
	if !strings.Contains(r.stderr, "12") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	notExist(t, filepath.Join(tmp, "a", "vault.json"))
	ok(t, valv(t, "short\n", "init", "--passphrase-stdin", "--allow-weak-passphrase", filepath.Join(tmp, "b")))
	ok(t, valv(t, "short\n", "ls", "--passphrase-stdin", "--vault", filepath.Join(tmp, "b")))

	// A trailing \r is part of the passphrase when no newline follows.
	dir := filepath.Join(tmp, "c")
	ok(t, valv(t, "carriage return\r", "init", "--passphrase-stdin", dir))
	ok(t, valv(t, "carriage return\r", "ls", "--passphrase-stdin", "--vault", dir))
	ok(t, valv(t, "carriage return\r\r\n", "ls", "--passphrase-stdin", "--vault", dir))
	fails(t, valv(t, "carriage return\n", "ls", "--passphrase-stdin", "--vault", dir))
	fails(t, valv(t, "carriage return\r\n", "ls", "--passphrase-stdin", "--vault", dir))
}

// Review S2: an object whose name is NFD (written by another tool) is
// readable; verify warns but does not fail, and get by id works.
func TestReviewS2NonNFCAccepted(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "vault")
	os.MkdirAll(filepath.Join(dir, "inbox"), 0o700)
	vectors := "../../testvectors"
	os.WriteFile(filepath.Join(dir, "vault.json"), mustRead(t, filepath.Join(vectors, "vault/vault.json")), 0o600)
	obj := mustRead(t, filepath.Join(vectors, "objects/nfd_name.obj"))
	var id core.FileID
	copy(id[:], obj[6:22])
	p := filepath.Join(dir, filepath.FromSlash(core.ObjectPath(id)))
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, obj, 0o600)
	pass := "correct horse battery staple\n"
	args := func(a ...string) []string {
		return append([]string{a[0], "--vault", dir, "--passphrase-stdin"}, a[1:]...)
	}
	r := ok(t, valv(t, pass, args("verify")...))
	if !strings.Contains(r.stdout, "warn") || !strings.Contains(r.stdout, "not NFC") {
		t.Fatalf("verify: %s", r.stdout)
	}
	ok(t, valv(t, pass, args("ls")...))
	out := filepath.Join(tmp, "out")
	ok(t, valv(t, pass, args("get", id.String(), "-o", out)...))
	if string(mustRead(t, out)) != "NFD" {
		t.Fatal("content")
	}
	// By path, typed in NFC.
	ok(t, valv(t, pass, args("get", "Kök/Räksmörgås.txt", "-o", filepath.Join(tmp, "out2"))...))
}

// recovery-key prints the same key that init showed.
func TestRecoveryKeyCommandMatchesInit(t *testing.T) {
	v := newVault(t)
	r := ok(t, v.run("recovery-key"))
	if got := strings.TrimSpace(r.stdout); got != v.recoveryKey {
		t.Fatalf("recovery-key %q differs from init's %q", got, v.recoveryKey)
	}
}
