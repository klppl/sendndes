package main

import (
	"bytes"
	"crypto/rand"
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

// valv runs the CLI with stdin as its standard input.
func valv(t *testing.T, stdin string, args ...string) result {
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
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{out.String(), errb.String(), code}
}

func ok(t *testing.T, r result) result {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	return r
}

func fails(t *testing.T, r result) result {
	t.Helper()
	if r.code == 0 {
		t.Fatalf("succeeded, want failure\nstdout: %s", r.stdout)
	}
	lines := strings.Split(strings.TrimSpace(r.stderr), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "valv: ") {
		t.Fatalf("last stderr line is not a one-line valv: error: %q", r.stderr)
	}
	return r
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

var recoveryKeyRE = regexp.MustCompile(`[A-Z2-7]{4}(-[A-Z2-7]{4}){12}`)

func TestCLI(t *testing.T) {
	tmp := t.TempDir()
	vault := filepath.Join(tmp, "vault")
	work := filepath.Join(tmp, "work")
	os.Mkdir(work, 0o700)
	pw := "correct horse\n"
	// v puts the common flags after the command name.
	v := func(args ...string) []string {
		return append([]string{args[0], "--vault", vault, "--passphrase-stdin"}, args[1:]...)
	}

	// init
	r := ok(t, valv(t, pw, "init", "--passphrase-stdin", vault))
	recoveryKey := recoveryKeyRE.FindString(r.stdout)
	if recoveryKey == "" || !strings.Contains(r.stdout, "self-check passed") {
		t.Fatalf("init output: %s", r.stdout)
	}
	for _, p := range []string{"vault.json", "objects", "inbox"} {
		if _, err := os.Stat(filepath.Join(vault, p)); err != nil {
			t.Fatal(err)
		}
	}
	fails(t, valv(t, pw, "init", "--passphrase-stdin", vault))
	fails(t, valv(t, "", "init", "--passphrase-stdin", filepath.Join(tmp, "empty-pass")))

	// Passphrase must not come from a non-terminal stdin without the flag.
	r = fails(t, valv(t, pw, "ls", "--vault", vault))
	if !strings.Contains(r.stderr, "--passphrase-stdin") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	fails(t, valv(t, "wrong\n", v("ls")...))

	// add, several sizes
	type added struct {
		id, path string
		data     []byte
		mtime    time.Time
	}
	var files []added
	sizes := []int{0, 1, core.ChunkSize, 3*core.ChunkSize + 5}
	for i, n := range sizes {
		name := []string{"empty.bin", "one.bin", "chunk.bin", "Räksmörgås.txt"}[i]
		src := filepath.Join(work, name)
		data := randBytes(n)
		os.WriteFile(src, data, 0o600)
		mt := time.Date(2001, 2, 3, 4, 5, 6, 789000000, time.UTC).Add(time.Duration(i) * time.Hour)
		os.Chtimes(src, mt, mt)
		r := ok(t, valv(t, pw, v("add", src, "--dir", "Docs/2026")...))
		id := strings.TrimSpace(r.stdout)
		if _, err := core.ParseFileID(id); err != nil {
			t.Fatalf("add printed %q", id)
		}
		files = append(files, added{id, "Docs/2026/" + name, data, mt})
	}
	src := filepath.Join(work, "x.txt")
	os.WriteFile(src, []byte("top level"), 0o600)
	r = ok(t, valv(t, pw, v("add", src, "--name", "renamed.txt")...))
	files = append(files, added{strings.TrimSpace(r.stdout), "renamed.txt", []byte("top level"), time.Time{}})
	fails(t, valv(t, pw, v("add", src, "--dir", "/abs")...))
	fails(t, valv(t, pw, v("add", src, "--name", "..")...))
	fails(t, valv(t, pw, v("add", filepath.Join(work, "missing"))...))

	// ls
	r = ok(t, valv(t, pw, v("ls")...))
	for _, f := range files {
		if !strings.Contains(r.stdout, f.id) || !strings.Contains(r.stdout, f.path) {
			t.Fatalf("ls misses %s\n%s", f.path, r.stdout)
		}
	}
	r = ok(t, valv(t, pw, v("ls", "--dir", "Docs")...))
	if strings.Contains(r.stdout, "renamed.txt") || strings.Count(r.stdout, "\n") != len(sizes) {
		t.Fatalf("ls --dir Docs:\n%s", r.stdout)
	}

	// get by id and by path, compare bytes and mtime
	for i, f := range files {
		out := filepath.Join(work, "out", f.id)
		os.MkdirAll(filepath.Dir(out), 0o700)
		arg := f.id
		if i%2 == 1 {
			arg = f.path
		}
		ok(t, valv(t, pw, v("get", arg, "-o", out)...))
		got, err := os.ReadFile(out)
		if err != nil || !bytes.Equal(got, f.data) {
			t.Fatalf("get %s: content differs", arg)
		}
		if st, _ := os.Stat(out); !f.mtime.IsZero() && !st.ModTime().Equal(f.mtime) {
			t.Fatalf("get %s: mtime %v, want %v", arg, st.ModTime(), f.mtime)
		}
	}
	// NFD path argument finds the NFC name.
	out := filepath.Join(work, "nfd.txt")
	ok(t, valv(t, pw, v("get", "Docs/2026/Räksmörgås.txt", "-o", out)...))
	// Refuse to overwrite; --force replaces.
	os.WriteFile(out, []byte("keep me"), 0o600)
	fails(t, valv(t, pw, v("get", files[1].id, "-o", out)...))
	if got, _ := os.ReadFile(out); string(got) != "keep me" {
		t.Fatal("existing output was changed")
	}
	ok(t, valv(t, pw, v("get", files[1].id, "-o", out, "--force")...))
	// Default output name, in the working directory.
	cmdDir := filepath.Join(work, "cwd")
	os.Mkdir(cmdDir, 0o700)
	cmd := exec.Command(os.Args[0], v("get", files[4].id)...)
	cmd.Dir = cmdDir
	cmd.Env = []string{"VALV_TEST_RUN_MAIN=1"}
	cmd.Stdin = strings.NewReader(pw)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(cmdDir, "renamed.txt")); string(got) != "top level" {
		t.Fatal("default output name")
	}
	// -o - writes plaintext to stdout.
	r = ok(t, valv(t, pw, v("get", files[4].id, "-o", "-")...))
	if r.stdout != "top level" {
		t.Fatalf("stdout: %q", r.stdout)
	}
	fails(t, valv(t, pw, v("get", "no/such/file", "-o", filepath.Join(work, "none"))...))

	// ingest a sealed inbox file
	cfg, _ := core.ParseConfig(mustRead(t, filepath.Join(vault, "vault.json")))
	inboxData := randBytes(core.ChunkSize + 77)
	var sealed bytes.Buffer
	inID, err := core.SealInbox(&sealed, cfg.InboxPub, core.Metadata{Name: "scan.pdf", Dir: "Inbox", MTime: 1, MIME: "application/pdf"}, bytes.NewReader(inboxData))
	if err != nil {
		t.Fatal(err)
	}
	inboxFile := filepath.Join(vault, "inbox", core.InboxName(inID))
	os.WriteFile(inboxFile, sealed.Bytes(), 0o600)
	r = ok(t, valv(t, pw, v("ingest")...))
	if !strings.Contains(r.stdout, "ingested 1") {
		t.Fatalf("ingest: %s", r.stdout)
	}
	if _, err := os.Stat(inboxFile); !os.IsNotExist(err) {
		t.Fatal("inbox file not removed after ingest")
	}
	out = filepath.Join(work, "scan.pdf")
	ok(t, valv(t, pw, v("get", inID.String(), "-o", out)...))
	if !bytes.Equal(mustRead(t, out), inboxData) {
		t.Fatal("ingested content differs")
	}
	// Ingest again after a lost delete: idempotent, inbox file removed.
	os.WriteFile(inboxFile, sealed.Bytes(), 0o600)
	r = ok(t, valv(t, pw, v("ingest")...))
	if !strings.Contains(r.stdout, "already ingested 1") {
		t.Fatalf("re-ingest: %s", r.stdout)
	}
	if _, err := os.Stat(inboxFile); !os.IsNotExist(err) {
		t.Fatal("inbox file not removed after idempotent ingest")
	}
	// A corrupt inbox file is kept and nothing is written.
	var sealed2 bytes.Buffer
	badID, _ := core.SealInbox(&sealed2, cfg.InboxPub, core.Metadata{Name: "bad.bin", MTime: 1}, bytes.NewReader(randBytes(2*core.ChunkSize)))
	bad := sealed2.Bytes()
	bad[len(bad)-3] ^= 1
	badInbox := filepath.Join(vault, "inbox", core.InboxName(badID))
	os.WriteFile(badInbox, bad, 0o600)
	fails(t, valv(t, pw, v("ingest")...))
	if _, err := os.Stat(badInbox); err != nil {
		t.Fatal("corrupt inbox file was deleted")
	}
	badObj := filepath.Join(vault, filepath.FromSlash(core.ObjectPath(badID)))
	for _, p := range []string{badObj, badObj + ".part"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", p)
		}
	}
	// verify also authenticates inbox files: the bad one fails it.
	r = fails(t, valv(t, pw, v("verify")...))
	if !strings.Contains(r.stdout, core.InboxName(badID)) {
		t.Fatalf("verify did not name the bad inbox file:\n%s", r.stdout)
	}
	os.Remove(badInbox)

	// verify on a good vault
	r = ok(t, valv(t, pw, v("verify")...))
	if !strings.Contains(r.stdout, "0 problem(s)") {
		t.Fatalf("verify: %s", r.stdout)
	}

	// flip one byte in an object
	objPath := filepath.Join(vault, filepath.FromSlash(core.ObjectPath(mustID(t, files[3].id))))
	orig := mustRead(t, objPath)
	flipped := bytes.Clone(orig)
	flipped[len(flipped)/2] ^= 0x40
	os.WriteFile(objPath, flipped, 0o600)
	r = fails(t, valv(t, pw, v("verify")...))
	if !strings.Contains(r.stdout, files[3].id) {
		t.Fatalf("verify did not name the object:\n%s", r.stdout)
	}
	// get must fail and leave nothing behind
	out = filepath.Join(work, "tampered.out")
	fails(t, valv(t, pw, v("get", files[3].id, "-o", out)...))
	for _, p := range []string{out, out + ".part"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left behind after an authentication error", p)
		}
	}
	os.WriteFile(objPath, orig, 0o600)
	ok(t, valv(t, pw, v("verify")...))

	// stray files and a renamed object
	stray := filepath.Join(vault, "objects", "conflicted copy.obj")
	os.WriteFile(stray, []byte("x"), 0o600)
	r = fails(t, valv(t, pw, v("verify")...))
	if !strings.Contains(r.stdout, "conflicted copy.obj") {
		t.Fatalf("verify did not report the stray file:\n%s", r.stdout)
	}
	os.Remove(stray)
	upper := filepath.Join(filepath.Dir(objPath), strings.ToUpper(files[3].id)+".obj")
	os.Rename(objPath, upper)
	fails(t, valv(t, pw, v("verify")...))
	var otherID core.FileID
	rand.Read(otherID[:])
	otherPath := filepath.Join(vault, filepath.FromSlash(core.ObjectPath(otherID)))
	os.MkdirAll(filepath.Dir(otherPath), 0o700)
	os.Rename(upper, otherPath)
	r = fails(t, valv(t, pw, v("verify")...))
	if !strings.Contains(r.stdout, "does not match") {
		t.Fatalf("verify did not report the id mismatch:\n%s", r.stdout)
	}
	os.Rename(otherPath, objPath)
	os.Remove(filepath.Dir(otherPath))
	ok(t, valv(t, pw, v("verify")...))

	// passwd
	pw2 := "new passphrase\n"
	ok(t, valv(t, pw+pw2, v("passwd")...))
	fails(t, valv(t, pw, v("ls")...))
	ok(t, valv(t, pw2, v("ls")...))

	// recover after deleting vault.json
	cfgPath := filepath.Join(vault, "vault.json")
	fails(t, valv(t, recoveryKey+"\nx\n", "recover", "--passphrase-stdin", vault)) // exists, no --force
	os.Remove(cfgPath)
	var wrong [core.KeySize]byte
	rand.Read(wrong[:])
	fails(t, valv(t, core.EncodeRecoveryKey(wrong)+"\nx\n", "recover", "--passphrase-stdin", vault))
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatal("recover with a wrong key wrote vault.json")
	}
	pw3 := "recovered\n"
	ok(t, valv(t, strings.ToLower(recoveryKey)+"\n"+pw3, "recover", "--passphrase-stdin", vault))
	fails(t, valv(t, pw2, v("ls")...))
	r = ok(t, valv(t, pw3, v("ls")...))
	if !strings.Contains(r.stdout, files[3].path) {
		t.Fatalf("ls after recover:\n%s", r.stdout)
	}
	ok(t, valv(t, pw3, v("verify")...))
	// No .part files anywhere.
	filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
		if strings.HasSuffix(p, ".part") {
			t.Errorf("leftover %s", p)
		}
		return nil
	})
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
