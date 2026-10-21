package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klppl/sendndes/core"
)

// N1 (in-process): every handled signal removes temp files and runs the
// cleanup hooks, then exits with 128 + the signal number.
func TestN1AllSignalsCleanUp(t *testing.T) {
	for _, c := range []struct {
		sig  syscall.Signal
		code int
	}{{syscall.SIGINT, 130}, {syscall.SIGTERM, 143}, {syscall.SIGHUP, 129}, {syscall.SIGQUIT, 131}} {
		t.Run(c.sig.String(), func(t *testing.T) {
			dir := t.TempDir()
			exited := make(chan int, 1)
			stop := installSignalCleanup(func(code int) { exited <- code })
			defer stop()
			hookRan := false
			defer addCleanupHook(func() { hookRan = true })()
			started := make(chan struct{})
			release := make(chan struct{})
			go writeAtomic(filepath.Join(dir, "out"), writeOpts{}, func(w io.Writer) error {
				w.Write([]byte("partial"))
				close(started)
				<-release
				return errors.New("interrupted")
			})
			<-started
			syscall.Kill(os.Getpid(), c.sig)
			select {
			case code := <-exited:
				if code != c.code {
					t.Fatalf("exit code %d, want %d", code, c.code)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("signal not handled")
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 || !hookRan {
				t.Fatalf("after %v: entries %v, hook ran %v", c.sig, entries, hookRan)
			}
			close(release)
		})
	}
}

// N1 (real process): read-only and writing commands, including init and
// recover, exit with 128 + signal while waiting for a passphrase.
func TestN1SignalExitCodesRealProcess(t *testing.T) {
	v := newVault(t)
	other := newVault(t)
	os.Remove(filepath.Join(v.dir, "vault.json"))
	for _, c := range []struct {
		args []string
		sig  syscall.Signal
		code int
	}{
		{[]string{"init", "--passphrase-stdin", filepath.Join(v.tmp, "new")}, syscall.SIGHUP, 129},
		{[]string{"recover", "--passphrase-stdin", v.dir}, syscall.SIGQUIT, 131},
		{[]string{"recover", "--passphrase-stdin", v.dir}, syscall.SIGTERM, 143},
		{[]string{"ls", "--passphrase-stdin", "--vault", other.dir}, syscall.SIGINT, 130},
	} {
		cmd := exec.Command(os.Args[0], c.args...)
		cmd.Env = []string{"NDES_TEST_RUN_MAIN=1"}
		stdin, _ := cmd.StdinPipe() // left open: the command blocks reading it
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
		cmd.Process.Signal(c.sig)
		err := cmd.Wait()
		stdin.Close()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != c.code {
			t.Errorf("%v %v: %v, want exit %d", c.args[0], c.sig, err, c.code)
		}
	}
	notExist(t, filepath.Join(v.tmp, "new"), filepath.Join(v.dir, "vault.json"))
}

// N2: the terminal-restore hook registered while echo is off runs on a
// signal. (No pty in the test setup, so the hook itself is checked.)
func TestN2TerminalRestoredOnSignal(t *testing.T) {
	exited := make(chan int, 1)
	stop := installSignalCleanup(func(code int) { exited <- code })
	defer stop()
	restored := make(chan struct{}, 1)
	remove := addCleanupHook(func() { restored <- struct{}{} }) // what osTerminal.ReadPassword registers
	defer remove()
	syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case <-restored:
	case <-time.After(10 * time.Second):
		t.Fatal("terminal restore hook did not run")
	}
	<-exited
	// A removed hook does not run.
	ran := false
	addCleanupHook(func() { ran = true })()
	runCleanup()
	if ran {
		t.Fatal("unregistered hook ran")
	}
}

// N3: an -o that is an existing directory is refused, inside or outside the
// vault, also through a symlink.
func TestN3OutputDirectoryRefused(t *testing.T) {
	v := newVault(t)
	id := v.add("a.txt", []byte("data"))
	outside := filepath.Join(v.work, "dir")
	os.Mkdir(outside, 0o700)
	link := filepath.Join(v.work, "dirlink")
	os.Symlink(outside, link)
	for _, out := range []string{outside, link, filepath.Join(v.dir, "objects"), v.dir} {
		r := fails(t, v.run("get", id, "-o", out, "--force"))
		if !strings.Contains(r.stderr, "directory") {
			t.Fatalf("%s: %s", out, r.stderr)
		}
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote into %s: %v", outside, entries)
	}
	noTemps(t, v.tmp)
}

// N4/N7 case 3: no objects, but a genuine inbox file confirms the key.
func TestN4RecoverVerifiedByInbox(t *testing.T) {
	v := newVault(t)
	_, kAuth := v.serverConfig()
	v.seal(kAuth, core.Metadata{Name: "scan.pdf", MTime: 1}, []byte("scan"))
	os.Remove(filepath.Join(v.dir, "vault.json"))
	r := ok(t, ndes(t, v.recoveryKey+"\nrecovered passphrase\n", "recover", "--passphrase-stdin", v.dir))
	if !strings.Contains(r.stdout, "inbox file") {
		t.Fatalf("stdout: %s", r.stdout)
	}
	v.pass = "recovered passphrase\n"
	ok(t, v.run("ingest"))
}

// N4/N7 case 4: a planted garbage inbox file, or only damaged objects, make
// the key unverifiable: refused (never "wrong key") unless --unverified-key.
func TestN4RecoverUnverifiable(t *testing.T) {
	// Planted garbage inbox file on an otherwise empty vault.
	v := newVault(t)
	var id core.FileID
	rand.Read(id[:])
	os.WriteFile(filepath.Join(v.dir, "inbox", core.InboxName(id)), randBytes(500), 0o600)
	cfg := filepath.Join(v.dir, "vault.json")
	os.Remove(cfg)
	in := v.recoveryKey + "\nrecovered passphrase\n"
	r := fails(t, ndes(t, in, "recover", "--passphrase-stdin", v.dir))
	if !strings.Contains(r.stderr, "cannot be verified: 0 of 0 readable objects unwrap") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	notExist(t, cfg)
	r = ok(t, ndes(t, in, "recover", "--passphrase-stdin", "--unverified-key", v.dir))
	if !strings.Contains(r.stdout, "NOT verified") {
		t.Fatalf("stdout: %s", r.stdout)
	}

	// Only damaged objects.
	v2 := newVault(t)
	objID := v2.add("a.txt", []byte("data"))
	p := v2.objectPath(objID)
	os.WriteFile(p, mustRead(t, p)[:50], 0o600)
	cfg2 := filepath.Join(v2.dir, "vault.json")
	os.Remove(cfg2)
	in2 := v2.recoveryKey + "\nrecovered passphrase\n"
	r = fails(t, ndes(t, in2, "recover", "--passphrase-stdin", v2.dir))
	if !strings.Contains(r.stderr, "cannot be verified: 0 of 0 readable objects unwrap") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	notExist(t, cfg2)
	ok(t, ndes(t, in2, "recover", "--passphrase-stdin", "--unverified-key", v2.dir))

	// F2: readable objects that do not unwrap are "cannot be verified" too,
	// never a hard refusal.
	v3 := newVault(t)
	v3.add("a.txt", []byte("data"))
	os.Remove(filepath.Join(v3.dir, "vault.json"))
	var wrong [core.KeySize]byte
	rand.Read(wrong[:])
	in3 := core.EncodeRecoveryKey(wrong) + "\nrecovered passphrase\n"
	r = fails(t, ndes(t, in3, "recover", "--passphrase-stdin", v3.dir))
	if !strings.Contains(r.stderr, "cannot be verified: 0 of 1 readable objects unwrap") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	ok(t, ndes(t, in3, "recover", "--passphrase-stdin", "--unverified-key", v3.dir))
}

// N4/N7: interactively, cases 4 (with the override) and 5 need a retype.
func TestN4RecoverRetypeInteractive(t *testing.T) {
	v := newVault(t)
	cfg := filepath.Join(v.dir, "vault.json")
	os.Remove(cfg)
	run := func(answers ...string) (int, string) {
		var out, errb bytes.Buffer
		a := &app{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, term: &fakeTerminal{answers: answers}}
		return a.run([]string{"recover", v.dir}), errb.String()
	}
	var other [core.KeySize]byte
	if code, stderr := run(v.recoveryKey, core.EncodeRecoveryKey(other)); code == 0 || !strings.Contains(stderr, "not the same") {
		t.Fatalf("wrong retype accepted: %s", stderr)
	}
	notExist(t, cfg)
	if code, stderr := run(v.recoveryKey, strings.ToLower(v.recoveryKey), "interactive passphrase", "interactive passphrase"); code != 0 {
		t.Fatalf("recover: %s", stderr)
	}
	if _, err := os.Stat(cfg); err != nil {
		t.Fatal(err)
	}
}

// N5: init removes the directories it created, and only those, on an error
// or a signal before vault.json is committed.
func TestN5InitCleansUpCreatedDirs(t *testing.T) {
	defer func() { initTestHook = nil }()
	tmp := t.TempDir()
	initRun := func(dir string) int {
		a := &app{stdin: strings.NewReader("init passphrase\n"), stdout: io.Discard, stderr: io.Discard, term: &fakeTerminal{}, passStdin: true}
		return a.run([]string{"init", "--passphrase-stdin", dir})
	}

	// Error: nested new directories are all removed.
	initTestHook = func() error { return errors.New("injected failure") }
	nested := filepath.Join(tmp, "a", "b", "vault")
	if initRun(nested) == 0 {
		t.Fatal("init succeeded")
	}
	notExist(t, filepath.Join(tmp, "a"))

	// Error with a pre-existing empty vault directory: it stays.
	existing := filepath.Join(tmp, "existing")
	os.Mkdir(existing, 0o700)
	if initRun(existing) == 0 {
		t.Fatal("init succeeded")
	}
	if entries, err := os.ReadDir(existing); err != nil || len(entries) != 0 {
		t.Fatalf("existing dir: %v, %v", entries, err)
	}

	// Signal while vault.json's temp file exists.
	exited := make(chan int, 1)
	stop := installSignalCleanup(func(code int) { exited <- code })
	defer stop()
	initTestHook = func() error {
		syscall.Kill(os.Getpid(), syscall.SIGHUP)
		<-exited
		return errors.New("interrupted")
	}
	sig := filepath.Join(tmp, "sig", "vault")
	initRun(sig)
	notExist(t, filepath.Join(tmp, "sig"))

	// Success keeps everything.
	initTestHook = nil
	if initRun(filepath.Join(tmp, "ok")) != 0 {
		t.Fatal("init failed")
	}
	if _, err := os.Stat(filepath.Join(tmp, "ok", "vault.json")); err != nil {
		t.Fatal(err)
	}
}

// N6: default names starting with "." or containing C1 controls are refused;
// -o still works. Windows builds fail with a clear message.
func TestN6DefaultNamesAndPlatforms(t *testing.T) {
	v := newVault(t)
	_, kAuth := v.serverConfig()
	for _, name := range []string{".bashrc", ".hidden.txt", "c1\u0085x", "csi\u009b31m"} {
		id, _ := v.seal(kAuth, core.Metadata{Name: name, MTime: 1}, []byte("data"))
		ok(t, v.run("ingest"))
		fails(t, v.runIn(v.work, "get", id.String()))
		ok(t, v.run("get", id.String(), "-o", filepath.Join(v.work, "out-"+id.String())))
	}
	id, _ := v.seal(kAuth, core.Metadata{Name: "colon: fine.txt", MTime: 1}, []byte("ok"))
	ok(t, v.run("ingest"))
	ok(t, v.runIn(v.work, "get", id.String()))

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not in PATH")
	}
	for _, pkg := range []string{"./", "../../core"} {
		cmd := exec.Command(goBin, "build", "-o", os.DevNull, pkg)
		cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "ndes_supports_only_macOS_iOS_and_Linux") {
			t.Fatalf("windows build of %s: %v\n%s", pkg, err, out)
		}
	}
}

// N8: OS junk in the root, objects/, objects/xx/ and inbox/ gives notes and a
// passing verify; a junk-named symlink and an unlisted stray file still fail.
func TestN8OSJunk(t *testing.T) {
	v := newVault(t)
	id := v.add("a.txt", []byte("data"))
	xx := filepath.Dir(v.objectPath(id))
	junk := []string{
		filepath.Join(v.dir, ".DS_Store"),
		filepath.Join(v.dir, "objects", "Thumbs.db"),
		filepath.Join(xx, ".DS_Store"),
		filepath.Join(xx, "._"+filepath.Base(v.objectPath(id))),
		filepath.Join(v.dir, "inbox", "desktop.ini"),
		filepath.Join(v.dir, "inbox", ".localized"),
	}
	for _, p := range junk {
		os.WriteFile(p, []byte("junk"), 0o600)
	}
	os.MkdirAll(filepath.Join(v.dir, ".Spotlight-V100", "Store-V2", "anything"), 0o700)
	os.MkdirAll(filepath.Join(v.dir, "objects", ".fseventsd"), 0o700)
	os.WriteFile(filepath.Join(v.dir, "objects", ".fseventsd", "not-scanned"), []byte("x"), 0o600)
	r := ok(t, v.run("verify"))
	if !strings.Contains(r.stdout, fmt.Sprintf("%d junk file(s) ignored", len(junk)+2)) { // F3
		t.Fatalf("verify summary:\n%s", r.stdout)
	}
	if strings.Count(r.stdout, "OS junk") != len(junk)+2 {
		t.Fatalf("verify notes:\n%s", r.stdout)
	}
	ok(t, v.run("ls"))
	ok(t, v.run("ingest"))
	for _, p := range junk {
		if string(mustRead(t, p)) != "junk" {
			t.Fatalf("%s changed", p)
		}
	}

	link := filepath.Join(v.dir, "inbox", ".DS_Store")
	os.Symlink("/etc/hosts", link)
	fails(t, v.run("verify"))
	os.Remove(link)
	stray := filepath.Join(v.dir, "notes.txt")
	os.WriteFile(stray, []byte("x"), 0o600)
	fails(t, v.run("verify"))
	os.Remove(stray)
	ok(t, v.run("verify"))
}

// N9: a symlinked objects/ (or objects/xx/) directory is an error in verify
// and makes every other command refuse.
func TestN9SymlinkedDirectories(t *testing.T) {
	v := newVault(t)
	id := v.add("a.txt", []byte("data"))
	objects := filepath.Join(v.dir, "objects")
	elsewhere := filepath.Join(v.tmp, "elsewhere")
	os.Rename(objects, elsewhere)
	os.Symlink(elsewhere, objects)
	src := filepath.Join(v.work, "b.txt")
	os.WriteFile(src, []byte("b"), 0o600)
	r := fails(t, v.run("verify"))
	if !strings.Contains(r.stdout, "symlinked directory in vault") {
		t.Fatalf("verify: %s", r.stdout)
	}
	for _, args := range [][]string{
		{"ls"}, {"get", id, "-o", filepath.Join(v.work, "out")}, {"add", src}, {"ingest"},
	} {
		r := fails(t, v.run(args...))
		if !strings.Contains(r.stderr, "symlinked directory") {
			t.Fatalf("%v: %s", args, r.stderr)
		}
	}
	fails(t, ndes(t, v.recoveryKey+"\nrecovered passphrase\n", "recover", "--passphrase-stdin", "--force", v.dir))
	os.Remove(objects)
	os.Rename(elsewhere, objects)
	ok(t, v.run("verify"))

	// A symlinked objects/xx/ directory.
	xx := filepath.Dir(v.objectPath(id))
	moved := filepath.Join(v.tmp, "xx")
	os.Rename(xx, moved)
	os.Symlink(moved, xx)
	r = fails(t, v.run("verify"))
	if !strings.Contains(r.stdout, "symlinked directory in vault") {
		t.Fatalf("verify: %s", r.stdout)
	}
	fails(t, v.run("get", id, "-o", filepath.Join(v.work, "out2")))
	notExist(t, filepath.Join(v.work, "out"), filepath.Join(v.work, "out2"))
}

// N10: server-config redirected to a regular file makes it mode 0600.
func TestN10ServerConfigFileMode(t *testing.T) {
	v := newVault(t)
	out := filepath.Join(v.work, "server.conf")
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := ndesIn(t, v.pass, []runOpt{func(c *exec.Cmd) { c.Stdout = f }}, v.args("server-config")...)
	if r.code != 0 || !strings.Contains(r.stderr, "secret") {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	st, _ := os.Stat(out)
	if st.Mode().Perm() != 0o600 || !strings.Contains(string(mustRead(t, out)), "k_auth: ") {
		t.Fatalf("mode %v", st.Mode())
	}
}

// N11: two files whose paths differ only in normalization coexist; get by
// path reports the ambiguity, verify warns.
func TestN11NormalizationTwins(t *testing.T) {
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
	src := filepath.Join(tmp, "src")
	os.WriteFile(src, []byte("NFC twin"), 0o600)
	ok(t, ndes(t, pass, args("add", src, "--dir", "Kök", "--name", "Räksmörgås.txt")...))
	r := ok(t, ndes(t, pass, args("verify")...))
	if !strings.Contains(r.stdout, "differ only in Unicode normalization") {
		t.Fatalf("verify: %s", r.stdout)
	}
	r = fails(t, ndes(t, pass, args("get", "Kök/Räksmörgås.txt", "-o", filepath.Join(tmp, "out"))...))
	if !strings.Contains(r.stderr, "use an id") {
		t.Fatalf("stderr: %s", r.stderr)
	}
}
