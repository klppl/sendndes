package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klppl/valv/core"
)

func mkfifo(p string) error { return syscall.Mkfifo(p, 0o600) }

// fakeTerminal answers ReadPassword prompts from a list.
type fakeTerminal struct{ answers []string }

func (f *fakeTerminal) IsTerminal() bool { return true }

func (f *fakeTerminal) ReadPassword(prompt string) (string, error) {
	if len(f.answers) == 0 {
		return "", errors.New("no more answers")
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a, nil
}

// interactiveInit runs init in-process with a fake terminal. retype maps the
// shown recovery key to what the user types back.
func interactiveInit(t *testing.T, dir string, retype func(string) string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	term := &fakeTerminal{answers: []string{"interactive passphrase", "interactive passphrase"}}
	// The retype answer depends on the key printed, so feed it lazily.
	a := &app{stdin: strings.NewReader(""), stdout: &out, stderr: &errb}
	a.term = &lazyRetype{fakeTerminal: term, out: &out, retype: retype}
	code := a.run([]string{"init", dir})
	return code, errb.String()
}

type lazyRetype struct {
	*fakeTerminal
	out    *bytes.Buffer
	retype func(string) string
}

func (l *lazyRetype) ReadPassword(prompt string) (string, error) {
	if strings.Contains(prompt, "Retype") {
		return l.retype(recoveryKeyRE.FindString(l.out.String())), nil
	}
	return l.fakeTerminal.ReadPassword(prompt)
}

// Review M1: interactively, the recovery key must be retyped before
// vault.json is written.
func TestReviewM1InteractiveRetype(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "wrong")
	code, stderr := interactiveInit(t, dir, func(string) string {
		var vk [core.KeySize]byte
		return core.EncodeRecoveryKey(vk) // a valid key, but not this one
	})
	if code == 0 || !strings.Contains(stderr, "not created") {
		t.Fatalf("code %d, stderr %s", code, stderr)
	}
	notExist(t, filepath.Join(dir, "vault.json"))

	dir = filepath.Join(tmp, "typo")
	code, stderr = interactiveInit(t, dir, func(k string) string { return k[:len(k)-1] + "A" })
	if code == 0 {
		t.Fatalf("a mistyped key was accepted: %s", stderr)
	}
	notExist(t, filepath.Join(dir, "vault.json"))

	dir = filepath.Join(tmp, "right")
	code, stderr = interactiveInit(t, dir, func(k string) string { return strings.ToLower(strings.ReplaceAll(k, "-", " ")) })
	if code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.json")); err != nil {
		t.Fatal(err)
	}
}

// Review M4: a source file that changes while it is read is not added.
func TestReviewM4SourceChangedWhileReading(t *testing.T) {
	keys := func() *core.VaultKeys {
		var vk [core.KeySize]byte
		k, _ := core.DeriveVaultKeys(vk)
		return k
	}()
	src := filepath.Join(t.TempDir(), "src")
	os.WriteFile(src, bytes.Repeat([]byte("a"), 1000), 0o600)
	f, _ := os.Open(src)
	defer f.Close()
	before, _ := f.Stat()

	obj, _ := core.PrepareObject(core.Metadata{Name: "x", MTime: 1, Rev: 1})
	// Another process appends while the file is being read.
	other, _ := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0)
	other.Write([]byte("more"))
	other.Close()
	if err := encryptSource(io.Discard, obj, keys, f, before); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("got %v", err)
	}

	// Unchanged file: fine.
	f2, _ := os.Open(src)
	defer f2.Close()
	before2, _ := f2.Stat()
	obj2, _ := core.PrepareObject(core.Metadata{Name: "x", MTime: 1, Rev: 1})
	if err := encryptSource(io.Discard, obj2, keys, f2, before2); err != nil {
		t.Fatal(err)
	}
}

var tempNameRE = regexp.MustCompile(`^\.valv-[0-9a-f]{16}\.part$`)

// Review M2 (PoC): a symlink planted where the temp file used to go was
// followed. Temp files are now random, exclusive and never follow symlinks,
// and moving into place replaces a planted symlink instead of writing through it.
func TestReviewM2TempFiles(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("victim"), 0o600)

	// Old predictable temp name planted as a symlink: ignored now.
	dst := filepath.Join(dir, "out")
	os.Symlink(victim, dst+".part")
	var seen string
	err := writeAtomic(dst, writeOpts{check: func(r *os.File) error {
		seen = filepath.Base(r.Name())
		st, err := os.Lstat(r.Name())
		if err != nil || st.Mode().Perm() != 0o600 || !st.Mode().IsRegular() {
			t.Errorf("temp file mode %v, %v", st.Mode(), err)
		}
		return nil
	}}, func(w io.Writer) error { _, err := w.Write([]byte("new")); return err })
	if err != nil {
		t.Fatal(err)
	}
	if !tempNameRE.MatchString(seen) {
		t.Fatalf("temp name %q", seen)
	}
	if string(mustRead(t, victim)) != "victim" || string(mustRead(t, dst)) != "new" {
		t.Fatal("wrote through a symlink")
	}

	// A symlink planted at the destination is replaced (overwrite) or refused.
	dst2 := filepath.Join(dir, "out2")
	os.Symlink(victim, dst2)
	err = writeAtomic(dst2, writeOpts{}, func(w io.Writer) error { _, err := w.Write([]byte("x")); return err })
	if !errors.Is(err, errExists) {
		t.Fatalf("no-overwrite onto a symlink: %v", err)
	}
	if err := writeAtomic(dst2, writeOpts{overwrite: true}, func(w io.Writer) error { _, err := w.Write([]byte("x")); return err }); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(dst2); !st.Mode().IsRegular() || string(mustRead(t, victim)) != "victim" {
		t.Fatal("overwrite followed the symlink")
	}

	// A failing fill leaves nothing behind.
	err = writeAtomic(filepath.Join(dir, "out3"), writeOpts{}, func(w io.Writer) error { return errors.New("boom") })
	if err == nil {
		t.Fatal("no error")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".valv-") {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

// Review L2: SIGINT during a write removes the temp file and exits 130.
func TestReviewL2SignalRemovesTempFiles(t *testing.T) {
	dir := t.TempDir()
	exited := make(chan int, 1)
	stop := installSignalCleanup(func(code int) { exited <- code })
	defer stop()

	started := make(chan string, 1)
	release := make(chan struct{})
	go writeAtomic(filepath.Join(dir, "out"), writeOpts{}, func(w io.Writer) error {
		w.Write([]byte("partial plaintext"))
		started <- "ok"
		<-release
		return errors.New("interrupted")
	})
	<-started
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || !tempNameRE.MatchString(entries[0].Name()) {
		t.Fatalf("temp file not there: %v", entries)
	}
	syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case code := <-exited:
		if code != 130 {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("signal not handled")
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("temp file left after SIGINT: %v", entries)
	}
	close(release)
}

// Review I4: a core error is printed with one "valv: " prefix.
func TestReviewI4SinglePrefix(t *testing.T) {
	if got := oneLine("valv: objects/x: valv: authentication failed: chunk 1"); got != "objects/x: authentication failed: chunk 1" {
		t.Fatalf("got %q", got)
	}
}

// writeAtomic (tests only) writes the path dst through writeAt, relative to a handle on
// dst's directory part (resolved physically).
func writeAtomic(dst string, opts writeOpts, fill func(io.Writer) error) error {
	dir, name := splitPath(dst)
	d, err := openDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return writeAt(d, name, opts, fill)
}
