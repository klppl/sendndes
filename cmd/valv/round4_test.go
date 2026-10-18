package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klppl/valv/core"
)

// promptTerminal answers prompts in order and runs onFirst at the first one,
// i.e. while the command waits at its first passphrase prompt.
type promptTerminal struct {
	answers []string
	onFirst func()
	called  bool
}

func (p *promptTerminal) IsTerminal() bool { return true }

func (p *promptTerminal) ReadPassword(prompt string) (string, error) {
	if !p.called {
		p.called = true
		if p.onFirst != nil {
			p.onFirst()
		}
	}
	if len(p.answers) == 0 {
		return "", os.ErrClosed
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return a, nil
}

// runPrompted runs a command in-process with a promptTerminal.
func runPrompted(t *testing.T, term *promptTerminal, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, term: term}
	return a.run(args), out.String(), errb.String()
}

// swapVault moves the vault away and puts a symlink to an empty directory at
// its path. It returns where the original vault went and the decoy directory.
func swapVault(t *testing.T, vault string) (orig, decoy string) {
	t.Helper()
	orig = vault + "-orig"
	decoy = vault + "-decoy"
	if err := os.Rename(vault, orig); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, vault); err != nil {
		t.Fatal(err)
	}
	return orig, decoy
}

func emptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("%s is not empty: %v %v", dir, entries, err)
	}
}

func countObjects(t *testing.T, vault string) int {
	t.Helper()
	n := 0
	filepath.Walk(filepath.Join(vault, "objects"), func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() && strings.HasSuffix(p, ".obj") {
			n++
		}
		return nil
	})
	return n
}

const pass = "correct horse battery" // pw without the newline

// Review round 4, NEW 2: the vault path is swapped for a symlink while each
// command waits at its first passphrase prompt. Every write must land in the
// originally opened vault; the decoy directory must stay empty.
func TestRound4VaultSwappedAtPrompt(t *testing.T) {
	t.Run("passwd", func(t *testing.T) {
		v := newVault(t)
		var orig, decoy string
		before := mustRead(t, filepath.Join(v.dir, "vault.json"))
		term := &promptTerminal{answers: []string{pass, "swapped passphrase", "swapped passphrase"},
			onFirst: func() { orig, decoy = swapVault(t, v.dir) }}
		if code, _, stderr := runPrompted(t, term, "passwd", "--vault", v.dir); code != 0 {
			t.Fatalf("passwd: %s", stderr)
		}
		emptyDir(t, decoy)
		after := mustRead(t, filepath.Join(orig, "vault.json"))
		if bytes.Equal(before, after) {
			t.Fatal("the original vault.json was not changed")
		}
		c, _ := core.ParseConfig(after)
		if _, err := core.Unlock(c, "swapped passphrase"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("add", func(t *testing.T) {
		v := newVault(t)
		src := filepath.Join(v.work, "src.txt")
		os.WriteFile(src, []byte("data"), 0o600)
		var orig, decoy string
		term := &promptTerminal{answers: []string{pass}, onFirst: func() { orig, decoy = swapVault(t, v.dir) }}
		if code, _, stderr := runPrompted(t, term, "add", "--vault", v.dir, src); code != 0 {
			t.Fatalf("add: %s", stderr)
		}
		emptyDir(t, decoy)
		if countObjects(t, orig) != 1 {
			t.Fatal("the object did not land in the original vault")
		}
	})

	t.Run("ingest", func(t *testing.T) {
		v := newVault(t)
		_, kAuth := v.serverConfig()
		_, inboxFile := v.seal(kAuth, core.Metadata{Name: "scan.pdf", MTime: 1}, []byte("scan"))
		var orig, decoy string
		term := &promptTerminal{answers: []string{pass}, onFirst: func() { orig, decoy = swapVault(t, v.dir) }}
		if code, _, stderr := runPrompted(t, term, "ingest", "--vault", v.dir); code != 0 {
			t.Fatalf("ingest: %s", stderr)
		}
		emptyDir(t, decoy)
		if countObjects(t, orig) != 1 {
			t.Fatal("the object did not land in the original vault")
		}
		notExist(t, filepath.Join(orig, "inbox", filepath.Base(inboxFile)))
	})

	t.Run("recover", func(t *testing.T) {
		v := newVault(t)
		v.add("a.txt", []byte("data")) // so the key is verified by an object
		os.Remove(filepath.Join(v.dir, "vault.json"))
		var orig, decoy string
		term := &promptTerminal{answers: []string{v.recoveryKey, "recovered passphrase", "recovered passphrase"},
			onFirst: func() { orig, decoy = swapVault(t, v.dir) }}
		if code, _, stderr := runPrompted(t, term, "recover", v.dir); code != 0 {
			t.Fatalf("recover: %s", stderr)
		}
		emptyDir(t, decoy)
		c, err := core.ParseConfig(mustRead(t, filepath.Join(orig, "vault.json")))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := core.Unlock(c, "recovered passphrase"); err != nil {
			t.Fatal(err)
		}
	})
}

// Review round 4, NEW 2: a vault path whose last component is a symlink is
// refused up front (the handle is opened with no-follow).
func TestRound4SymlinkedVaultPathRefused(t *testing.T) {
	v := newVault(t)
	link := filepath.Join(v.tmp, "vault-link")
	os.Symlink(v.dir, link)
	r := fails(t, valv(t, pw, "ls", "--vault", link, "--passphrase-stdin"))
	if !strings.Contains(r.stderr, "symlink") {
		t.Fatalf("stderr: %s", r.stderr)
	}
}

// Review round 4, NEW 1: the output directory is moved into the vault while
// get waits at the prompt. The final check must refuse, and no plaintext (or
// temp file) may be left in the vault.
func TestRound4GetOutputMovedIntoVault(t *testing.T) {
	v := newVault(t)
	id := v.add("secret.txt", []byte("plaintext secret"))
	out := filepath.Join(v.work, "out")
	os.Mkdir(out, 0o700)
	moved := filepath.Join(v.dir, "out")
	term := &promptTerminal{answers: []string{pass}, onFirst: func() {
		if err := os.Rename(out, moved); err != nil {
			t.Fatal(err)
		}
	}}
	code, _, stderr := runPrompted(t, term, "get", "--vault", v.dir, id, "-o", filepath.Join(out, "secret.txt"))
	if code == 0 || !strings.Contains(stderr, "inside the vault") {
		t.Fatalf("code %d, stderr %s", code, stderr)
	}
	emptyDir(t, moved)
	filepath.Walk(v.dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() && bytes.Contains(mustRead(t, p), []byte("plaintext secret")) {
			t.Errorf("plaintext left in the vault at %s", p)
		}
		return nil
	})
}

// Review round 4, NEW 3: what an interrupted init leaves behind gets a hint;
// nothing is deleted. Anything else is just "not empty".
func TestRound4InterruptedInitMessage(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "half")
	os.MkdirAll(filepath.Join(dir, "objects"), 0o700)
	os.MkdirAll(filepath.Join(dir, "inbox"), 0o700)
	tmpFile := filepath.Join(dir, ".valv-0123456789abcdef.part")
	os.WriteFile(tmpFile, []byte("partial vault.json"), 0o600)
	r := fails(t, valv(t, pw, "init", "--passphrase-stdin", dir))
	if !strings.Contains(r.stderr, "this looks like an interrupted init; remove the directory and run init again") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatal("init deleted something")
	}
	// Only objects/ (empty): still the hint.
	dir2 := filepath.Join(tmp, "half2")
	os.MkdirAll(filepath.Join(dir2, "objects"), 0o700)
	if r := fails(t, valv(t, pw, "init", "--passphrase-stdin", dir2)); !strings.Contains(r.stderr, "interrupted init") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	// A non-empty objects/ or any other file: no hint.
	for _, extra := range []string{"objects/x", "notes.txt"} {
		d := filepath.Join(tmp, "other-"+filepath.Base(extra))
		os.MkdirAll(filepath.Join(d, "objects"), 0o700)
		os.WriteFile(filepath.Join(d, extra), []byte("x"), 0o600)
		r := fails(t, valv(t, pw, "init", "--passphrase-stdin", d))
		if strings.Contains(r.stderr, "interrupted") || !strings.Contains(r.stderr, "not empty") {
			t.Fatalf("%s: %s", extra, r.stderr)
		}
	}
}

// Review round 4, wording: the advice after an unverified recovery.
func TestRound4UnverifiedRecoveryAdvice(t *testing.T) {
	v := newVault(t)
	id := v.add("a.txt", []byte("data"))
	p := v.objectPath(id)
	data := mustRead(t, p)
	copy(data[34:82], randBytes(48)) // decoy: nothing unwraps
	os.WriteFile(p, data, 0o600)
	os.Remove(filepath.Join(v.dir, "vault.json"))
	r := ok(t, valv(t, v.recoveryKey+"\nrecovered passphrase\n", "recover", "--passphrase-stdin", "--unverified-key", v.dir))
	want := "Run `valv ls`. If every file fails with an authentication error, the key was probably wrong: run recover again with the right key and --force. If only some files fail, those objects may be damaged: run `valv verify`."
	if !strings.Contains(r.stdout, want) {
		t.Fatalf("stdout: %s", r.stdout)
	}
}
