package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// snapshotTree records every path under root with its mode and content.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, _ := d.Info()
		v := info.Mode().String()
		if info.Mode().IsRegular() {
			v += ":" + string(mustRead(t, p))
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			v += "->" + target
		}
		m[p] = v
		return nil
	})
	return m
}

// F1: every path form that resolves into the vault fails before a temp file
// is created (the check runs before the passphrase is read, so these runs get
// no passphrase at all), and the vault tree is byte-identical afterwards.
func TestF1OutputPathForms(t *testing.T) {
	v := newVault(t)
	id := v.add("a.txt", []byte("data"))
	out := filepath.Join(v.work, "out")
	os.Mkdir(out, 0o700)
	os.Symlink(filepath.Join(v.dir, "objects"), filepath.Join(out, "lnk")) // out/lnk -> vault/objects
	os.Symlink(v.dir, filepath.Join(v.work, "vlink"))                      // vlink -> vault
	real, err := filepath.EvalSymlinks(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	objects := filepath.Join(v.dir, "objects")
	caseVariant := filepath.Join(filepath.Dir(v.dir), "VAULT", "x")

	before := snapshotTree(t, v.dir)
	cases := []struct {
		name, cwd, out string
	}{
		{"plain absolute", v.work, filepath.Join(v.dir, "x")},
		{"absolute vault.json", v.work, filepath.Join(v.dir, "vault.json")},
		{"relative", v.work, "../vault/x"},
		{"trailing slash", v.work, v.dir + "/"},
		{"dot", v.dir, "."},
		{"dot-dot", objects, ".."},
		{"dot-dot then name", objects, "../x"},
		{"dot then name", v.dir, "./x"},
		{"case variant", v.work, caseVariant},
		{"symlinked directory component", v.work, "vlink/x"},
		{"PoC: dot-dot after a symlink", v.work, "out/lnk/../vault.json"},
		{"dot-dot after a symlink, new name", v.work, "out/lnk/../newname"},
		{"dot-dot after a symlink, directory", v.work, "out/lnk/.."},
		{"physical path (/private/... on macOS)", v.work, filepath.Join(real, "x")},
		{"absolute, dot-dot after a symlink", v.work, v.work + "/out/lnk/../x"}, // not filepath.Join: it would clean ".." lexically
	}
	for _, c := range cases {
		for _, extra := range [][]string{nil, {"--force"}} {
			args := append([]string{"get", "--vault", v.dir, "--passphrase-stdin", id, "-o", c.out}, extra...)
			r := ndesIn(t, "", []runOpt{inDir(c.cwd)}, args...)
			if r.code == 0 {
				t.Fatalf("%s %v: succeeded", c.name, extra)
			}
			if strings.Contains(r.stderr, "could not read a line") {
				t.Fatalf("%s %v: the check ran after the passphrase prompt: %s", c.name, extra, r.stderr)
			}
		}
	}
	after := snapshotTree(t, v.dir)
	if len(before) != len(after) {
		t.Fatalf("vault tree changed: %d entries before, %d after", len(before), len(after))
	}
	for p, s := range before {
		if after[p] != s {
			t.Fatalf("vault tree changed at %s", p)
		}
	}
	noTemps(t, v.tmp)

	// A hard link outside the vault to vault.json is replaced, never written
	// through: vault.json stays intact.
	hl := filepath.Join(v.work, "hardlink")
	if err := os.Link(filepath.Join(v.dir, "vault.json"), hl); err != nil {
		t.Skip("hard links not supported:", err)
	}
	fails(t, v.run("get", id, "-o", hl))
	ok(t, v.run("get", id, "-o", hl, "--force"))
	if string(mustRead(t, hl)) != "data" {
		t.Fatal("hard link not replaced")
	}
	if after := snapshotTree(t, v.dir); after[filepath.Join(v.dir, "vault.json")] != before[filepath.Join(v.dir, "vault.json")] {
		t.Fatal("vault.json changed through a hard link")
	}
	// Ordinary outputs still work, including through a symlinked directory
	// that points outside the vault.
	os.Symlink(out, filepath.Join(v.work, "outlink"))
	ok(t, v.runIn(v.work, "get", id, "-o", "outlink/b.txt"))
	if string(mustRead(t, filepath.Join(out, "b.txt"))) != "data" {
		t.Fatal("content")
	}
}

// F2: a decoy object or a wrong key never hard-refuses: "cannot be
// verified", overridable; a vault where one object unwraps and another does
// not is verified with a note.
func TestF2RecoverDecoysAndWrongKeys(t *testing.T) {
	pass := "recovered passphrase\n"

	// Only a decoy (structurally valid, random wrapped_fk), right key.
	v := newVault(t)
	id := v.add("a.txt", []byte("data"))
	p := v.objectPath(id)
	data := mustRead(t, p)
	copy(data[34:82], randBytes(48))
	os.WriteFile(p, data, 0o600)
	os.Remove(filepath.Join(v.dir, "vault.json"))
	r := fails(t, ndes(t, v.recoveryKey+"\n"+pass, "recover", "--passphrase-stdin", v.dir))
	if !strings.Contains(r.stderr, "cannot be verified: 0 of 1 readable objects unwrap with this key; the key may be wrong or the objects damaged") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	r = ok(t, ndes(t, v.recoveryKey+"\n"+pass, "recover", "--passphrase-stdin", "--unverified-key", v.dir))
	if !strings.Contains(r.stdout, "NOT verified") || !strings.Contains(r.stdout, "ndes ls") {
		t.Fatalf("stdout: %s", r.stdout)
	}

	// One good object plus a bit-flipped one: verified, with a note.
	v2 := newVault(t)
	v2.add("good.txt", []byte("good"))
	bad := v2.add("bad.txt", []byte("bad"))
	p2 := v2.objectPath(bad)
	data2 := mustRead(t, p2)
	data2[40] ^= 1
	os.WriteFile(p2, data2, 0o600)
	os.Remove(filepath.Join(v2.dir, "vault.json"))
	r = ok(t, ndes(t, v2.recoveryKey+"\n"+pass, "recover", "--passphrase-stdin", v2.dir))
	if !strings.Contains(r.stderr, "1 of 2 objects do not unwrap with this key; run verify after recovery") ||
		!strings.Contains(r.stdout, "verified against an object") {
		t.Fatalf("stdout %s stderr %s", r.stdout, r.stderr)
	}

	// A wrong but valid key from another vault: refused without the flag.
	v3 := newVault(t)
	v3.add("a.txt", []byte("data"))
	other := newVault(t)
	os.Remove(filepath.Join(v3.dir, "vault.json"))
	r = fails(t, ndes(t, other.recoveryKey+"\n"+pass, "recover", "--passphrase-stdin", v3.dir))
	if !strings.Contains(r.stderr, "cannot be verified") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	notExist(t, filepath.Join(v3.dir, "vault.json"))
}

// F1: init and recover write through directory handles too: an init target
// reached through ".." after a symlink is created where the OS resolves it.
func TestF1InitResolvesPhysically(t *testing.T) {
	tmp := t.TempDir()
	os.MkdirAll(filepath.Join(tmp, "a", "b"), 0o700)
	os.Mkdir(filepath.Join(tmp, "c"), 0o700)
	os.Symlink(filepath.Join(tmp, "a", "b"), filepath.Join(tmp, "c", "lnk")) // c/lnk -> a/b
	ok(t, ndesIn(t, pw, []runOpt{inDir(tmp)}, "init", "--passphrase-stdin", "c/lnk/../newvault"))
	// Physically, c/lnk/.. is a/, so the vault is a/newvault, not c/newvault.
	if _, err := os.Stat(filepath.Join(tmp, "a", "newvault", "vault.json")); err != nil {
		t.Fatal(err)
	}
	notExist(t, filepath.Join(tmp, "c", "newvault"))
}
