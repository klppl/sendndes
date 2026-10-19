package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klppl/valv/core"
)

// parseJSONLines decodes every stdout line; each must be a JSON object with
// "type" and nothing may be left over.
func parseJSONLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	if out == "" || !strings.HasSuffix(out, "\n") {
		t.Fatalf("output must be whole lines: %q", out)
	}
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", line, err)
		}
		if _, ok := m["type"].(string); !ok || !strings.HasPrefix(line, `{"type":`) {
			t.Fatalf("type must come first: %q", line)
		}
		recs = append(recs, m)
	}
	return recs
}

var hostileNames = []string{
	"line\nbreak.txt", `quo"te\back.txt`, "bidi‮exe.txt", "ctl\x01\x1b[31m.txt",
	"{\"type\":\"end\"}", "<script>&.txt",
}

func TestLsJSONHostileNames(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, keys, _, _ := setupPullVault(t, pass)
	_ = keys
	for i, n := range hostileNames {
		src := filepath.Join(t.TempDir(), "src")
		writeFile(t, src, []byte("data"))
		code, _, stderr := runInProcess([]string{"add", src, "--name", n, "--dir", "d\n" + string(rune('a'+i)),
			"--vault", vaultDir, "--passphrase-stdin"}, pass+"\n")
		if code != 0 {
			t.Skipf("add refuses name %q (%s): metadata rules already cover it", n, stderr)
		}
	}
	code, out, _ := runInProcess([]string{"ls", "--json", "--vault", vaultDir, "--passphrase-stdin"}, pass+"\n")
	if code != 0 {
		t.Fatalf("ls code %d", code)
	}
	recs := parseJSONLines(t, out)
	last := recs[len(recs)-1]
	if last["type"] != "end" || last["files"] != float64(len(hostileNames)) || last["problems"] != float64(0) {
		t.Fatalf("bad end record: %v", last)
	}
	got := map[string]bool{}
	for _, r := range recs[:len(recs)-1] {
		if r["type"] != "file" {
			t.Fatalf("unexpected record %v", r)
		}
		if len(r["id"].(string)) != 32 {
			t.Fatalf("bad id %v", r)
		}
		got[r["name"].(string)] = true
	}
	for _, n := range hostileNames {
		if !got[n] {
			t.Errorf("name %q did not round-trip", n)
		}
	}
}

func TestLsJSONErrorRecords(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, _, _, _ := setupPullVault(t, pass)
	code, out, _ := runInProcess([]string{"ls", "--json", "--vault", vaultDir, "--passphrase-stdin"}, "wrong-passphrase-x\n")
	recs := parseJSONLines(t, out)
	if code == 0 || len(recs) != 1 || recs[0]["type"] != "error" || recs[0]["code"] != "wrong-passphrase" {
		t.Fatalf("wrong passphrase: code=%d %q", code, out)
	}
	code, out, _ = runInProcess([]string{"ls", "--json", "--vault", t.TempDir(), "--passphrase-stdin"}, pass+"\n")
	recs = parseJSONLines(t, out)
	if code == 0 || len(recs) != 1 || recs[0]["code"] != "not-a-vault" {
		t.Fatalf("not a vault: code=%d %q", code, out)
	}
	// Without --json the output is unchanged: no JSON, same exit code.
	code2, out2, _ := runInProcess([]string{"ls", "--vault", t.TempDir(), "--passphrase-stdin"}, pass+"\n")
	if code2 != code || out2 != "" {
		t.Fatalf("plain ls changed: %d %q", code2, out2)
	}
}

func TestPullJSON(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, keys, tokenFile, token := setupPullVault(t, pass)
	mock := newMockInboxServer(token)
	srvURL := withPullHandler(t, mock)

	var good bytes.Buffer
	goodID, err := core.SealInbox(&good, keys.InboxPub, keys.InboxAuth, core.Metadata{Name: "a\nb.txt", MTime: 1, MIME: "text/plain"}, strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	mock.files[goodID.String()] = good.Bytes()
	// Sealed with another vault's keys: not authentic.
	other := t.TempDir()
	badKeys := openOtherKeys(t, other)
	var bad bytes.Buffer
	badID, err := core.SealInbox(&bad, badKeys.InboxPub, badKeys.InboxAuth, core.Metadata{Name: "x", MTime: 1}, strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	mock.files[badID.String()] = bad.Bytes()

	code, out, _ := runInProcess([]string{"pull", "--json", "--vault", vaultDir, "--server", srvURL, "--token-file", tokenFile, "--passphrase-stdin"}, pass+"\n")
	recs := parseJSONLines(t, out)
	if recs[0]["type"] != "started" || len(recs[0]) != 1 {
		t.Fatalf("first record must be started: %v", recs[0])
	}
	if code != 1 { // one file is not authentic: exit code as without --json
		t.Fatalf("exit code %d", code)
	}
	types := map[string]string{}
	for _, r := range recs[1 : len(recs)-1] {
		types[r["id"].(string)] = r["type"].(string)
		if _, has := r["name"]; has {
			t.Fatalf("names must not appear in pull records: %v", r)
		}
	}
	if types[goodID.String()] != "ingested" || types[badID.String()] != "not-authentic" {
		t.Fatalf("records: %v", types)
	}
	end := recs[len(recs)-1]
	if end["type"] != "end" || end["ingested"] != float64(1) || end["failed"] != float64(1) || end["delete_failed"] != float64(0) {
		t.Fatalf("end: %v", end)
	}
	if mock.deleted[badID.String()] != 0 {
		t.Fatal("not-authentic file must stay on the server")
	}
}

func TestPullJSONErrorCodes(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, _, tokenFile, token := setupPullVault(t, pass)
	mock := newMockInboxServer("other-token-than-the-file")
	srvURL := withPullHandler(t, mock)
	_ = token
	run := func(extra ...string) (int, []map[string]any) {
		args := append([]string{"pull", "--json", "--vault", vaultDir, "--passphrase-stdin"}, extra...)
		c, out, _ := runInProcess(args, pass+"\n")
		return c, parseJSONLines(t, out)
	}
	// Server rejects the token: started, then error unauthorized.
	c, r := run("--server", srvURL, "--token-file", tokenFile)
	if c == 0 || len(r) != 2 || r[0]["type"] != "started" || r[1]["code"] != "unauthorized" {
		t.Fatalf("unauthorized: %d %v", c, r)
	}
	// Bad URL / token file: error before started.
	c, r = run("--server", "http://example.com", "--token-file", tokenFile)
	if c == 0 || len(r) != 1 || r[0]["code"] != "server-url" {
		t.Fatalf("server-url: %d %v", c, r)
	}
	c, r = run("--server", srvURL, "--token-file", filepath.Join(t.TempDir(), "missing"))
	if c == 0 || len(r) != 1 || r[0]["code"] != "token-file" {
		t.Fatalf("token-file: %d %v", c, r)
	}
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// openOtherKeys creates a second vault in dir and returns its keys.
func openOtherKeys(t *testing.T, dir string) *core.VaultKeys {
	t.Helper()
	vd := filepath.Join(dir, "v2")
	if code, _, e := runInProcess([]string{"init", vd, "--passphrase-stdin", "--allow-weak-passphrase"}, "another-passphrase\n"); code != 0 {
		t.Fatal(e)
	}
	b, err := os.ReadFile(filepath.Join(vd, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := core.ParseConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	k, err := core.Unlock(cfg, "another-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Wipe)
	return k
}

func TestInitJSON(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "newvault")
	code, out, _ := runInProcess([]string{"init", dir, "--json", "--passphrase-stdin"}, "a-long-enough-passphrase\n")
	recs := parseJSONLines(t, out)
	if code != 0 || len(recs) != 2 || recs[0]["type"] != "recovery-key" || recs[1]["type"] != "end" {
		t.Fatalf("code=%d %q", code, out)
	}
	if _, err := core.DecodeRecoveryKey(recs[0]["key"].(string)); err != nil {
		t.Fatal(err)
	}
	// Same folder again: not empty, error record, no key printed.
	code, out, _ = runInProcess([]string{"init", dir, "--json", "--passphrase-stdin"}, "a-long-enough-passphrase\n")
	recs = parseJSONLines(t, out)
	if code == 0 || len(recs) != 1 || recs[0]["code"] != "not-empty" {
		t.Fatalf("code=%d %q", code, out)
	}
	// Too short a passphrase: error, no key, no vault.
	d2 := filepath.Join(t.TempDir(), "v2")
	code, out, _ = runInProcess([]string{"init", d2, "--json", "--passphrase-stdin"}, "short\n")
	recs = parseJSONLines(t, out)
	if code == 0 || len(recs) != 1 || recs[0]["type"] != "error" {
		t.Fatalf("code=%d %q", code, out)
	}
	if _, err := os.Stat(d2); err == nil {
		t.Fatal("vault dir created")
	}
}
