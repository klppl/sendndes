package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/klppl/valv/core"
)

type handlerRoundTripper struct {
	h http.Handler
}

func (rt handlerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rt.h.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func withPullHandler(t *testing.T, h http.Handler) string {
	t.Helper()
	prev := pullTestTransport
	pullTestTransport = handlerRoundTripper{h: h}
	t.Cleanup(func() { pullTestTransport = prev })
	return "http://127.0.0.1:8485"
}

func runInProcess(args []string, stdin string) (int, string, string) {
	var out, errb bytes.Buffer
	a := &app{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, term: osTerminal{in: strings.NewReader(stdin), prompt: &errb}}
	code := a.run(args)
	return code, out.String(), errb.String()
}

func setupPullVault(t *testing.T, pass string) (vaultDir string, keys *core.VaultKeys, tokenFile string, token string) {
	t.Helper()
	tmp := t.TempDir()
	vaultDir = filepath.Join(tmp, "vault")
	code, _, stderr := runInProcess([]string{"init", vaultDir, "--passphrase-stdin", "--allow-weak-passphrase"}, pass+"\n")
	if code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}
	cfgBytes, err := os.ReadFile(filepath.Join(vaultDir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := core.ParseConfig(cfgBytes)
	if err != nil {
		t.Fatal(err)
	}
	keys, err = core.Unlock(cfg, pass)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { keys.Wipe() })

	token = "0123456789abcdef0123456789abcdef-pull-token"
	tokenFile = filepath.Join(tmp, "token.secret")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return vaultDir, keys, tokenFile, token
}

type mockInboxServer struct {
	mu      sync.Mutex
	token   string
	files   map[string][]byte
	deleted map[string]int
}

func newMockInboxServer(token string) *mockInboxServer {
	return &mockInboxServer{
		token:   token,
		files:   make(map[string][]byte),
		deleted: make(map[string]int),
	}
}

func (m *mockInboxServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+m.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.URL.Path == "/inbox" && r.Method == http.MethodGet {
		ids := make([]string, 0, len(m.files))
		for id := range m.files {
			ids = append(ids, id)
		}
		_ = json.NewEncoder(w).Encode(map[string][]string{"ids": ids})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/inbox/") {
		id := strings.TrimPrefix(r.URL.Path, "/inbox/")
		switch r.Method {
		case http.MethodGet:
			data, ok := m.files[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		case http.MethodDelete:
			m.deleted[id]++
			delete(m.files, id)
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

// TestPullEndToEndAndIdempotency tests valv pull for a normal sealed file, an
// empty 0-byte sealed file (D-R2 #3), stale .valv-*.part cleanup in
// <vault>/inbox/ (D-R2 #4), and idempotency when a valid file is re-pulled.
func TestPullEndToEndAndIdempotency(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, keys, tokenFile, token := setupPullVault(t, pass)

	mock := newMockInboxServer(token)
	srvURL := withPullHandler(t, mock)

	// Seal 1: empty file (0 bytes, D-R2 #3).
	var emptyInb bytes.Buffer
	emptyID, err := core.SealInbox(&emptyInb, keys.InboxPub, keys.InboxAuth, core.Metadata{
		Name:  "empty.txt",
		Dir:   "",
		MTime: 100,
		MIME:  "text/plain",
	}, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	mock.files[emptyID.String()] = emptyInb.Bytes()

	// Seal 2: multi-chunk file.
	multiPlain := bytes.Repeat([]byte("pull-payload-"), 6000)
	var multiInb bytes.Buffer
	multiID, err := core.SealInbox(&multiInb, keys.InboxPub, keys.InboxAuth, core.Metadata{
		Name:  "report.bin",
		Dir:   "docs/2026",
		MTime: 200,
		MIME:  "application/octet-stream",
	}, bytes.NewReader(multiPlain))
	if err != nil {
		t.Fatal(err)
	}
	mock.files[multiID.String()] = multiInb.Bytes()

	// Plant a stale .valv-*.part file inside <vault>/inbox/ to verify D-R2 #4 cleanup.
	stalePart := filepath.Join(vaultDir, "inbox", ".valv-0123456789abcdef.part")
	if err := os.WriteFile(stalePart, []byte("stale partial download"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Run valv pull.
	code, stdout, stderr := runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", srvURL, "--token-file", tokenFile, "--passphrase-stdin",
	}, pass+"\n")
	if code != 0 {
		t.Fatalf("pull failed (code %d): stdout=%s stderr=%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "ingested 2, already ingested 0, failed 0") {
		t.Fatalf("unexpected stdout: %s", stdout)
	}

	// Stale .part file in <vault>/inbox/ must be cleaned up (D-R2 #4).
	if _, err := os.Lstat(stalePart); !os.IsNotExist(err) {
		t.Fatal("valv pull did not clean up stale .valv-*.part in <vault>/inbox/")
	}

	// Both files must have been deleted from the server after verified ingest.
	if mock.deleted[emptyID.String()] != 1 || mock.deleted[multiID.String()] != 1 {
		t.Fatalf("expected both files deleted once, got %v", mock.deleted)
	}

	// Verify the vault with valv verify and extract both files with valv get.
	code, _, stderr = runInProcess([]string{"verify", "--vault", vaultDir, "--passphrase-stdin"}, pass+"\n")
	if code != 0 {
		t.Fatalf("verify failed: %s", stderr)
	}

	code, gotEmpty, stderr := runInProcess([]string{"get", emptyID.String(), "-o", "-", "--unverified-stream", "--vault", vaultDir, "--passphrase-stdin"}, pass+"\n")
	if code != 0 {
		t.Fatalf("get empty failed: %s", stderr)
	}
	if len(gotEmpty) != 0 {
		t.Fatalf("expected 0 bytes, got %d", len(gotEmpty))
	}

	code, gotMulti, stderr := runInProcess([]string{"get", "docs/2026/report.bin", "-o", "-", "--unverified-stream", "--vault", vaultDir, "--passphrase-stdin"}, pass+"\n")
	if code != 0 {
		t.Fatalf("get multi failed: %s", stderr)
	}
	if !bytes.Equal([]byte(gotMulti), multiPlain) {
		t.Fatal("extracted multi-chunk content differs")
	}

	// Replay multiInb on the server (simulating a lost DELETE) and pull again:
	// must report "already ingested 1" and issue DELETE on the server.
	mock.files[multiID.String()] = multiInb.Bytes()
	code, stdout, stderr = runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", srvURL, "--token-file", tokenFile, "--passphrase-stdin",
	}, pass+"\n")
	if code != 0 || !strings.Contains(stdout, "ingested 0, already ingested 1, failed 0") {
		t.Fatalf("replay pull: code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if mock.deleted[multiID.String()] != 2 {
		t.Fatalf("replay did not delete from server: count=%d", mock.deleted[multiID.String()])
	}
}

// TestPullHostileServerNeverDeletesOnFailure verifies that unauthenticated,
// tampered, mismatched-id, or Q4-corrupted-replay .inb files served by a
// hostile server are NEVER deleted from the server and never overwrite objects.
func TestPullHostileServerNeverDeletesOnFailure(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, keys, tokenFile, token := setupPullVault(t, pass)

	mock := newMockInboxServer(token)
	srvURL := withPullHandler(t, mock)

	// 1. Forged .inb sealed with wrong K_auth.
	var wrongKAuth [core.KeySize]byte
	wrongKAuth[0] = 0xff
	var forgedInb bytes.Buffer
	forgedID, err := core.SealInbox(&forgedInb, keys.InboxPub, wrongKAuth, core.Metadata{Name: "forged.txt", MTime: 1}, strings.NewReader("forged"))
	if err != nil {
		t.Fatal(err)
	}
	mock.files[forgedID.String()] = forgedInb.Bytes()

	// 2. Valid header, tampered chunk 1 byte.
	var tamperedInb bytes.Buffer
	tamperedID, err := core.SealInbox(&tamperedInb, keys.InboxPub, keys.InboxAuth, core.Metadata{Name: "tampered.bin", MTime: 1}, bytes.NewReader(bytes.Repeat([]byte("z"), core.ChunkSize+100)))
	if err != nil {
		t.Fatal(err)
	}
	tamperedBytes := bytes.Clone(tamperedInb.Bytes())
	tamperedBytes[len(tamperedBytes)-1] ^= 1
	mock.files[tamperedID.String()] = tamperedBytes

	// 3. Q4 ruling: An object already exists in the vault, and the server serves
	// a corrupted/unauthenticated .inb with that same file_id.
	// First, ingest a genuine inbox file into the vault so objects/<xx>/<q4ID>.obj exists.
	var genuineInb bytes.Buffer
	q4ID, err := core.SealInbox(&genuineInb, keys.InboxPub, keys.InboxAuth, core.Metadata{Name: "q4.txt", MTime: 1}, strings.NewReader("genuine-q4"))
	if err != nil {
		t.Fatal(err)
	}
	mock.files[q4ID.String()] = genuineInb.Bytes()
	code, _, stderr := runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", srvURL, "--token-file", tokenFile, "--passphrase-stdin",
	}, pass+"\n")
	// Only q4ID should succeed; forgedID and tamperedID must fail.
	if code == 0 {
		t.Fatal("expected non-zero exit when forged and tampered files fail")
	}
	if mock.deleted[q4ID.String()] != 1 {
		t.Fatalf("genuine q4 file was not ingested and deleted: %v (stderr: %s)", mock.deleted, stderr)
	}
	if mock.deleted[forgedID.String()] != 0 || mock.deleted[tamperedID.String()] != 0 {
		t.Fatalf("hostile files were deleted from server: %v", mock.deleted)
	}
	// Clean up the kept local failed inbox files before testing Q4 replay.
	_ = os.Remove(filepath.Join(vaultDir, "inbox", forgedID.String()+".inb"))
	_ = os.Remove(filepath.Join(vaultDir, "inbox", tamperedID.String()+".inb"))
	delete(mock.files, forgedID.String())
	delete(mock.files, tamperedID.String())

	// Now serve a corrupted version of q4ID on the server while objects/<xx>/<q4ID>.obj already exists.
	corruptQ4 := bytes.Clone(genuineInb.Bytes())
	corruptQ4[len(corruptQ4)-1] ^= 1 // corrupt chunk tag
	mock.files[q4ID.String()] = corruptQ4

	code, stdout, stderr := runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", srvURL, "--token-file", tokenFile, "--passphrase-stdin",
	}, pass+"\n")
	if code == 0 || !strings.Contains(stdout, "already ingested 0, failed 1") {
		t.Fatalf("Q4 corrupt replay was accepted as already ingested! code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if mock.deleted[q4ID.String()] != 1 {
		t.Fatalf("Q4 corrupt replay triggered DELETE on server (count=%d)", mock.deleted[q4ID.String()])
	}
	// And the local corrupt .inb in <vault>/inbox/ must have been kept (SPEC 6.3 Q4).
	if _, err := os.Stat(filepath.Join(vaultDir, "inbox", q4ID.String()+".inb")); err != nil {
		t.Fatalf("Q4 corrupt inbox file was not kept locally: %v", err)
	}
}

// TestPullTransportAndTokenGuards checks that redirects are not followed,
// non-loopback plain HTTP is refused without --allow-insecure-http, and
// overly permissive token files (0644) are refused.
func TestPullTransportAndTokenGuards(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, _, tokenFile, _ := setupPullVault(t, pass)

	// 1. Plain HTTP to external IP refused without --allow-insecure-http.
	code, _, stderr := runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", "http://93.184.216.34:8485", "--token-file", tokenFile, "--passphrase-stdin",
	}, pass+"\n")
	if code == 0 || !strings.Contains(stderr, "refusing plain HTTP") {
		t.Fatalf("plain HTTP to public IP accepted: code=%d stderr=%s", code, stderr)
	}

	// 2. Redirect (302) must not be followed and must fail.
	leakedAuth := false
	srvURL := withPullHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/evil" {
			if r.Header.Get("Authorization") != "" {
				leakedAuth = true
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "http://127.0.0.1:8485/evil", http.StatusFound)
	}))

	code, _, _ = runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", srvURL, "--token-file", tokenFile, "--passphrase-stdin",
	}, pass+"\n")
	if code == 0 || leakedAuth {
		t.Fatalf("redirect followed or leaked Authorization header (code=%d leaked=%v)", code, leakedAuth)
	}

	// 3. Token file with 0644 permissions must be refused.
	badTokFile := filepath.Join(t.TempDir(), "open.tok")
	_ = os.WriteFile(badTokFile, []byte("0123456789abcdef0123456789abcdef\n"), 0o644)
	code, _, stderr = runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", srvURL, "--token-file", badTokFile, "--passphrase-stdin",
	}, pass+"\n")
	if code == 0 || !strings.Contains(stderr, "permissions") {
		t.Fatalf("0644 token file accepted: code=%d stderr=%s", code, stderr)
	}
}
