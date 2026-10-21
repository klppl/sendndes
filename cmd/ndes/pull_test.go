package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klppl/sendndes/core"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

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

// TestPullEndToEndAndIdempotency tests ndes pull for a normal sealed file, an
// empty 0-byte sealed file (D-R2 #3), stale .ndes-*.part cleanup in
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

	// Plant a stale .ndes-*.part file inside <vault>/inbox/ to verify D-R2 #4 cleanup.
	stalePart := filepath.Join(vaultDir, "inbox", ".ndes-0123456789abcdef.part")
	if err := os.WriteFile(stalePart, []byte("stale partial download"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(stalePart, old, old); err != nil { // L10: only old leftovers are removed
		t.Fatal(err)
	}

	// Run ndes pull.
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
		t.Fatal("ndes pull did not clean up stale .ndes-*.part in <vault>/inbox/")
	}

	// Both files must have been deleted from the server after verified ingest.
	if mock.deleted[emptyID.String()] != 1 || mock.deleted[multiID.String()] != 1 {
		t.Fatalf("expected both files deleted once, got %v", mock.deleted)
	}

	// Verify the vault with ndes verify and extract both files with ndes get.
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
	for _, id := range []core.FileID{forgedID, tamperedID} {
		if _, err := os.Lstat(filepath.Join(vaultDir, "inbox", id.String()+".inb")); err == nil {
			t.Fatalf("unauthentic download %s was stored in <vault>/inbox/", id)
		}
	}
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
	// M2: the corrupt download is never stored in the vault; it stays on the server.
	if _, err := os.Lstat(filepath.Join(vaultDir, "inbox", q4ID.String()+".inb")); err == nil {
		t.Fatal("corrupt download was stored in <vault>/inbox/")
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

// TestPullOversizedAndStallingDownloads verifies VALV-REV2-01 (rejecting
// oversized downloads both with known Content-Length and with chunked
// ContentLength == -1) and VALV-REV2-02 (aborting downloads whose body stalls
// past --io-timeout), ensuring no leftover .part or .inb files remain and
// DELETE is never called.
func TestPullOversizedAndStallingDownloads(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, _, tokenFile, _ := setupPullVault(t, pass)

	const (
		bigKnownID   = "11111111111111111111111111111111"
		bigChunkedID = "22222222222222222222222222222222"
		stallID      = "33333333333333333333333333333333"
	)

	assertInboxEmpty := func(t *testing.T) {
		t.Helper()
		entries, err := os.ReadDir(filepath.Join(vaultDir, "inbox"))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("expected <vault>/inbox/ to have 0 files, found: %v", names)
		}
	}

	// 1. VALV-REV2-01 (known Content-Length > --max-download-bytes).
	t.Run("oversized known Content-Length", func(t *testing.T) {
		deleteCalls := 0
		prev := pullTestTransport
		pullTestTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/inbox":
				body := `{"ids":["` + bigKnownID + `"]}`
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: int64(len(body)),
					Body:          io.NopCloser(strings.NewReader(body)),
					Header:        make(http.Header),
				}, nil
			case req.Method == http.MethodGet && req.URL.Path == "/inbox/"+bigKnownID:
				payload := bytes.Repeat([]byte("A"), 2048)
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: int64(len(payload)),
					Body:          io.NopCloser(bytes.NewReader(payload)),
					Header:        make(http.Header),
				}, nil
			case req.Method == http.MethodDelete:
				deleteCalls++
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
				return nil, nil
			}
		})
		defer func() { pullTestTransport = prev }()

		code, stdout, stderr := runInProcess([]string{
			"pull", "--vault", vaultDir, "--server", "http://127.0.0.1:8485",
			"--token-file", tokenFile, "--max-download-bytes", "1024", "--passphrase-stdin",
		}, pass+"\n")
		if code == 0 || !strings.Contains(stderr, "exceeds maximum download size") {
			t.Fatalf("expected oversized download error, got code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if deleteCalls != 0 {
			t.Fatalf("DELETE called %d times on oversized download", deleteCalls)
		}
		assertInboxEmpty(t)
	})

	// 2. VALV-REV2-01 (chunked stream with ContentLength == -1 exceeding --max-download-bytes).
	t.Run("oversized chunked stream (ContentLength -1)", func(t *testing.T) {
		deleteCalls := 0
		prev := pullTestTransport
		pullTestTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/inbox":
				body := `{"ids":["` + bigChunkedID + `"]}`
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: int64(len(body)),
					Body:          io.NopCloser(strings.NewReader(body)),
					Header:        make(http.Header),
				}, nil
			case req.Method == http.MethodGet && req.URL.Path == "/inbox/"+bigChunkedID:
				payload := bytes.Repeat([]byte("B"), 8192)
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: -1, // chunked / unknown length
					Body:          io.NopCloser(bytes.NewReader(payload)),
					Header:        make(http.Header),
				}, nil
			case req.Method == http.MethodDelete:
				deleteCalls++
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
				return nil, nil
			}
		})
		defer func() { pullTestTransport = prev }()

		code, stdout, stderr := runInProcess([]string{
			"pull", "--vault", vaultDir, "--server", "http://127.0.0.1:8485",
			"--token-file", tokenFile, "--max-download-bytes", "1024", "--passphrase-stdin",
		}, pass+"\n")
		if code == 0 || !strings.Contains(stderr, "exceeds maximum download size") {
			t.Fatalf("expected chunked oversized download error, got code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if deleteCalls != 0 {
			t.Fatalf("DELETE called %d times on chunked oversized download", deleteCalls)
		}
		assertInboxEmpty(t)
	})

	// 3. VALV-REV2-02 (hostile server sends 200 OK, writes 64 bytes, then stalls past --io-timeout).
	t.Run("stalling download body past io-timeout", func(t *testing.T) {
		deleteCalls := 0
		pr, pw := io.Pipe()
		defer pw.Close()

		prev := pullTestTransport
		pullTestTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.Method == http.MethodGet && req.URL.Path == "/inbox":
				body := `{"ids":["` + stallID + `"]}`
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: int64(len(body)),
					Body:          io.NopCloser(strings.NewReader(body)),
					Header:        make(http.Header),
				}, nil
			case req.Method == http.MethodGet && req.URL.Path == "/inbox/"+stallID:
				go func() {
					_, _ = pw.Write(bytes.Repeat([]byte("C"), 64))
					// Stall without closing pw; pullProgressReader must time out and close pr.
				}()
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: 10000,
					Body:          pr,
					Header:        make(http.Header),
				}, nil
			case req.Method == http.MethodDelete:
				deleteCalls++
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			default:
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
				return nil, nil
			}
		})
		defer func() { pullTestTransport = prev }()

		start := time.Now()
		code, stdout, stderr := runInProcess([]string{
			"pull", "--vault", vaultDir, "--server", "http://127.0.0.1:8485",
			"--token-file", tokenFile, "--io-timeout", "120ms", "--passphrase-stdin",
		}, pass+"\n")
		elapsed := time.Since(start)
		if code == 0 || !strings.Contains(stderr, "timed out") {
			t.Fatalf("expected timeout error on stalling download, got code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("stalling download took too long to time out: %v", elapsed)
		}
		if deleteCalls != 0 {
			t.Fatalf("DELETE called %d times on stalling download", deleteCalls)
		}
		assertInboxEmpty(t)
	})
}

// vaultSnapshot returns every path under dir with its size and content hash.
func vaultSnapshot(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			sb.WriteString("d " + rel + "\n")
			return nil
		}
		b, _ := os.ReadFile(p)
		sb.WriteString(fmt.Sprintf("f %s %d %x\n", rel, len(b), sha256.Sum256(b)))
		return nil
	})
	return sb.String()
}

// TestPullRogueServerLeavesVaultUntouched is the M2 audit PoC: a server that
// returns random bytes for every id must leave the vault byte-identical, with
// nothing in inbox/, and the scratch directory must be gone afterwards.
func TestPullRogueServerLeavesVaultUntouched(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, _, tokenFile, token := setupPullVault(t, pass)
	mock := newMockInboxServer(token)
	for i := 0; i < 5; i++ {
		var id [16]byte
		rand.Read(id[:])
		junk := make([]byte, 5000)
		rand.Read(junk)
		mock.files[hex.EncodeToString(id[:])] = junk
	}
	srvURL := withPullHandler(t, mock)
	scratchBase := t.TempDir()
	t.Setenv("TMPDIR", scratchBase)
	before := vaultSnapshot(t, vaultDir)
	code, _, stderr := runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", srvURL, "--token-file", tokenFile, "--passphrase-stdin",
	}, pass+"\n")
	if code == 0 {
		t.Fatal("expected failure for junk files")
	}
	if !strings.Contains(stderr, "not authentic") {
		t.Fatalf("expected not-authentic reports: %s", stderr)
	}
	if after := vaultSnapshot(t, vaultDir); after != before {
		t.Fatalf("vault changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if len(mock.deleted) != 0 || len(mock.files) != 5 {
		t.Fatalf("junk must stay on the server: deleted=%v", mock.deleted)
	}
	if left, _ := os.ReadDir(scratchBase); len(left) != 0 {
		t.Fatalf("scratch directory not cleaned: %v", left)
	}
}

// TestPullTotalBytesCap: --max-total-bytes stops the run; nothing lands in the vault.
func TestPullTotalBytesCap(t *testing.T) {
	pass := "correct-horse-battery"
	vaultDir, _, tokenFile, token := setupPullVault(t, pass)
	mock := newMockInboxServer(token)
	for _, id := range []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"} {
		mock.files[id] = make([]byte, 600)
	}
	srvURL := withPullHandler(t, mock)
	before := vaultSnapshot(t, vaultDir)
	code, _, stderr := runInProcess([]string{
		"pull", "--vault", vaultDir, "--server", srvURL, "--token-file", tokenFile, "--passphrase-stdin", "--max-total-bytes", "1000",
	}, pass+"\n")
	if code == 0 || !strings.Contains(stderr, "max-total-bytes") {
		t.Fatalf("expected total cap error: code=%d %s", code, stderr)
	}
	if vaultSnapshot(t, vaultDir) != before {
		t.Fatal("vault changed")
	}
}

// H1: plain http to a Tailscale address must go through a Tailscale interface.
func TestPullRefusesTailscaleURLNotRoutedThroughTailscale(t *testing.T) {
	prev := routeInterfaceLookup
	defer func() { routeInterfaceLookup = prev }()
	cases := []struct {
		name  string
		iface string
		err   error
		extra string
		want  bool // route accepted
	}{
		{"default gateway", "en0", nil, "", false},
		{"utun", "utun4", nil, "", true},
		{"tailscale0", "tailscale0", nil, "", true},
		{"no interface", "", errors.New("none"), "", false},
		{"override list", "wg0", nil, "wg0", true},
		{"override does not match", "en0", nil, "wg0", false},
	}
	for _, c := range cases {
		routeInterfaceLookup = func(netip.Addr) (string, error) { return c.iface, c.err }
		err := checkTailscaleRoute("http://100.101.102.103:8485", splitList(c.extra))
		if (err == nil) != c.want {
			t.Errorf("%s: err=%v want accepted=%v", c.name, err, c.want)
		}
	}
	// Loopback and https never look up a route.
	routeInterfaceLookup = func(netip.Addr) (string, error) { t.Fatal("lookup called"); return "", nil }
	for _, u := range []string{"http://127.0.0.1:1", "https://100.101.102.103", "https://example.com"} {
		if err := checkTailscaleRoute(u, nil); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// The check runs at the start of a pull (nothing is requested) and again before every file.
func TestPullChecksRouteAtStartAndBeforeEachFile(t *testing.T) {
	prev := routeInterfaceLookup
	defer func() { routeInterfaceLookup = prev }()
	pass := "correct-horse-battery"
	vaultDir, keys, tokenFile, token := setupPullVault(t, pass)
	mock := newMockInboxServer(token)
	var ids []string
	for i := 0; i < 2; i++ {
		var b bytes.Buffer
		id, err := core.SealInbox(&b, keys.InboxPub, keys.InboxAuth, core.Metadata{Name: "f.txt", MTime: 1}, strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		mock.files[id.String()] = b.Bytes()
		ids = append(ids, id.String())
	}
	requests := 0
	counting := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return handlerRoundTripper{h: mock}.RoundTrip(r)
	})
	prevT := pullTestTransport
	pullTestTransport = counting
	defer func() { pullTestTransport = prevT }()
	args := []string{"pull", "--vault", vaultDir, "--server", "http://100.101.102.103:8485", "--token-file", tokenFile, "--passphrase-stdin"}

	// Start: the route is wrong, so no request is made.
	routeInterfaceLookup = func(netip.Addr) (string, error) { return "en0", nil }
	code, _, stderr := runInProcess(args, pass+"\n")
	if code == 0 || requests != 0 || !strings.Contains(stderr, "Tailscale") {
		t.Fatalf("code=%d requests=%d stderr=%s", code, requests, stderr)
	}

	// The route flips to en0 after the first file: the second is not fetched or deleted.
	calls := 0
	routeInterfaceLookup = func(netip.Addr) (string, error) {
		calls++
		if calls <= 2 { // start + first file
			return "utun3", nil
		}
		return "en0", nil
	}
	code, _, stderr = runInProcess(args, pass+"\n")
	if code == 0 || !strings.Contains(stderr, "Tailscale") {
		t.Fatalf("expected route failure: code=%d %s", code, stderr)
	}
	if len(mock.deleted) != 1 || len(mock.files) != 1 {
		t.Fatalf("exactly one file should have been pulled: deleted=%v left=%d", mock.deleted, len(mock.files))
	}
	_ = ids
}

// decodeBytes turns \xNN escapes of the shared policy list into raw bytes.
func decodeBytes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s)+0 && s[i+1] == 'x' {
			v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
			if err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// L12: the server-address policy must agree with the Swift app's (same list on both sides).
func TestURLPolicyCases(t *testing.T) {
	data, err := os.ReadFile("../../app/Tests/AppCoreTests/url-policy-cases.tsv")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		in, want, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		in = decodeBytes(in)
		got, err := validatePullServerURL(in, false)
		if want == "REJECT" {
			if err == nil {
				t.Errorf("%q: accepted as %q, want REJECT", in, got)
			}
		} else if err != nil || got != want {
			t.Errorf("%q: got %q (%v), want %q", in, got, err, want)
		}
		n++
	}
	if n < 80 {
		t.Fatalf("only %d cases", n)
	}
}

// L4: the download client ignores HTTP_PROXY and friends.
func TestPullTransportIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	tr := newPullTransport(time.Second)
	if tr.Proxy != nil {
		t.Fatal("pull transport has a proxy function")
	}
}

// L10: stale-part cleanup removes only old, unlocked temp files, so two runs on the same inbox
// cannot delete each other's work.
func TestStaleCleanupSkipsLockedAndFreshParts(t *testing.T) {
	dir := t.TempDir()
	d, err := openDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	old := time.Now().Add(-time.Hour)
	mk := func(name string, age time.Time) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, age, age); err != nil {
			t.Fatal(err)
		}
	}
	mk(".ndes-aaaaaaaaaaaaaaaa.part", old)        // leftover: removed
	mk(".ndes-bbbbbbbbbbbbbbbb.part", time.Now()) // fresh: kept
	cleanStaleInboxParts(d)
	if _, err := os.Lstat(filepath.Join(dir, ".ndes-aaaaaaaaaaaaaaaa.part")); err == nil {
		t.Error("old unlocked part was not removed")
	}
	if _, err := os.Lstat(filepath.Join(dir, ".ndes-bbbbbbbbbbbbbbbb.part")); err != nil {
		t.Error("fresh part was removed")
	}

	// Run A is in the middle of a write (temp file open and locked, even if its mtime looks old);
	// run B starts and cleans up: A's file must survive and A must finish.
	entered := make(chan string)
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- writeAt(d, "final.inb", writeOpts{}, func(w io.Writer) error {
			entries, _ := d.list()
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".ndes-") && e.Name() != ".ndes-bbbbbbbbbbbbbbbb.part" {
					p := filepath.Join(dir, e.Name())
					os.Chtimes(p, old, old)
					entered <- e.Name()
				}
			}
			<-release
			_, err := w.Write([]byte("payload"))
			return err
		})
	}()
	live := <-entered
	d2, err := openDir(dir) // run B has its own handle
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	cleanStaleInboxParts(d2)
	if _, err := os.Lstat(filepath.Join(dir, live)); err != nil {
		t.Fatal("a locked temp file of a running write was deleted")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("the running write failed: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "final.inb")); err != nil || string(b) != "payload" {
		t.Fatalf("final file: %q %v", b, err)
	}
}
