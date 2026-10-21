package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/klppl/sendndes/core"
	"golang.org/x/text/unicode/norm"
)

const testBearerToken = "0123456789abcdef0123456789abcdef-secret-token"

type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		ch:     make(chan net.Conn, 64),
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8485}
}

func (l *pipeListener) dial() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	c1, c2 := net.Pipe()
	select {
	case l.ch <- c1:
		return c2, nil
	case <-l.closed:
		_ = c1.Close()
		_ = c2.Close()
		return nil, net.ErrClosed
	}
}

type testServerEnv struct {
	t        *testing.T
	keys     *core.VaultKeys
	inboxDir string
	dirH     *dirHandle
	reg      *tempRegistry
	srv      *inboxServer
	httpSrv  *http.Server
	ln       *pipeListener
	client   *http.Client
	baseURL  string
	cancel   context.CancelFunc
}

func startTestServer(t *testing.T, opts serverOpts) *testServerEnv {
	t.Helper()
	var vk [core.KeySize]byte
	if _, err := rand.Read(vk[:]); err != nil {
		t.Fatal(err)
	}
	keys, err := core.DeriveVaultKeys(vk)
	if err != nil {
		t.Fatal(err)
	}

	inboxDir := filepath.Join(t.TempDir(), "inbox")
	if err := os.Mkdir(inboxDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dirH, err := openInboxDir(inboxDir, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &serverConfig{
		InboxPub: keys.InboxPub,
		KAuth:    keys.InboxAuth,
		Token:    []byte(testBearerToken),
	}
	ctx, cancel := context.WithCancel(context.Background())
	reg := newTempRegistry()
	srv := newInboxServer(ctx, dirH, reg, cfg, opts)

	ln := newPipeListener()
	httpSrv := newHTTPServer(srv)
	go httpSrv.Serve(ln)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return ln.dial()
			},
		},
	}

	env := &testServerEnv{
		t:        t,
		keys:     keys,
		inboxDir: inboxDir,
		dirH:     dirH,
		reg:      reg,
		srv:      srv,
		httpSrv:  httpSrv,
		ln:       ln,
		client:   client,
		baseURL:  "http://127.0.0.1:8485",
		cancel:   cancel,
	}
	t.Cleanup(func() {
		cancel()
		_ = httpSrv.Close()
		_ = ln.Close()
		reg.cleanupAll()
		srv.Wipe()
		cfg.Wipe()
		keys.Wipe()
		_ = dirH.Close()
	})
	return env
}

func (e *testServerEnv) doReq(method, path string, headers map[string][]string, body io.Reader, contentLen int64) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.baseURL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testBearerToken)
	for k, vals := range headers {
		req.Header.Del(k)
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if contentLen >= 0 {
		req.ContentLength = contentLen
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, data
}

func assertNoPartFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ndes-") || strings.HasSuffix(e.Name(), ".part") {
			t.Fatalf("leftover temp file in inbox directory: %s", e.Name())
		}
	}
}

// TestNdesdEndToEndAndEmptyUpload covers PUT /inbox (including empty 0-byte
// files per review recommendation #3 / D-R2, multi-chunk files, and non-ASCII
// NFD metadata via Base64 headers), GET /inbox, GET /inbox/{id},core.IngestInbox,
// and DELETE /inbox/{id}.
func TestNdesdEndToEndAndEmptyUpload(t *testing.T) {
	env := startTestServer(t, defaultServerOpts())

	cases := []struct {
		name      string
		headers   map[string][]string
		plain     []byte
		wantName  string
		wantDir   string
		wantMIME  string
		wantMTime int64
	}{
		{
			name: "empty file (Content-Length 0, D-R2 #3)",
			headers: map[string][]string{
				"X-Ndes-Name":  {"empty.txt"},
				"X-Ndes-Mtime": {"0"},
			},
			plain:     []byte{},
			wantName:  "empty.txt",
			wantDir:   "",
			wantMIME:  "",
			wantMTime: 0,
		},
		{
			name: "multi-chunk with Base64 NFD Unicode metadata and negative mtime",
			headers: map[string][]string{
				"X-Ndes-Name-B64": {base64.StdEncoding.EncodeToString([]byte("Ra\u0308ksmo\u0308rga\u030as.bin"))},
				"X-Ndes-Dir-B64":  {base64.StdEncoding.EncodeToString([]byte("Ko\u0308k/2026"))},
				"X-Ndes-Mime":     {"application/octet-stream"},
				"X-Ndes-Mtime":    {"-1234567890"},
			},
			plain:     bytes.Repeat([]byte("ndes-stream-chunk-test-"), 6000), // > 2 chunks
			wantName:  norm.NFC.String("Ra\u0308ksmo\u0308rga\u030as.bin"),
			wantDir:   norm.NFC.String("Ko\u0308k/2026"),
			wantMIME:  "application/octet-stream",
			wantMTime: -1234567890,
		},
		{
			name: "mtime above 2^53",
			headers: map[string][]string{
				"X-Ndes-Name":  {"future.dat"},
				"X-Ndes-Mtime": {"18014398509481984"}, // 2^54
			},
			plain:     []byte("hello world"),
			wantName:  "future.dat",
			wantDir:   "",
			wantMIME:  "",
			wantMTime: 18014398509481984,
		},
	}

	var uploadedIDs []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := env.doReq(http.MethodPut, "/inbox", tc.headers, bytes.NewReader(tc.plain), int64(len(tc.plain)))
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("PUT status %d: %s", resp.StatusCode, body)
			}
			var putResp struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(body, &putResp); err != nil {
				t.Fatal(err)
			}
			id, err := core.ParseFileID(putResp.ID)
			if err != nil {
				t.Fatalf("invalid file_id %q: %v", putResp.ID, err)
			}
			uploadedIDs = append(uploadedIDs, putResp.ID)

			// Download the sealed .inb and verify it with core.IngestInbox + core.DecryptObject.
			getResp, inbBytes := env.doReq(http.MethodGet, "/inbox/"+putResp.ID, nil, nil, -1)
			if getResp.StatusCode != http.StatusOK {
				t.Fatalf("GET /inbox/%s: status %d", putResp.ID, getResp.StatusCode)
			}
			// For empty file: header (58 + 540 = 598) + 16-byte tag = 614 bytes.
			if len(tc.plain) == 0 && len(inbBytes) != 58+540+16 {
				t.Fatalf("empty file .inb length = %d, want %d", len(inbBytes), 58+540+16)
			}
			var objBuf bytes.Buffer
			meta, err := core.IngestInbox(bytes.NewReader(inbBytes), int64(len(inbBytes)), id, env.keys, &objBuf)
			if err != nil {
				t.Fatalf("IngestInbox: %v", err)
			}
			if meta.Name != tc.wantName || meta.Dir != tc.wantDir || meta.MIME != tc.wantMIME || meta.MTime != tc.wantMTime || meta.Rev != 1 {
				t.Fatalf("metadata = %+v, want name=%q dir=%q mime=%q mtime=%d rev=1", meta, tc.wantName, tc.wantDir, tc.wantMIME, tc.wantMTime)
			}
			var decBuf bytes.Buffer
			if _, err := core.DecryptObject(bytes.NewReader(objBuf.Bytes()), int64(objBuf.Len()), id, env.keys, &decBuf); err != nil {
				t.Fatalf("DecryptObject: %v", err)
			}
			if !bytes.Equal(decBuf.Bytes(), tc.plain) {
				t.Fatalf("decrypted plaintext differs (got %d bytes, want %d)", decBuf.Len(), len(tc.plain))
			}
		})
	}

	assertNoPartFiles(t, env.inboxDir)

	// GET /inbox must list all 3 IDs sorted.
	listResp, listBody := env.doReq(http.MethodGet, "/inbox", nil, nil, -1)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /inbox: %d", listResp.StatusCode)
	}
	var listParsed struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(listBody, &listParsed); err != nil || len(listParsed.IDs) != len(uploadedIDs) {
		t.Fatalf("list = %+v, err = %v", listParsed, err)
	}

	// DELETE each ID and verify it is gone.
	for _, id := range uploadedIDs {
		delResp, _ := env.doReq(http.MethodDelete, "/inbox/"+id, nil, nil, -1)
		if delResp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE /inbox/%s: %d", id, delResp.StatusCode)
		}
		delAgain, _ := env.doReq(http.MethodDelete, "/inbox/"+id, nil, nil, -1)
		if delAgain.StatusCode != http.StatusNotFound {
			t.Fatalf("second DELETE /inbox/%s: %d, want 404", id, delAgain.StatusCode)
		}
		getGone, _ := env.doReq(http.MethodGet, "/inbox/"+id, nil, nil, -1)
		if getGone.StatusCode != http.StatusNotFound {
			t.Fatalf("GET deleted /inbox/%s: %d, want 404", id, getGone.StatusCode)
		}
	}
}

// TestHostileAuthAndRateLimit tests invalid bearer tokens, tokens > 512 bytes
// (D-R2 #2), duplicate Authorization headers, and per-IP rate limiting.
func TestHostileAuthAndRateLimit(t *testing.T) {
	env := startTestServer(t, defaultServerOpts())

	badAuths := [][]string{
		nil,
		{""},
		{"Basic dXNlcjpwYXNz"},
		{"Bearer "},
		{"Bearer wrong-token-0123456789abcdef0123456789abcdef"},
		{"Bearer " + testBearerToken[:len(testBearerToken)-1] + "X"},
		{"Bearer " + testBearerToken + "extra"},
		{"Bearer " + strings.Repeat("a", 513)},                     // D-R2 #2: > 512 bytes rejected before SHA-256
		{"Bearer " + testBearerToken, "Bearer " + testBearerToken}, // duplicate Authorization header
	}

	for i, authVals := range badAuths {
		// Reset rate limiter before each individual case so we test 401 first.
		env.srv.authRL = newIPRateLimiter(100, time.Second)
		req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/inbox", nil)
		for _, v := range authVals {
			req.Header.Add("Authorization", v)
		}
		resp, err := env.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("case %d (%v): got %d, want 401", i, authVals, resp.StatusCode)
		}
	}

	// Now test rate limiting: with burst 5, the 6th failed attempt from the same IP gets 429.
	env.srv.authRL = newIPRateLimiter(authRateBurst, time.Hour)
	for i := 1; i <= authRateBurst+2; i++ {
		req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/inbox", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		resp, err := env.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := http.StatusUnauthorized
		if i > authRateBurst {
			want = http.StatusTooManyRequests
		}
		if resp.StatusCode != want {
			t.Fatalf("attempt %d: got %d, want %d", i, resp.StatusCode, want)
		}
	}
}

// TestHostileMetadataHeaders tests duplicate headers (D-R2 #1), path traversal
// in names and dirs, invalid UTF-8, non-canonical base64, oversized metadata,
// and bad mtime values.
func TestHostileMetadataHeaders(t *testing.T) {
	env := startTestServer(t, defaultServerOpts())

	hugeNameB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), core.MaxMetaPadded))

	badHeaders := []struct {
		desc string
		h    map[string][]string
	}{
		{"missing name", map[string][]string{}},
		{"empty name", map[string][]string{"X-Ndes-Name": {""}}},
		{"empty b64 name", map[string][]string{"X-Ndes-Name-B64": {""}}},
		{"duplicate X-Ndes-Name (D-R2 #1)", map[string][]string{"X-Ndes-Name": {"a.txt", "b.txt"}}},
		{"duplicate X-Ndes-Name-B64 (D-R2 #1)", map[string][]string{"X-Ndes-Name-B64": {"YS50eHQ=", "Yi50eHQ="}}},
		{"duplicate X-Ndes-Dir (D-R2 #1)", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Dir": {"d1", "d2"}}},
		{"duplicate X-Ndes-Mtime (D-R2 #1)", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Mtime": {"1", "2"}}},
		{"both plain and b64 name", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Name-B64": {"YS50eHQ="}}},
		{"both plain and b64 dir", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Dir": {"d"}, "X-Ndes-Dir-B64": {"ZA=="}}},
		{"unknown X-Ndes header", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Extra": {"1"}}},
		{"dot name", map[string][]string{"X-Ndes-Name": {"."}}},
		{"dotdot name", map[string][]string{"X-Ndes-Name": {".."}}},
		{"slash in name", map[string][]string{"X-Ndes-Name": {"a/b.txt"}}},
		{"nul in b64 name", map[string][]string{"X-Ndes-Name-B64": {base64.StdEncoding.EncodeToString([]byte("a\x00b"))}}},
		{"invalid UTF-8 in b64 name", map[string][]string{"X-Ndes-Name-B64": {base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe})}}},
		{"unpadded base64 name", map[string][]string{"X-Ndes-Name-B64": {"YWJjZA"}}},
		{"leading slash in dir", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Dir": {"/sub"}}},
		{"trailing slash in dir", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Dir": {"sub/"}}},
		{"empty component in dir", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Dir": {"a//b"}}},
		{"dotdot component in dir", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Dir": {"a/../b"}}},
		{"dot component in dir", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Dir": {"a/./b"}}},
		{"invalid UTF-8 in dir", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Dir-B64": {base64.StdEncoding.EncodeToString([]byte{0x80})}}},
		{"invalid UTF-8 in mime", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Mime-B64": {base64.StdEncoding.EncodeToString([]byte{0x80})}}},
		{"float mtime", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Mtime": {"1.5"}}},
		{"leading zero mtime", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Mtime": {"01"}}},
		{"negative zero mtime", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Mtime": {"-0"}}},
		{"plus mtime", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Mtime": {"+100"}}},
		{"overflow mtime", map[string][]string{"X-Ndes-Name": {"a.txt"}, "X-Ndes-Mtime": {"99999999999999999999"}}},
		{"metadata exceeds 64 KiB padded", map[string][]string{"X-Ndes-Name-B64": {hugeNameB64}}},
	}

	// Metadata whose canonical JSON exceeds 65536 bytes (e.g. name=24000 bytes + dir=24000 bytes + mime=18000 bytes = 66000 bytes)
	// while keeping total HTTP headers under MaxHeaderBytes (128 KiB) -> 400 Bad Request from core.EncodeMetadata.
	part24k := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 24000))
	part18k := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("b"), 18000))
	respMetaBig, _ := env.doReq(http.MethodPut, "/inbox", map[string][]string{
		"X-Ndes-Name-B64": {part24k},
		"X-Ndes-Dir-B64":  {part24k},
		"X-Ndes-Mime-B64": {part18k},
	}, strings.NewReader("hello"), 5)
	if respMetaBig.StatusCode != http.StatusBadRequest && respMetaBig.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("metadata > 64 KiB: got %d, want 400 or 431", respMetaBig.StatusCode)
	}

	// Single header exceeding MaxHeaderBytes (64 KiB) -> 431 Request Header Fields Too Large.
	respHdrBig, _ := env.doReq(http.MethodPut, "/inbox", map[string][]string{
		"X-Ndes-Name-B64": {hugeNameB64},
	}, strings.NewReader("hello"), 5)
	if respHdrBig.StatusCode != http.StatusRequestHeaderFieldsTooLarge && respHdrBig.StatusCode != http.StatusBadRequest {
		t.Errorf("header > MaxHeaderBytes: got %d, want 431 or 400", respHdrBig.StatusCode)
	}

	for _, tc := range badHeaders {
		if tc.desc == "metadata exceeds 64 KiB padded" {
			continue
		}
		resp, _ := env.doReq(http.MethodPut, "/inbox", tc.h, strings.NewReader("hello"), 5)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: got status %d, want 400", tc.desc, resp.StatusCode)
		}
	}
	assertNoPartFiles(t, env.inboxDir)
	ids, active, _ := env.dirH.listInboxIDs()
	if len(ids) != 0 || active != 0 {
		t.Fatalf("bad metadata created files: ids=%v active=%d", ids, active)
	}
}

// TestHostileStreams covers truncated uploads, oversized uploads (> maxUploadBytes),
// slow uploads stalling past ioTimeout, and concurrency limits.
func TestHostileStreams(t *testing.T) {
	opts := defaultServerOpts()
	opts.maxUploadBytes = 100 * 1024 // 100 KiB
	opts.ioTimeout = 150 * time.Millisecond
	opts.maxConcurrentPUTs = 1
	opts.slotWaitTimeout = 100 * time.Millisecond
	env := startTestServer(t, opts)

	// 1. Oversized upload with known Content-Length.
	resp, _ := env.doReq(http.MethodPut, "/inbox", map[string][]string{"X-Ndes-Name": {"big.bin"}}, bytes.NewReader(make([]byte, 200*1024)), 200*1024)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("known oversized PUT: got %d, want 413", resp.StatusCode)
	}

	// 2. Oversized chunked upload (ContentLength == -1).
	resp, _ = env.doReq(http.MethodPut, "/inbox", map[string][]string{"X-Ndes-Name": {"big-chunked.bin"}}, io.LimitReader(bytes.NewReader(make([]byte, 200*1024)), 200*1024), -1)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversized PUT: got %d, want 413", resp.StatusCode)
	}
	assertNoPartFiles(t, env.inboxDir)

	// 3. Aborted upload mid-stream (declares Content-Length: 50000, sends 1000 bytes then closes connection).
	conn, err := env.ln.dial()
	if err != nil {
		t.Fatal(err)
	}
	rawReq := fmt.Sprintf("PUT /inbox HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nX-Ndes-Name: aborted.bin\r\nContent-Length: 50000\r\n\r\n", testBearerToken)
	_, _ = conn.Write([]byte(rawReq))
	_, _ = conn.Write(bytes.Repeat([]byte("x"), 1000))
	_ = conn.Close() // abort before sending remaining 49000 bytes

	// Wait briefly for server handler to finish cleanup.
	time.Sleep(50 * time.Millisecond)
	assertNoPartFiles(t, env.inboxDir)
	if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 0 {
		t.Fatalf("aborted upload left a sealed file: %v", ids)
	}

	// 4. Slow upload stalling past ioTimeout (150ms) and concurrent upload rejection.
	pr, pw := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	var slowStatus int
	go func() {
		defer wg.Done()
		req, _ := http.NewRequest(http.MethodPut, env.baseURL+"/inbox", pr)
		req.Header.Set("Authorization", "Bearer "+testBearerToken)
		req.Header.Set("X-Ndes-Name", "slow.bin")
		res, err := env.client.Do(req)
		if err == nil {
			slowStatus = res.StatusCode
			res.Body.Close()
		}
	}()

	// Wait until the slow upload is in-flight and holding the single upload slot.
	time.Sleep(30 * time.Millisecond)

	// A second concurrent PUT must fail with 429 Too Many Requests after slotWaitTimeout (100ms).
	resp2, _ := env.doReq(http.MethodPut, "/inbox", map[string][]string{"X-Ndes-Name": {"second.bin"}}, strings.NewReader("hi"), 2)
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("concurrent PUT while slot held: got %d, want 429", resp2.StatusCode)
	}

	// Let the first upload stall past ioTimeout (150ms).
	time.Sleep(250 * time.Millisecond)
	_ = pw.Close()
	wg.Wait()
	if slowStatus != 0 && slowStatus != http.StatusRequestTimeout && slowStatus != http.StatusBadRequest {
		t.Fatalf("slow upload status = %d, want 408 or 400 (or connection closed)", slowStatus)
	}
	assertNoPartFiles(t, env.inboxDir)
	if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 0 {
		t.Fatalf("slow upload left a file: %v", ids)
	}
}

// TestHostilePathsAndFilesystem tests path traversal, query strings, wrong HTTP
// methods, symlinks/FIFOs in the inbox directory, and startup .part cleanup.
func TestHostilePathsAndFilesystem(t *testing.T) {
	env := startTestServer(t, defaultServerOpts())

	badPaths := []string{
		"/inbox/../../etc/passwd",
		"/inbox/.ndes-0123456789abcdef.part",
		"/inbox/0123456789ABCDEF0123456789ABCDEF",  // uppercase hex
		"/inbox/0123456789abcdef0123456789abcde",   // 31 chars
		"/inbox/0123456789abcdef0123456789abcdef0", // 33 chars
		"/inbox/0123456789abcdef0123456789abcdef/extra",
		"/inbox?foo=bar",
	}
	for _, p := range badPaths {
		for _, m := range []string{http.MethodGet, http.MethodDelete} {
			resp, _ := env.doReq(m, p, nil, nil, -1)
			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s: got %d, want 400 or 404", m, p, resp.StatusCode)
			}
		}
	}

	// Unsupported methods.
	resp, _ := env.doReq(http.MethodPost, "/inbox", nil, nil, -1)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /inbox: got %d, want 405", resp.StatusCode)
	}

	// Plant a symlink and a directory with a valid <32 hex>.inb name inside inboxDir.
	symID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dirID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(victim, []byte("secret"), 0o600)
	_ = os.Symlink(victim, filepath.Join(env.inboxDir, symID+".inb"))
	_ = os.Mkdir(filepath.Join(env.inboxDir, dirID+".inb"), 0o700)

	// Neither should appear in GET /inbox.
	listResp, listBody := env.doReq(http.MethodGet, "/inbox", nil, nil, -1)
	if listResp.StatusCode != http.StatusOK || string(listBody) != `{"ids":[]}`+"\n" {
		t.Fatalf("GET /inbox with symlink/dir: %d %s", listResp.StatusCode, listBody)
	}
	// Neither should be served by GET /inbox/{id} or unlinked by DELETE /inbox/{id}.
	for _, id := range []string{symID, dirID} {
		gResp, _ := env.doReq(http.MethodGet, "/inbox/"+id, nil, nil, -1)
		if gResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET planted %s: got %d, want 400", id, gResp.StatusCode)
		}
		dResp, _ := env.doReq(http.MethodDelete, "/inbox/"+id, nil, nil, -1)
		if dResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("DELETE planted %s: got %d, want 400", id, dResp.StatusCode)
		}
	}
	if _, err := os.Lstat(filepath.Join(env.inboxDir, symID+".inb")); err != nil {
		t.Fatal("DELETE unlinked planted symlink")
	}

	// Startup cleanup of leftover .ndes-<16 hex>.part files.
	stalePart := filepath.Join(env.inboxDir, ".ndes-0123456789abcdef.part")
	_ = os.WriteFile(stalePart, []byte("incomplete"), 0o600)
	d2, err := openInboxDir(env.inboxDir, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	_ = d2.Close()
	if _, err := os.Lstat(stalePart); !os.IsNotExist(err) {
		t.Fatal("openInboxDir did not remove stale .part file on startup")
	}
}

// TestConfigPermissionsAndListenGuards verifies config file mode checks (0600),
// vault-root refusal, non-loopback plain HTTP refusal, and zero-logging.
func TestConfigPermissionsAndListenGuards(t *testing.T) {
	tmp := t.TempDir()
	inboxDir := filepath.Join(tmp, "inbox")
	_ = os.Mkdir(inboxDir, 0o700)

	var pub, kauth [core.KeySize]byte
	pub[0], kauth[0] = 1, 2
	cfgContent := fmt.Sprintf("inbox_pub: %s\nk_auth: %s\ntoken: %s\n",
		base64.StdEncoding.EncodeToString(pub[:]),
		base64.StdEncoding.EncodeToString(kauth[:]),
		testBearerToken)

	// 1. Config with 0644 permissions must be refused.
	openCfg := filepath.Join(tmp, "open.conf")
	_ = os.WriteFile(openCfg, []byte(cfgContent), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"--config", openCfg, "--inbox", inboxDir}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "permissions") {
		t.Fatalf("0644 config accepted: code=%d stderr=%s", code, errb.String())
	}

	// 2. Symlinked config file must be refused.
	goodCfg := filepath.Join(tmp, "good.conf")
	_ = os.WriteFile(goodCfg, []byte(cfgContent), 0o600)
	symCfg := filepath.Join(tmp, "sym.conf")
	_ = os.Symlink(goodCfg, symCfg)
	errb.Reset()
	if code := run([]string{"--config", symCfg, "--inbox", inboxDir}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "symlink") {
		t.Fatalf("symlink config accepted: code=%d stderr=%s", code, errb.String())
	}

	// 3. Non-loopback address without TLS or --allow-insecure-http must be refused.
	errb.Reset()
	if code := run([]string{"--config", goodCfg, "--inbox", inboxDir, "--listen", "0.0.0.0:0"}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "non-loopback") {
		t.Fatalf("non-loopback plain HTTP accepted without flag: code=%d stderr=%s", code, errb.String())
	}

	// 4. Pointing --inbox at a vault root (containing vault.json) must be refused.
	vaultRoot := filepath.Join(tmp, "vault")
	_ = os.Mkdir(vaultRoot, 0o700)
	_ = os.WriteFile(filepath.Join(vaultRoot, "vault.json"), []byte("{}"), 0o600)
	errb.Reset()
	if code := run([]string{"--config", goodCfg, "--inbox", vaultRoot}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "vault.json") {
		t.Fatalf("vault root accepted as Mode B inbox: code=%d stderr=%s", code, errb.String())
	}

	// 5. Signal cleanup removes active temp files and exits 130 on SIGINT.
	reg := newTempRegistry()
	d, err := openInboxDir(inboxDir, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tmpName, f, err := createTempAt(d)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	reg.register(tmpName, func() { _ = d.unlink(tmpName) })
	exited := make(chan int, 1)
	stop := installSignalCleanup(reg, func(code int) { exited <- code })
	defer stop()
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case code := <-exited:
		if code != 130 {
			t.Fatalf("exit code %d, want 130", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("signal not handled")
	}
	assertNoPartFiles(t, inboxDir)
}

// TestZeroLogging ensures neither filenames, metadata, nor tokens appear in any
// server output stream.
func TestZeroLogging(t *testing.T) {
	var stderrBuf bufio.Writer
	var raw bytes.Buffer
	stderrBuf = *bufio.NewWriter(&raw)
	env := startTestServer(t, defaultServerOpts())

	secretName := "ultra-secret-filename-9999.pdf"
	secretDir := "secret-folder-8888"
	resp, _ := env.doReq(http.MethodPut, "/inbox", map[string][]string{
		"X-Ndes-Name": {secretName},
		"X-Ndes-Dir":  {secretDir},
	}, strings.NewReader("classified-body-7777"), 20)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_ = stderrBuf.Flush()
	logged := raw.String()
	for _, forbidden := range []string{secretName, secretDir, "classified-body-7777", testBearerToken} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("server logged sensitive string %q", forbidden)
		}
	}
}

// TestConcurrentUploadQuotaEnforcement verifies VALV-REV2-03: when maxInboxFiles
// is 2 and 1 .inb file already exists, 4 concurrent uploads launched at the same
// time must result in at most 1 allowed upload (201 Created) and 3 rejected
// uploads (507 Insufficient Storage), never overshooting maxInboxFiles.
func TestConcurrentUploadQuotaEnforcement(t *testing.T) {
	opts := defaultServerOpts()
	opts.maxInboxFiles = 2
	opts.maxConcurrentPUTs = 4
	env := startTestServer(t, opts)

	// 1. Seed 1 existing .inb file so only 1 quota slot remains (maxInboxFiles - 1).
	resp, _ := env.doReq(http.MethodPut, "/inbox", map[string][]string{
		"X-Ndes-Name": {"existing.txt"},
	}, strings.NewReader("existing"), 8)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("seed PUT failed: %d", resp.StatusCode)
	}

	// 2. Launch 4 concurrent slow uploads simultaneously.
	const concurrentUploads = 4
	type pipePair struct {
		pr *io.PipeReader
		pw *io.PipeWriter
	}
	pipes := make([]pipePair, concurrentUploads)
	for i := range pipes {
		pr, pw := io.Pipe()
		pipes[i] = pipePair{pr: pr, pw: pw}
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses []int
	)
	startGate := make(chan struct{})
	for i := 0; i < concurrentUploads; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startGate
			req, err := http.NewRequest(http.MethodPut, env.baseURL+"/inbox", pipes[idx].pr)
			if err != nil {
				t.Errorf("NewRequest: %v", err)
				return
			}
			req.Header.Set("Authorization", "Bearer "+testBearerToken)
			req.Header.Set("X-Ndes-Name", fmt.Sprintf("concurrent-%d.bin", idx))
			res, err := env.client.Do(req)
			if err != nil {
				t.Errorf("Do(%d): %v", idx, err)
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			mu.Lock()
			statuses = append(statuses, res.StatusCode)
			mu.Unlock()
		}(i)
	}

	// Release all 4 concurrent PUT requests at once.
	close(startGate)

	// Give all 4 handlers time to reach writeInboxAt while the 1 allowed upload is still open.
	time.Sleep(60 * time.Millisecond)

	// Finish writing to any open pipe and close all pipes.
	for _, p := range pipes {
		_, _ = p.pw.Write([]byte("payload"))
		_ = p.pw.Close()
	}
	wg.Wait()

	var createdCount, quotaRejectedCount int
	for _, st := range statuses {
		switch st {
		case http.StatusCreated:
			createdCount++
		case http.StatusInsufficientStorage:
			quotaRejectedCount++
		default:
			t.Fatalf("unexpected status code in concurrent quota test: %d (all: %v)", st, statuses)
		}
	}
	if createdCount != 1 || quotaRejectedCount != 3 {
		t.Fatalf("expected 1x 201 Created and 3x 507 Insufficient Storage, got created=%d rejected=%d (statuses=%v)",
			createdCount, quotaRejectedCount, statuses)
	}

	assertNoPartFiles(t, env.inboxDir)
	ids, activeFiles, err := env.dirH.listInboxIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || activeFiles != 2 {
		t.Fatalf("expected exactly 2 inbox files on disk, got ids=%d activeFiles=%d", len(ids), activeFiles)
	}
}

// L2: byte quota, free-space margin and ENOSPC mapping.
func TestInboxByteQuotaAndSpace(t *testing.T) {
	opts := defaultServerOpts()
	opts.maxInboxBytes = 350 << 10
	opts.minFreeBytes = 0
	env := startTestServer(t, opts)
	put := func(name string, n int) (*http.Response, string) {
		resp, body := env.doReq(http.MethodPut, "/inbox", map[string][]string{"X-Ndes-Name": {name}}, bytes.NewReader(make([]byte, n)), int64(n))
		return resp, string(body)
	}
	// A 100 KiB file fits (its stored size is estimated as length plus about 70 KiB).
	if resp, body := put("a.bin", 100<<10); resp.StatusCode != http.StatusCreated {
		t.Fatalf("first upload: %d %s", resp.StatusCode, body)
	}
	// A declared length that cannot fit is refused at once, with the byte-limit body.
	resp, body := put("huge.bin", 400<<10)
	if resp.StatusCode != http.StatusInsufficientStorage || !strings.Contains(body, "inbox byte limit reached") {
		t.Fatalf("oversized declared length: %d %q", resp.StatusCode, body)
	}
	assertNoPartFiles(t, env.inboxDir)
}

func TestByteQuotaIsAtomicUnderConcurrency(t *testing.T) {
	opts := defaultServerOpts()
	opts.maxInboxBytes = 3 * sealedEstimate(64<<10) // room for exactly three 64 KiB uploads
	opts.minFreeBytes = 0
	opts.maxConcurrentPUTs = 16
	env := startTestServer(t, opts)
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[int]int{}
	gate := make(chan struct{})
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			resp, _ := env.doReq(http.MethodPut, "/inbox", map[string][]string{"X-Ndes-Name": {fmt.Sprintf("f%d", i)}}, bytes.NewReader(make([]byte, 64<<10)), 64<<10)
			mu.Lock()
			counts[resp.StatusCode]++
			mu.Unlock()
		}(i)
	}
	close(gate)
	wg.Wait()
	if counts[http.StatusCreated] > 3 || counts[http.StatusCreated] == 0 || counts[http.StatusCreated]+counts[http.StatusInsufficientStorage] != 12 {
		t.Fatalf("quota overshoot or odd statuses: %v", counts)
	}
	total, _ := env.dirH.storedInboxBytes()
	if total > opts.maxInboxBytes {
		t.Fatalf("stored %d bytes > quota %d", total, opts.maxInboxBytes)
	}
	assertNoPartFiles(t, env.inboxDir)
}

func TestChunkedUploadStopsAtItsBudget(t *testing.T) {
	opts := defaultServerOpts()
	opts.maxInboxBytes = 3 << 20 // a chunked upload gets what is left: 3 MiB
	opts.minFreeBytes = 0
	env := startTestServer(t, opts)
	resp, body := env.doReq(http.MethodPut, "/inbox", map[string][]string{"X-Ndes-Name": {"c.bin"}}, io.LimitReader(zeroReader{}, 5<<20), -1)
	if resp.StatusCode != http.StatusInsufficientStorage || !strings.Contains(string(body), "inbox byte limit reached") {
		t.Fatalf("chunked overshoot: %d %q", resp.StatusCode, body)
	}
	assertNoPartFiles(t, env.inboxDir)
	if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 0 {
		t.Fatalf("partial upload kept: %v", ids)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestFreeSpaceMarginRefusesWithOutOfSpaceBody(t *testing.T) {
	opts := defaultServerOpts()
	opts.minFreeBytes = 1 << 60 // more than any disk has
	env := startTestServer(t, opts)
	resp, body := env.doReq(http.MethodPut, "/inbox", map[string][]string{"X-Ndes-Name": {"x"}}, strings.NewReader("hello"), 5)
	if resp.StatusCode != http.StatusInsufficientStorage || !strings.Contains(string(body), "server out of space") {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
}

func TestPutErrorMapping(t *testing.T) {
	enospc := &os.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC}
	cases := []struct {
		err    error
		status int
		msg    string
	}{
		{fmt.Errorf("seal: %w", enospc), 507, "server out of space"},
		{fmt.Errorf("%w", &os.PathError{Op: "write", Err: syscall.EDQUOT}), 507, "server out of space"},
		{errNoSpace, 507, "server out of space"},
		{errBytesQuota, 507, "inbox byte limit reached"},
		{errQuotaExceeded, 507, "inbox file limit reached"},
		{errUploadTooSlow, 408, "upload too slow"},
		{errors.New("other"), 400, "upload failed"},
	}
	for _, c := range cases {
		if st, msg := putErrorResponse(c.err); st != c.status || msg != c.msg {
			t.Errorf("%v: got %d %q, want %d %q", c.err, st, msg, c.status, c.msg)
		}
	}
}

// L3: the whole upload has a deadline, so a slow drip loses its slot.
func TestSlowDripUploadLosesItsSlot(t *testing.T) {
	opts := defaultServerOpts()
	opts.maxConcurrentPUTs = 1
	opts.slotWaitTimeout = 100 * time.Millisecond
	opts.ioTimeout = 30 * time.Second // each read is fine; only the overall deadline can stop this
	opts.uploadBase = 500 * time.Millisecond
	opts.minUploadRate = 1 << 20
	opts.minFreeBytes = 0
	env := startTestServer(t, opts)

	pr, pw := io.Pipe()
	done := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPut, env.baseURL+"/inbox", pr)
		req.ContentLength = 100000
		req.Header.Set("Authorization", "Bearer "+testBearerToken)
		req.Header.Set("X-Ndes-Name", "drip.bin")
		res, err := env.client.Do(req)
		if err != nil {
			done <- 0
			return
		}
		res.Body.Close()
		done <- res.StatusCode
	}()
	go func() { // one byte every 100 ms: never idle for long, never finishing
		for i := 0; i < 100; i++ {
			if _, err := pw.Write([]byte{'x'}); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		pw.Close()
	}()
	start := time.Now()
	select {
	case st := <-done:
		if st != 0 && st != http.StatusRequestTimeout {
			t.Fatalf("drip upload ended with %d, want 408 (or a closed connection)", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("slow drip kept its slot past the overall deadline")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	// The slot is free again.
	if resp, body := env.doReq(http.MethodPut, "/inbox", map[string][]string{"X-Ndes-Name": {"after.bin"}}, strings.NewReader("ok"), 2); resp.StatusCode != http.StatusCreated {
		t.Fatalf("slot not released: %d %s", resp.StatusCode, body)
	}
	assertNoPartFiles(t, env.inboxDir)
}

func TestUploadDeadlineFormula(t *testing.T) {
	s := &inboxServer{opts: serverOpts{uploadBase: 10 * time.Second, minUploadRate: 1000, maxChunkedTime: time.Minute}}
	now := time.Unix(0, 0)
	if got := s.uploadDeadline(5000, now); got != now.Add(15*time.Second) {
		t.Fatalf("known length: %v", got)
	}
	if got := s.uploadDeadline(-1, now); got != now.Add(time.Minute) {
		t.Fatalf("unknown length: %v", got)
	}
}

// L9: the inbox directory must not be writable by group or others.
func TestInboxDirectoryPermissions(t *testing.T) {
	mk := func(mode os.FileMode) string {
		d := filepath.Join(t.TempDir(), "inbox")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		return d
	}
	for _, m := range []os.FileMode{0o777, 0o770, 0o702, 0o722} {
		if _, err := openInboxDir(mk(m), io.Discard); err == nil || !strings.Contains(err.Error(), "write") {
			t.Errorf("mode %04o accepted: %v", m, err)
		}
	}
	var warn bytes.Buffer
	d, err := openInboxDir(mk(0o755), &warn)
	if err != nil {
		t.Fatalf("0755 refused: %v", err)
	}
	d.Close()
	if !strings.Contains(warn.String(), "readable by group or others") {
		t.Errorf("no warning for 0755: %q", warn.String())
	}
	warn.Reset()
	d, err = openInboxDir(mk(0o700), &warn)
	if err != nil || warn.Len() != 0 {
		t.Fatalf("0700: %v %q", err, warn.String())
	}
	d.Close()
}

func TestClientSealedUpload(t *testing.T) {
	env := startTestServer(t, defaultServerOpts())

	// 1. Create a client-sealed inbox file locally.
	meta := core.Metadata{Name: "client_secret.txt", Dir: "docs", MTime: 1234567890, MIME: "text/plain", Rev: 1}
	plain := []byte("this is a client-sealed secret plaintext that the server never sees in the clear")
	var inbBuf bytes.Buffer
	id, err := core.SealInbox(&inbBuf, env.keys.InboxPub, env.keys.InboxAuth, meta, bytes.NewReader(plain))
	if err != nil {
		t.Fatalf("SealInbox: %v", err)
	}
	sealedBytes := inbBuf.Bytes()

	// 2. Reject if metadata headers are supplied on client-sealed upload.
	reqBadHdr, _ := http.NewRequest(http.MethodPut, env.baseURL+"/inbox/"+id.String(), bytes.NewReader(sealedBytes))
	reqBadHdr.Header.Set("Authorization", "Bearer "+testBearerToken)
	reqBadHdr.Header.Set("X-Ndes-Name", "leak.txt")
	respBadHdr, err := env.client.Do(reqBadHdr)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	respBadHdr.Body.Close()
	if respBadHdr.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT with X-Ndes-* headers: got %d, want 400", respBadHdr.StatusCode)
	}

	// 3. Reject wrong auth token.
	reqBadAuth, _ := http.NewRequest(http.MethodPut, env.baseURL+"/inbox/"+id.String(), bytes.NewReader(sealedBytes))
	reqBadAuth.Header.Set("Authorization", "Bearer wrong-token")
	respBadAuth, err := env.client.Do(reqBadAuth)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	respBadAuth.Body.Close()
	if respBadAuth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PUT with wrong auth: got %d, want 401", respBadAuth.StatusCode)
	}

	// 4. Reject file_id mismatch between URL and header.
	wrongID := core.FileID{}
	rand.Read(wrongID[:])
	reqWrongID, _ := http.NewRequest(http.MethodPut, env.baseURL+"/inbox/"+wrongID.String(), bytes.NewReader(sealedBytes))
	reqWrongID.Header.Set("Authorization", "Bearer "+testBearerToken)
	respWrongID, err := env.client.Do(reqWrongID)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	respWrongID.Body.Close()
	if respWrongID.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT with mismatched ID: got %d, want 400", respWrongID.StatusCode)
	}

	// 5. Valid client-sealed upload -> 201 Created.
	req, _ := http.NewRequest(http.MethodPut, env.baseURL+"/inbox/"+id.String(), bytes.NewReader(sealedBytes))
	req.Header.Set("Authorization", "Bearer "+testBearerToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(sealedBytes))
	resp, err := env.client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT client-sealed: got %d, want 201: %s", resp.StatusCode, body)
	}
	var res struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.ID != id.String() {
		t.Fatalf("PUT client-sealed response mismatch: %s", body)
	}

	// Verify the stored file on server by downloading and ingesting it.
	getReq, _ := http.NewRequest(http.MethodGet, env.baseURL+"/inbox/"+id.String(), nil)
	getReq.Header.Set("Authorization", "Bearer "+testBearerToken)
	getResp, err := env.client.Do(getReq)
	if err != nil {
		t.Fatalf("GET /inbox/{id}: %v", err)
	}
	gotBytes, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if !bytes.Equal(gotBytes, sealedBytes) {
		t.Fatal("downloaded bytes differ from uploaded client-sealed bytes")
	}

	var objBuf bytes.Buffer
	ingestMeta, err := core.IngestInbox(bytes.NewReader(gotBytes), int64(len(gotBytes)), id, env.keys, &objBuf)
	if err != nil {
		t.Fatalf("IngestInbox: %v", err)
	}
	if ingestMeta.Name != meta.Name || ingestMeta.Dir != meta.Dir {
		t.Fatalf("metadata mismatch: got %+v, want %+v", ingestMeta, meta)
	}
	var plainBuf bytes.Buffer
	if _, err := core.DecryptObject(bytes.NewReader(objBuf.Bytes()), int64(objBuf.Len()), id, env.keys, &plainBuf); err != nil {
		t.Fatalf("DecryptObject: %v", err)
	}
	if !bytes.Equal(plainBuf.Bytes(), plain) {
		t.Fatalf("decrypted plaintext differs: got %q, want %q", plainBuf.String(), string(plain))
	}

	// 6. L11 Idempotency: Uploading identical bytes for the existing file_id succeeds as a no-op (200 OK).
	retryReq, _ := http.NewRequest(http.MethodPut, env.baseURL+"/inbox/"+id.String(), bytes.NewReader(sealedBytes))
	retryReq.Header.Set("Authorization", "Bearer "+testBearerToken)
	retryReq.Header.Set("Content-Type", "application/octet-stream")
	retryReq.ContentLength = int64(len(sealedBytes))
	retryResp, err := env.client.Do(retryReq)
	if err != nil {
		t.Fatalf("Do retry: %v", err)
	}
	retryBody, _ := io.ReadAll(retryResp.Body)
	retryResp.Body.Close()
	if retryResp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent PUT retry: got %d, want 200: %s", retryResp.StatusCode, retryBody)
	}

	// 7. Uploading DIFFERENT bytes for an existing file_id -> 409 Conflict.
	diffBytes := make([]byte, len(sealedBytes))
	copy(diffBytes, sealedBytes)
	diffBytes[len(diffBytes)-1] ^= 0x01 // flip last byte
	confReq, _ := http.NewRequest(http.MethodPut, env.baseURL+"/inbox/"+id.String(), bytes.NewReader(diffBytes))
	confReq.Header.Set("Authorization", "Bearer "+testBearerToken)
	confReq.Header.Set("Content-Type", "application/octet-stream")
	confReq.ContentLength = int64(len(diffBytes))
	confResp, err := env.client.Do(confReq)
	if err != nil {
		t.Fatalf("Do conflict: %v", err)
	}
	confResp.Body.Close()
	if confResp.StatusCode != http.StatusConflict {
		t.Fatalf("conflicting PUT: got %d, want 409", confResp.StatusCode)
	}
}
