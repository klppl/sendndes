package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/klppl/sendndes/core"
)

const (
	uploadToken = "upload-only-token-0123456789abcdefghij"
	pullToken   = "pull-only-token-0123456789abcdefghijkl"
)

// sealedEnv is a server that holds no key material: sealed uploads only, three tokens with roles.
func sealedEnv(t *testing.T, mutate func(*serverOpts)) *testServerEnv {
	t.Helper()
	opts := defaultServerOpts()
	opts.enableServerSealing = false
	if mutate != nil {
		mutate(&opts)
	}
	env := startTestServer(t, opts)
	env.srv.setTokens(mustTokens(t,
		"upload phone "+hashHex(uploadToken),
		"pull mac "+hashHex(pullToken),
		"both owner "+hashHex(testBearerToken)))
	return env
}

func mustTokens(t *testing.T, lines ...string) *tokenSet {
	t.Helper()
	set, err := parseTokensFile([]byte(strings.Join(lines, "\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// sealedFile makes a valid sealed inbox file of n plaintext bytes.
func (e *testServerEnv) sealedFile(n int) (core.FileID, []byte) {
	e.t.Helper()
	meta := core.Metadata{Name: "x.bin", Dir: "iPhone", MTime: 1, Size: int64(n)}
	var buf bytes.Buffer
	data := make([]byte, n)
	rand.Read(data)
	id, err := core.SealInbox(&buf, e.keys.InboxPub, e.keys.InboxAuth, meta, bytes.NewReader(data))
	if err != nil {
		e.t.Fatal(err)
	}
	return id, buf.Bytes()
}

// call sends one request with the given token and returns the status and body.
func (e *testServerEnv) call(method, path, token string, body []byte, hdr map[string]string) (int, string) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, e.baseURL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRolesAndPing(t *testing.T) {
	env := sealedEnv(t, nil)
	id, file := env.sealedFile(100)

	// Ping: any valid token, 204, empty body.
	for _, tok := range []string{uploadToken, pullToken, testBearerToken} {
		if code, body := env.call("GET", "/v1/ping", tok, nil, nil); code != 204 || body != "" {
			t.Fatalf("ping with a valid token: %d %q", code, body)
		}
	}
	if code, _ := env.call("GET", "/v1/ping", "", nil, nil); code != 401 {
		t.Fatalf("ping without a token: %d", code)
	}
	if code, _ := env.call("POST", "/v1/ping", uploadToken, nil, nil); code != 405 {
		t.Fatalf("POST ping: %d", code)
	}

	// An upload token uploads and nothing else.
	if code, body := env.call("PUT", "/inbox/"+id.String(), uploadToken, file, nil); code != 201 {
		t.Fatalf("upload token PUT: %d %s", code, body)
	}
	for _, c := range [][2]string{{"GET", "/inbox"}, {"GET", "/inbox/" + id.String()}, {"DELETE", "/inbox/" + id.String()}} {
		if code, _ := env.call(c[0], c[1], uploadToken, nil, nil); code != 403 {
			t.Fatalf("upload token %s %s: %d, want 403", c[0], c[1], code)
		}
	}
	if _, err := os.Lstat(filepath.Join(env.inboxDir, id.String()+".inb")); err != nil {
		t.Fatal("a forbidden call changed the inbox")
	}

	// A pull token reads and deletes and cannot upload.
	id2, file2 := env.sealedFile(100)
	if code, _ := env.call("PUT", "/inbox/"+id2.String(), pullToken, file2, nil); code != 403 {
		t.Fatalf("pull token PUT: %d, want 403", code)
	}
	if code, body := env.call("GET", "/inbox", pullToken, nil, nil); code != 200 || !strings.Contains(body, id.String()) {
		t.Fatalf("pull token list: %d %s", code, body)
	}
	if code, body := env.call("GET", "/inbox/"+id.String(), pullToken, nil, nil); code != 200 || body != string(file) {
		t.Fatalf("pull token GET: %d", code)
	}
	if code, _ := env.call("DELETE", "/inbox/"+id.String(), pullToken, nil, nil); code != 204 {
		t.Fatalf("pull token DELETE: %d", code)
	}
	// Both does everything.
	if code, _ := env.call("PUT", "/inbox/"+id2.String(), testBearerToken, file2, nil); code != 201 {
		t.Fatalf("both PUT: %d", code)
	}
	if code, _ := env.call("GET", "/inbox", testBearerToken, nil, nil); code != 200 {
		t.Fatalf("both list: %d", code)
	}
}

func TestServerSealingIsOffByDefault(t *testing.T) {
	env := sealedEnv(t, nil)
	code, _ := env.call("PUT", "/inbox", testBearerToken, []byte("plaintext"), map[string]string{"X-Ndes-Name": "a.txt"})
	if code != 404 {
		t.Fatalf("PUT /inbox with server sealing off: %d, want 404", code)
	}
	if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 0 {
		t.Fatal("something was stored")
	}
	// And when it is on, the same call works (the old behaviour).
	on := startTestServer(t, defaultServerOpts())
	if code, _ := on.call("PUT", "/inbox", testBearerToken, []byte("plaintext"), map[string]string{"X-Ndes-Name": "a.txt"}); code != 201 {
		t.Fatalf("PUT /inbox with server sealing on: %d", code)
	}
}

func TestSealedUploadIdempotencyAndConflict(t *testing.T) {
	env := sealedEnv(t, nil)
	id, file := env.sealedFile(5000)
	if code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, file, nil); code != 201 {
		t.Fatalf("first: %d", code)
	}
	if code, body := env.call("PUT", "/inbox/"+id.String(), uploadToken, file, nil); code != 200 || !strings.Contains(body, id.String()) {
		t.Fatalf("identical retry: %d %s", code, body)
	}
	// Same id, different bytes: 409, and the stored file is untouched.
	other := bytes.Clone(file)
	other[len(other)-1] ^= 1
	if code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, other, nil); code != 409 {
		t.Fatalf("different bytes: %d, want 409", code)
	}
	got, _ := os.ReadFile(filepath.Join(env.inboxDir, id.String()+".inb"))
	if !bytes.Equal(got, file) {
		t.Fatal("the stored file changed")
	}
	// After the file was pulled and deleted, a replay stores it again (the client's already-ingested rule absorbs it).
	if code, _ := env.call("DELETE", "/inbox/"+id.String(), pullToken, nil, nil); code != 204 {
		t.Fatal("delete")
	}
	if code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, file, nil); code != 201 {
		t.Fatalf("replay after delete: %d", code)
	}
	assertNoPartFiles(t, env.inboxDir)
}

func TestConcurrentSameIDUploads(t *testing.T) {
	for _, identical := range []bool{true, false} {
		env := sealedEnv(t, func(o *serverOpts) { o.maxConcurrentPUTs = 8 })
		id, file := env.sealedFile(200000)
		const n = 4 // two tokens, two slots each
		codes := make([]int, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			body := file
			if !identical && i > 0 {
				body = bytes.Clone(file)
				body[len(body)-1] ^= byte(i)
			}
			wg.Add(1)
			go func(i int, body []byte) {
				defer wg.Done()
				tok := uploadToken
				if i%2 == 1 {
					tok = testBearerToken
				}
				codes[i], _ = env.call("PUT", "/inbox/"+id.String(), tok, body, nil)
			}(i, body)
		}
		wg.Wait()
		created, ok, conflict := 0, 0, 0
		for _, c := range codes {
			switch c {
			case 201:
				created++
			case 200:
				ok++
			case 409:
				conflict++
			default:
				t.Fatalf("identical=%v: unexpected status %d in %v", identical, c, codes)
			}
		}
		if created != 1 {
			t.Fatalf("identical=%v: %d uploads created the file: %v", identical, created, codes)
		}
		if identical && conflict != 0 {
			t.Fatalf("identical uploads got 409: %v", codes)
		}
		if !identical && ok+conflict != n-1 {
			t.Fatalf("codes %v", codes)
		}
		if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 1 {
			t.Fatalf("%d files stored", len(ids))
		}
		assertNoPartFiles(t, env.inboxDir)
	}
}

func TestSealedUploadRejectsMalformedBodies(t *testing.T) {
	env := sealedEnv(t, nil)
	id, file := env.sealedFile(70000) // two chunks
	hdr := 58 + 540
	// Truncation at every boundary near the structural limits: a cut is accepted only if the structure check
	// (SPEC 5.3) would accept those exact bytes; everything else is 400. Nothing may leave a temp file.
	cuts := map[int]bool{0: true, 1: true, 21: true, 22: true, 57: true, 58: true, 59: true, hdr - 1: true, hdr: true, hdr + 1: true, hdr + 15: true, hdr + 16: true, hdr + 17: true}
	for _, base := range []int{4096 + 16, 65536 + 16, 65552, 65552 + 16, 65552 + 17, len(file) - hdr} {
		for d := -2; d <= 2; d++ {
			if c := hdr + base + d; c > 0 && c < len(file) {
				cuts[c] = true
			}
		}
	}
	for cut := range cuts {
		body := file[:cut]
		code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, body, nil)
		var sink bytes.Buffer
		_, verr := core.ValidateAndCopyInbox(&sink, bytes.NewReader(body), id)
		switch {
		case verr != nil && code != 400:
			t.Fatalf("cut at %d: structure is invalid but the server said %d", cut, code)
		case verr == nil && code != 201:
			t.Fatalf("cut at %d: structure is valid but the server said %d", cut, code)
		}
		if code == 201 {
			env.call("DELETE", "/inbox/"+id.String(), pullToken, nil, nil)
		}
		assertNoPartFiles(t, env.inboxDir)
	}

	// The id in the URL must equal the header's; ids must be 32 lowercase hex.
	var other core.FileID
	rand.Read(other[:])
	for _, bad := range []string{other.String(), strings.ToUpper(id.String()), id.String()[:31], id.String() + "0", "../" + id.String(), "zz" + id.String()[2:]} {
		if code, _ := env.call("PUT", "/inbox/"+bad, uploadToken, file, nil); code != 400 && code != 404 {
			t.Fatalf("PUT /inbox/%s: %d", bad, code)
		}
	}
	// Wrong magic, version, kind.
	for i, b := range []byte{'X', 'D', 'E', 'S'} {
		bad := bytes.Clone(file)
		bad[i] = b ^ 0x20
		if code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, bad, nil); code != 400 {
			t.Fatalf("bad magic byte %d: %d", i, code)
		}
	}
	for _, at := range []int{4, 5} {
		bad := bytes.Clone(file)
		bad[at] = 9
		if code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, bad, nil); code != 400 {
			t.Fatalf("bad header byte %d: %d", at, code)
		}
	}
	// meta_len out of bounds, including a huge one.
	for _, ml := range []uint32{0, 539, 541, 65565, 0xFFFFFFFF, 1 << 30} {
		bad := bytes.Clone(file)
		bad[54], bad[55], bad[56], bad[57] = byte(ml>>24), byte(ml>>16), byte(ml>>8), byte(ml)
		if code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, bad, nil); code != 400 {
			t.Fatalf("meta_len %d: %d", ml, code)
		}
	}
	// File names are not allowed in headers.
	if code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, file, map[string]string{"X-Ndes-Name": "leak.txt"}); code != 400 {
		t.Fatalf("X-Ndes-Name on a sealed upload: %d", code)
	}
	assertNoPartFiles(t, env.inboxDir)
	if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 0 {
		t.Fatalf("bad uploads left %d files", len(ids))
	}
}

func TestSealedUploadLengthRules(t *testing.T) {
	env := sealedEnv(t, func(o *serverOpts) { o.maxSealedBytes = 300000 })
	id, file := env.sealedFile(100)

	// No Content-Length (chunked): 411.
	req, _ := http.NewRequest("PUT", env.baseURL+"/inbox/"+id.String(), io.LimitReader(bytes.NewReader(file), int64(len(file))))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+uploadToken)
	resp, err := env.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 411 {
		t.Fatalf("chunked: %d", resp.StatusCode)
	}

	// Over --max-sealed-bytes: 413 at once, nothing stored.
	big, bigFile := env.sealedFile(400000)
	if code, _ := env.call("PUT", "/inbox/"+big.String(), uploadToken, bigFile, nil); code != 413 {
		t.Fatalf("oversized: %d", code)
	}

	// Content-Length larger than what is sent, then the connection closes: nothing stored, no temp file.
	conn, err := env.ln.dial()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "PUT /inbox/%s HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n", id, uploadToken, len(file)+500)
	conn.Write(file)
	conn.Close()
	time.Sleep(100 * time.Millisecond)
	if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 0 {
		t.Fatal("a short body was stored")
	}
	assertNoPartFiles(t, env.inboxDir)
}

func TestSealedUploadSlowBodyAndQuota(t *testing.T) {
	env := sealedEnv(t, func(o *serverOpts) {
		o.ioTimeout = 150 * time.Millisecond
		o.maxInboxBytes = 400 << 10
	})
	id, file := env.sealedFile(100)
	pr, pw := io.Pipe()
	go func() { pw.Write(file[:200]); time.Sleep(600 * time.Millisecond); pw.Close() }()
	req, _ := http.NewRequest("PUT", env.baseURL+"/inbox/"+id.String(), pr)
	req.ContentLength = int64(len(file))
	req.Header.Set("Authorization", "Bearer "+uploadToken)
	resp, err := env.client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 201 || resp.StatusCode == 200 {
			t.Fatalf("a stalled body was stored: %d", resp.StatusCode)
		}
	}
	time.Sleep(100 * time.Millisecond)
	assertNoPartFiles(t, env.inboxDir)
	if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 0 {
		t.Fatal("a stalled upload left a file")
	}

	// The byte quota: 507 with its own message.
	bigID, bigFile := env.sealedFile(300000)
	if code, body := env.call("PUT", "/inbox/"+bigID.String(), uploadToken, bigFile, nil); code != 201 {
		t.Fatalf("first big file: %d %s", code, body)
	}
	id2, f2 := env.sealedFile(300000)
	if code, body := env.call("PUT", "/inbox/"+id2.String(), uploadToken, f2, nil); code != 507 || !strings.Contains(body, "byte limit") {
		t.Fatalf("over the byte quota: %d %s", code, body)
	}
	assertNoPartFiles(t, env.inboxDir)
}

func TestUploadRacingReadsAndDeletes(t *testing.T) {
	env := sealedEnv(t, nil)
	id, file := env.sealedFile(300000)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	bad := make(chan string, 16)
	for _, op := range []string{"GET", "DELETE", "LIST"} {
		wg.Add(1)
		go func(op string) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				var code int
				var body string
				switch op {
				case "LIST":
					code, body = env.call("GET", "/inbox", pullToken, nil, nil)
					if code != 200 {
						bad <- fmt.Sprintf("list %d", code)
					}
				case "GET":
					code, body = env.call("GET", "/inbox/"+id.String(), pullToken, nil, nil)
					if code == 200 && body != string(file) {
						bad <- "GET returned a partial or altered file"
					} else if code != 200 && code != 404 {
						bad <- fmt.Sprintf("get %d", code)
					}
				case "DELETE":
					code, _ = env.call("DELETE", "/inbox/"+id.String(), pullToken, nil, nil)
					if code != 204 && code != 404 {
						bad <- fmt.Sprintf("delete %d", code)
					}
				}
			}
		}(op)
	}
	for i := 0; i < 8; i++ {
		if code, _ := env.call("PUT", "/inbox/"+id.String(), uploadToken, file, nil); code != 201 && code != 200 {
			t.Errorf("PUT during reads: %d", code)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case m := <-bad:
		t.Fatal(m)
	default:
	}
	assertNoPartFiles(t, env.inboxDir)
}

func TestFailedAuthLimiterAndClientKey(t *testing.T) {
	env := sealedEnv(t, nil)
	srv := env.srv
	do := func(peer, token string, hdr map[string][]string) int {
		req := httptest.NewRequest("GET", "/v1/ping", nil)
		req.RemoteAddr = peer
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}
	// Exhaust the bucket of one client with bad tokens: 401s, then 429. A valid token still passes.
	got429 := false
	for i := 0; i < 20; i++ {
		if do("203.0.113.9:5000", "wrong-token-"+fmt.Sprint(i), nil) == 429 {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("failed attempts were never limited")
	}
	if c := do("203.0.113.9:5001", uploadToken, nil); c != 204 {
		t.Fatalf("a valid token was blocked while the bucket is exhausted: %d", c)
	}
	if c := do("203.0.113.9:5002", "wrong", nil); c != 429 {
		t.Fatalf("bucket should still be exhausted: %d", c)
	}

	// Without --client-ip-header, headers never change the key.
	hdr := map[string][]string{"Cf-Connecting-Ip": {"198.51.100.7"}, "X-Forwarded-For": {"198.51.100.8"}}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	for k, v := range hdr {
		req.Header[k] = v
	}
	if k := srv.clientKey(req); k != "127.0.0.1" {
		t.Fatalf("header trusted without the option: %s", k)
	}

	// With the option: loopback peer + exactly one IP is trusted; everything else falls back to the peer.
	srv.opts.clientIPHeader = "CF-Connecting-IP"
	key := func(peer string, vals ...string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer
		if vals != nil {
			r.Header["Cf-Connecting-Ip"] = vals
		}
		r.Header["X-Forwarded-For"] = []string{"9.9.9.9"}
		return srv.clientKey(r)
	}
	for _, c := range []struct {
		name, peer string
		vals       []string
		want       string
	}{
		{"loopback with one IP", "127.0.0.1:1", []string{"198.51.100.7"}, "198.51.100.7"},
		{"loopback v6 with one IP", "[::1]:1", []string{"2001:db8::1"}, "2001:db8::1"},
		{"non-loopback peer spoofing", "203.0.113.9:1", []string{"198.51.100.7"}, "203.0.113.9"},
		{"private non-loopback peer", "10.0.0.5:1", []string{"198.51.100.7"}, "10.0.0.5"},
		{"two IPs in one value", "127.0.0.1:1", []string{"198.51.100.7, 198.51.100.8"}, "127.0.0.1"},
		{"two header lines", "127.0.0.1:1", []string{"198.51.100.7", "198.51.100.8"}, "127.0.0.1"},
		{"not an IP", "127.0.0.1:1", []string{"banana"}, "127.0.0.1"},
		{"empty", "127.0.0.1:1", []string{""}, "127.0.0.1"},
		{"absent", "127.0.0.1:1", nil, "127.0.0.1"},
	} {
		if got := key(c.peer, c.vals...); got != limiterKey(c.want) {
			t.Errorf("%s: key %q, want %q", c.name, got, c.want)
		}
	}
}

func TestLimiterBucketsPerClientBehindProxy(t *testing.T) {
	env := sealedEnv(t, func(o *serverOpts) { o.clientIPHeader = "CF-Connecting-IP" })
	do := func(client string) int {
		req := httptest.NewRequest("GET", "/v1/ping", nil)
		req.RemoteAddr = "127.0.0.1:4000"
		req.Header.Set("CF-Connecting-IP", client)
		req.Header.Set("Authorization", "Bearer nope")
		rec := httptest.NewRecorder()
		env.srv.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 20; i++ {
		do("198.51.100.1")
	}
	if do("198.51.100.1") != 429 {
		t.Fatal("the noisy client was not limited")
	}
	if c := do("198.51.100.2"); c != 401 {
		t.Fatalf("another client behind the same proxy was limited: %d", c)
	}
}

func TestStartupRefusals(t *testing.T) {
	tmp := t.TempDir()
	inbox := filepath.Join(tmp, "inbox")
	os.Mkdir(inbox, 0o700)
	var pub, kauth [core.KeySize]byte
	pub[0], kauth[0] = 1, 2
	conf := filepath.Join(tmp, "server.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf("inbox_pub: %s\nk_auth: %s\ntoken: %s\n", strictB64.EncodeToString(pub[:]), strictB64.EncodeToString(kauth[:]), testBearerToken)), 0o600)
	tokens := filepath.Join(tmp, "tokens")
	os.WriteFile(tokens, []byte("upload phone "+hashHex(uploadToken)+"\n"), 0o600)
	loose := filepath.Join(tmp, "loose")
	os.WriteFile(loose, []byte("upload phone "+hashHex(uploadToken)+"\n"), 0o644)
	broken := filepath.Join(tmp, "broken")
	os.WriteFile(broken, []byte("upload phone nothex\n"), 0o600)
	plain := filepath.Join(tmp, "plain")
	os.WriteFile(plain, []byte(testBearerToken+"\n"), 0o600)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"key material without the opt-in", []string{"--config", conf, "--inbox", inbox, "--tokens-file", tokens}, "must not hold"},
		{"opt-in without keys", []string{"--enable-server-sealing", "--tokens-file", tokens, "--inbox", inbox}, "needs --config"},
		{"no tokens at all", []string{"--inbox", inbox}, "no tokens"},
		{"loose tokens file", []string{"--tokens-file", loose, "--inbox", inbox}, "permissions"},
		{"broken tokens file", []string{"--tokens-file", broken, "--inbox", inbox}, "line 1"},
		{"bad header name", []string{"--tokens-file", tokens, "--inbox", inbox, "--client-ip-header", "bad name"}, "header name"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if code := run(c.args, &out, &errb); code == 0 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%s: code=%d stderr=%q", c.name, code, errb.String())
		}
		for _, secret := range []string{testBearerToken, uploadToken, hashHex(uploadToken)} {
			if strings.Contains(errb.String(), secret) || strings.Contains(out.String(), secret) {
				t.Errorf("%s: output repeats a token or hash", c.name)
			}
		}
	}
}

func TestLegacyTokenFileWarnsWithoutPrintingIt(t *testing.T) {
	tmp := t.TempDir()
	inbox := filepath.Join(tmp, "inbox")
	os.Mkdir(inbox, 0o700)
	plain := filepath.Join(tmp, "plain")
	os.WriteFile(plain, []byte(testBearerToken+"\n"), 0o600)
	// A bad listen address makes run return right after the config is loaded and the warning is printed.
	var out, errb bytes.Buffer
	code := run([]string{"--token-file", plain, "--inbox", inbox, "--listen", "127.0.0.1:99999"}, &out, &errb)
	if code == 0 {
		t.Fatal("unexpected success")
	}
	if !strings.Contains(errb.String(), "deprecated") {
		t.Fatalf("no deprecation warning: %q", errb.String())
	}
	if strings.Contains(errb.String(), testBearerToken) {
		t.Fatal("the warning prints the token")
	}
}

func TestReloadOnSIGHUPKeepsOldTokensOnError(t *testing.T) {
	env := sealedEnv(t, nil)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "tokens")
	write := func(s string) { os.WriteFile(path, []byte(s), 0o600) }
	write("upload phone " + hashHex(uploadToken) + "\n")
	set, err := readTokensFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	env.srv.setTokens(set)
	var logb bytes.Buffer
	var mu sync.Mutex
	logw := writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logb.Write(p) })
	stop := installReload(logw, func() error {
		t2, err := readTokensFile(path, true)
		if err != nil {
			return err
		}
		env.srv.setTokens(t2)
		return nil
	})
	defer stop()
	hup := func() {
		syscall.Kill(os.Getpid(), syscall.SIGHUP)
		time.Sleep(200 * time.Millisecond)
	}
	ping := func(tok string) int { c, _ := env.call("GET", "/v1/ping", tok, nil, nil); return c }

	if ping(uploadToken) != 204 || ping(pullToken) != 401 {
		t.Fatal("initial tokens")
	}
	// A valid new file replaces the set: the old token stops working, the new one starts.
	write("pull mac " + hashHex(pullToken) + "\n")
	hup()
	if ping(uploadToken) != 401 || ping(pullToken) != 204 {
		t.Fatal("reload did not swap the tokens")
	}
	// A broken file keeps the previous tokens and reports an error that holds no token.
	write("pull mac garbage\n")
	hup()
	if ping(pullToken) != 204 || ping(uploadToken) != 401 {
		t.Fatal("a broken file changed the tokens")
	}
	// An empty file is a valid file: it revokes every token in it (deleting the last line must not fail open).
	write("# nobody\n")
	hup()
	if ping(pullToken) != 401 {
		t.Fatal("an empty tokens file did not revoke the tokens in it")
	}
	mu.Lock()
	log := logb.String()
	mu.Unlock()
	if !strings.Contains(log, "reload failed, keeping the previous tokens") || strings.Count(log, "tokens reloaded") != 2 {
		t.Fatalf("reload log: %q", log)
	}
	for _, s := range []string{uploadToken, pullToken, hashHex(pullToken), hashHex(uploadToken)} {
		if strings.Contains(log, s) {
			t.Fatal("the reload log repeats a token or hash")
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestNoTokenOrIDInResponsesToWrongRole(t *testing.T) {
	env := sealedEnv(t, nil)
	id, file := env.sealedFile(100)
	env.call("PUT", "/inbox/"+id.String(), uploadToken, file, nil)
	_, body := env.call("GET", "/inbox/"+id.String(), uploadToken, nil, nil)
	if strings.Contains(body, id.String()) || strings.Contains(body, uploadToken) {
		t.Fatalf("a 403 body repeats the id or token: %q", body)
	}
}

func TestUploadOnlyTokenCannotUseServerSideSealing(t *testing.T) {
	opts := defaultServerOpts() // server-side sealing on, as in managed mode
	env := startTestServer(t, opts)
	env.srv.setTokens(mustTokens(t, "upload phone "+hashHex(uploadToken), "both owner "+hashHex(testBearerToken)))
	hdr := map[string]string{"X-Ndes-Name": "evil.txt"}
	if code, _ := env.call("PUT", "/inbox", uploadToken, []byte("plaintext"), hdr); code != 403 {
		t.Fatalf("an upload token reached server-side sealing: %d", code)
	}
	if ids, _, _ := env.dirH.listInboxIDs(); len(ids) != 0 {
		t.Fatal("a file was sealed for an upload-only token")
	}
	if code, _ := env.call("PUT", "/inbox", testBearerToken, []byte("plaintext"), hdr); code != 201 {
		t.Fatalf("the owner's token: %d", code)
	}
}

func TestPerTokenUploadSlotsAndNoStore(t *testing.T) {
	env := sealedEnv(t, func(o *serverOpts) { o.maxConcurrentPUTs = 8; o.ioTimeout = 3 * time.Second })
	if code, _ := env.call("GET", "/v1/ping", uploadToken, nil, nil); code != 204 {
		t.Fatal("ping")
	}
	resp, err := env.client.Get(env.baseURL + "/v1/ping")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("responses must carry Cache-Control: no-store")
	}
	// Two stalled uploads with one token fill that token's slots; a third gets 429; another token still works.
	var pipes []*io.PipeWriter
	done := make(chan struct{}, 2)
	for i := 0; i < maxUploadsPerToken; i++ {
		id, file := env.sealedFile(100)
		pr, pw := io.Pipe()
		pipes = append(pipes, pw)
		go func() {
			req, _ := http.NewRequest("PUT", env.baseURL+"/inbox/"+id.String(), pr)
			req.ContentLength = int64(len(file))
			req.Header.Set("Authorization", "Bearer "+uploadToken)
			if r, err := env.client.Do(req); err == nil {
				r.Body.Close()
			}
			done <- struct{}{}
		}()
		pw.Write([]byte("x"))
	}
	time.Sleep(300 * time.Millisecond)
	id3, file3 := env.sealedFile(100)
	if code, _ := env.call("PUT", "/inbox/"+id3.String(), uploadToken, file3, nil); code != 429 {
		t.Fatalf("a third concurrent upload for one token: %d, want 429", code)
	}
	if code, _ := env.call("PUT", "/inbox/"+id3.String(), testBearerToken, file3, nil); code != 201 {
		t.Fatalf("another token was blocked: %d", code)
	}
	for _, pw := range pipes {
		pw.CloseWithError(io.ErrClosedPipe)
	}
	for i := 0; i < maxUploadsPerToken; i++ {
		<-done
	}
	// The slots are free again.
	id4, file4 := env.sealedFile(100)
	if code, _ := env.call("PUT", "/inbox/"+id4.String(), uploadToken, file4, nil); code != 201 {
		t.Fatalf("slots not released: %d", code)
	}
}

func TestLimiterKeyUsesTheIPv6PrefixAndEvictsOneEntry(t *testing.T) {
	if limiterKey("2001:db8:1:2:aaaa::1") != limiterKey("2001:db8:1:2:bbbb::9") {
		t.Fatal("two addresses of one /64 got different buckets")
	}
	if limiterKey("2001:db8:1:2::1") == limiterKey("2001:db8:1:3::1") {
		t.Fatal("different /64 prefixes share a bucket")
	}
	if limiterKey("::ffff:203.0.113.9") != "203.0.113.9" || limiterKey("203.0.113.9") != "203.0.113.9" {
		t.Fatal("IPv4 key")
	}
	l := newIPRateLimiter(2, time.Hour)
	now := time.Now()
	for i := 0; i < maxRateLimiterTrackedIPs; i++ {
		l.allow(fmt.Sprintf("k%d", i), now.Add(time.Duration(i)*time.Millisecond))
	}
	l.allow("victim", now.Add(time.Hour*0+time.Second))
	l.allow("victim", now.Add(time.Second))
	l.allow("new", now.Add(2*time.Second)) // map is full: one old entry goes, not all of them
	if len(l.buckets) < maxRateLimiterTrackedIPs-1 {
		t.Fatalf("the limiter forgot %d clients at once", maxRateLimiterTrackedIPs-len(l.buckets))
	}
}

func TestSIGHUPDoesNotStopAServerWithoutATokensFile(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "ndesd")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Skipf("cannot build: %v %s", err, out)
	}
	tmp := t.TempDir()
	inbox := filepath.Join(tmp, "inbox")
	os.Mkdir(inbox, 0o700)
	tok := filepath.Join(tmp, "tok")
	os.WriteFile(tok, []byte(testBearerToken+"\n"), 0o600)
	cmd := exec.Command(bin, "--token-file", tok, "--inbox", inbox, "--listen", "127.0.0.1:0")
	var errb safeBuffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	for i := 0; i < 100 && !strings.Contains(errb.String(), "listening on"); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	syscall.Kill(cmd.Process.Pid, syscall.SIGHUP)
	time.Sleep(300 * time.Millisecond)
	if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
		t.Fatalf("SIGHUP stopped the server: %v", err)
	}
	if !strings.Contains(errb.String(), "nothing to reload") {
		t.Fatalf("log: %q", errb.String())
	}
	if strings.Contains(errb.String(), testBearerToken) {
		t.Fatal("the log holds the token")
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
