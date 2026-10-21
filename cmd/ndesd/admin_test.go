package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type adminEnv struct {
	t   *testing.T
	m   *manager
	srv *adminServer
	dir string
	ck  *http.Cookie
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	m, err := newManager(dir, "127.0.0.1:8485", false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.shutdown(); m.dir.Close() })
	return &adminEnv{t: t, m: m, srv: newAdminServer(m, false), dir: dir}
}

func (e *adminEnv) do(method, path, remote string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = remote
	if method != http.MethodGet {
		r.Header.Set("X-Ndes-Admin", "1")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if e.ck != nil {
		r.AddCookie(e.ck)
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge >= 0 {
			e.ck = c
		}
	}
	return w
}

func (e *adminEnv) ok(method, path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	w := e.do(method, path, "127.0.0.1:5555", body, nil)
	if w.Code != 200 {
		e.t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
	}
	return w
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func randKeyText(t *testing.T) string {
	var a, b [32]byte
	rand.Read(a[:])
	rand.Read(b[:])
	e := base64.StdEncoding
	return "inbox_pub: " + e.EncodeToString(a[:]) + "\nk_auth: " + e.EncodeToString(b[:]) + "\n"
}

func TestAdminRefusesPublicAndProxied(t *testing.T) {
	e := newAdminEnv(t)
	for _, remote := range []string{"8.8.8.8:1234", "[2001:4860::1]:1"} {
		if w := e.do("GET", "/api/state", remote, nil, nil); w.Code != 403 {
			t.Errorf("%s: want 403, got %d", remote, w.Code)
		}
		if w := e.do("GET", "/", remote, nil, nil); w.Code != 403 {
			t.Errorf("static from %s: want 403, got %d", remote, w.Code)
		}
	}
	for _, remote := range []string{"127.0.0.1:1", "10.1.2.3:1", "192.168.1.5:1", "100.101.102.103:1", "172.17.0.1:1", "[::1]:1", "[fd7a:115c:a1e0::1]:1"} {
		if w := e.do("GET", "/api/state", remote, nil, nil); w.Code != 200 {
			t.Errorf("%s: want 200, got %d", remote, w.Code)
		}
	}
	if w := e.do("GET", "/api/state", "127.0.0.1:1", nil, map[string]string{"X-Forwarded-For": "8.8.8.8"}); w.Code != 403 {
		t.Errorf("proxied request must be refused, got %d", w.Code)
	}
}

func TestAdminSetupLoginFlow(t *testing.T) {
	e := newAdminEnv(t)
	code, err := e.m.ensureSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	if w := e.do("POST", "/api/setup", "127.0.0.1:1", map[string]string{"code": "WRONG-CODE0", "password": "correct horse battery"}, nil); w.Code != 403 {
		t.Fatalf("wrong code: %d", w.Code)
	}
	if w := e.do("POST", "/api/setup", "127.0.0.1:1", map[string]string{"code": code, "password": "short"}, nil); w.Code != 400 {
		t.Fatalf("short password: %d", w.Code)
	}
	e.ok("POST", "/api/setup", map[string]string{"code": strings.ToLower(code), "password": "correct horse battery"})
	if _, err := os.Stat(e.m.path(setupCodeFile)); err == nil {
		t.Fatal("setup code should be removed after use")
	}
	if w := e.do("POST", "/api/setup", "127.0.0.1:1", map[string]string{"code": code, "password": "another long password"}, nil); w.Code != 409 {
		t.Fatalf("second setup must be refused: %d", w.Code)
	}
	e.ok("GET", "/api/status", nil) // setup logged us in

	// fresh browser: unauthenticated until login
	e.ck = nil
	if w := e.do("GET", "/api/status", "127.0.0.1:1", nil, nil); w.Code != 401 {
		t.Fatalf("unauthenticated status: %d", w.Code)
	}
	if w := e.do("POST", "/api/login", "127.0.0.1:1", map[string]string{"password": "nope nope nope"}, nil); w.Code != 401 {
		t.Fatalf("wrong password: %d", w.Code)
	}
	e.ok("POST", "/api/login", map[string]string{"password": "correct horse battery"})
	e.ok("GET", "/api/status", nil)
	e.ok("POST", "/api/logout", map[string]string{})
}

func TestAdminCSRFGuards(t *testing.T) {
	e := newAdminEnv(t)
	e.m.setPassword("correct horse battery")
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"correct horse battery"}`))
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("POST without X-Ndes-Admin must be refused, got %d", w.Code)
	}
	w = e.do("POST", "/api/login", "127.0.0.1:1", map[string]string{"password": "correct horse battery"}, map[string]string{"Origin": "http://evil.example"})
	if w.Code != 403 {
		t.Fatalf("cross-origin POST must be refused, got %d", w.Code)
	}
}

func TestAdminLinkConfigureAndRun(t *testing.T) {
	e := newAdminEnv(t)
	e.m.setPassword("correct horse battery")
	e.ok("POST", "/api/login", map[string]string{"password": "correct horse battery"})

	if w := e.do("POST", "/api/keys", "127.0.0.1:1", map[string]string{"text": "inbox_pub: nope"}, nil); w.Code != 400 {
		t.Fatalf("bad keys: %d", w.Code)
	}
	e.ok("POST", "/api/keys", map[string]string{"text": randKeyText(t)})

	fi, err := os.Stat(e.m.path(confFileName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("server.conf mode: %v %v", fi, err)
	}
	var tok struct{ Token string }
	json.Unmarshal(e.ok("GET", "/api/token", nil).Body.Bytes(), &tok)
	if len(tok.Token) < minTokenLen {
		t.Fatalf("token too short: %q", tok.Token)
	}

	settings := map[string]any{"listen": freeAddr(t), "max_upload_bytes": 10 << 20, "max_inbox_files": 5, "max_concurrent_uploads": 2}
	w := e.ok("POST", "/api/settings", settings)
	var st syncStatus
	json.Unmarshal(w.Body.Bytes(), &st)
	if !st.Running || !st.Linked {
		t.Fatalf("expected running+linked, got %+v", st)
	}

	// The sync server answers with the token it generated, and rejects others.
	url := "http://" + st.Addr + "/inbox"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("sync GET /inbox: %v %v", resp, err)
	}
	resp.Body.Close()
	req.Header.Set("Authorization", "Bearer wrong")
	if resp, _ = http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatalf("wrong token must be 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// New token invalidates the old one on the running server.
	var nt struct{ Token string }
	json.Unmarshal(e.ok("POST", "/api/token/regenerate", map[string]string{}).Body.Bytes(), &nt)
	st = e.m.status()
	req, _ = http.NewRequest("GET", "http://"+st.Addr+"/inbox", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	if resp, _ = http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatalf("old token must be rejected, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Stop persists; start again.
	e.ok("POST", "/api/server/stop", map[string]string{})
	if e.m.status().Running || !e.m.status().Stopped {
		t.Fatal("expected stopped")
	}
	e.ok("POST", "/api/server/start", map[string]string{})
	if !e.m.status().Running {
		t.Fatal("expected running")
	}

	// Inbox listing and delete.
	id := "4f8a9c1e2b3d4e5f60718293a4b5c6d7"
	os.WriteFile(filepath.Join(e.dir, inboxDirName, id+".inb"), []byte("sealed"), 0o600)
	var status struct {
		Files     []inboxFile `json:"files"`
		FileCount int         `json:"file_count"`
	}
	json.Unmarshal(e.ok("GET", "/api/status", nil).Body.Bytes(), &status)
	if status.FileCount != 1 || status.Files[0].ID != id {
		t.Fatalf("listing: %+v", status)
	}
	e.ok("DELETE", "/api/inbox/"+id, nil)
	if w := e.do("DELETE", "/api/inbox/../../etc/passwd", "127.0.0.1:1", nil, nil); w.Code == 200 {
		t.Fatal("path traversal id accepted")
	}
}

func TestSettingsValidation(t *testing.T) {
	good := defaultSyncSettings("127.0.0.1:8485")
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*syncSettings){
		"plain http public": func(s *syncSettings) { s.Listen = "0.0.0.0:8485" },
		"bad port":          func(s *syncSettings) { s.Listen = "127.0.0.1:99999" },
		"hostname":          func(s *syncSettings) { s.Listen = "example.com:8485" },
		"half tls":          func(s *syncSettings) { s.TLSCert = "/x" },
		"tiny upload":       func(s *syncSettings) { s.MaxUploadBytes = 10 },
		"zero files":        func(s *syncSettings) { s.MaxInboxFiles = 0 },
	}
	for name, mut := range cases {
		s := good
		mut(&s)
		if s.validate() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	s := good
	s.Listen, s.AckPlainHTTP = "100.64.1.2:8485", true
	if err := s.validate(); err != nil {
		t.Errorf("acknowledged plain http should pass: %v", err)
	}
}

func TestRunManagedRefusesPublicBind(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--data", t.TempDir(), "--admin-listen", "8.8.8.8:8080"}, &out, &errb)
	if code == 0 || !strings.Contains(errb.String(), "public address") {
		t.Fatalf("expected refusal, got %d %q", code, errb.String())
	}
}

func TestAdminBehindProxy(t *testing.T) {
	e := newAdminEnv(t)
	e.srv.behindProxy = true
	h := map[string]string{"X-Forwarded-For": "8.8.8.8", "Cf-Connecting-Ip": "8.8.8.8"}
	if w := e.do("GET", "/api/state", "127.0.0.1:1", nil, h); w.Code != 200 {
		t.Fatalf("tunnel from localhost must work, got %d", w.Code)
	}
	if w := e.do("GET", "/api/state", "8.8.8.8:1", nil, h); w.Code != 403 {
		t.Fatalf("direct public peer must still be refused, got %d", w.Code)
	}
}

func TestAdminSetupDone(t *testing.T) {
	e := newAdminEnv(t)
	e.m.setPassword("correct horse battery")
	if w := e.do("POST", "/api/setup/finish", "127.0.0.1:1", map[string]string{}, nil); w.Code != 401 {
		t.Fatalf("finish without a session: %d", w.Code)
	}
	e.ok("POST", "/api/login", map[string]string{"password": "correct horse battery"})
	var st struct {
		Sync struct {
			SetupDone bool `json:"setup_done"`
		} `json:"sync"`
	}
	json.Unmarshal(e.ok("GET", "/api/status", nil).Body.Bytes(), &st)
	if st.Sync.SetupDone {
		t.Fatal("a fresh install must not start as set up")
	}
	e.ok("POST", "/api/keys", map[string]string{"text": randKeyText(t)})
	e.ok("POST", "/api/setup/finish", map[string]string{})
	json.Unmarshal(e.ok("GET", "/api/status", nil).Body.Bytes(), &st)
	if !st.Sync.SetupDone {
		t.Fatal("setup_done not reported after finish")
	}

	// A restart in the middle of the guided setup keeps it unfinished.
	e.m.mu.Lock()
	e.m.state.SetupDone = false
	e.m.saveStateLocked()
	e.m.mu.Unlock()
	mid, err := newManager(e.dir, "127.0.0.1:8485", false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if mid.status().SetupDone {
		t.Fatal("restart mid-setup must not count as finished")
	}
	mid.dir.Close()

	// An install linked before the guided setup existed counts as set up.
	e.m.shutdown()
	data, _ := os.ReadFile(e.m.path(stateFileName))
	var raw map[string]any
	json.Unmarshal(data, &raw)
	delete(raw, "setup_done")
	data, _ = json.Marshal(raw)
	os.WriteFile(e.m.path(stateFileName), data, 0o600)
	e.m.dir.Close()
	m2, err := newManager(e.dir, "127.0.0.1:8485", false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.dir.Close()
	if !m2.status().SetupDone {
		t.Fatal("linked install without the field should load as set up")
	}
}
