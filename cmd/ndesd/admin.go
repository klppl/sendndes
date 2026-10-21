package main

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

//go:embed web
var webFS embed.FS

const (
	sessionCookie  = "ndesd_session"
	sessionTTL     = 12 * time.Hour
	maxAdminBody   = 64 << 10
	maxListedFiles = 200
)

func hashPassword(pw string, salt []byte) []byte {
	return argon2.IDKey([]byte(pw), salt, 3, 64*1024, 2, 32)
}

func constantTimeEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func tlsConfig13() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS13} }

// cgnat is the Tailscale address range 100.64.0.0/10.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// privateAddr reports whether ip is something the public internet cannot be:
// loopback, link-local, RFC 1918 / ULA (which includes Tailscale's fd7a: range),
// or the Tailscale CGNAT range.
func privateAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}

// adminServer is the owner-only web GUI. It is never reachable from the public
// internet by default: requests from public addresses (or carrying proxy
// headers) are refused before anything else happens, on top of the password.
type adminServer struct {
	m           *manager
	allowPublic bool
	behindProxy bool // trust a reverse proxy / tunnel on this host or private network
	loginRL     *ipRateLimiter
	setupRL     *ipRateLimiter
	static      http.Handler

	mu       sync.Mutex
	sessions map[string]time.Time
}

func newAdminServer(m *manager, allowPublic bool) *adminServer {
	sub, _ := fs.Sub(webFS, "web")
	return &adminServer{
		m:           m,
		allowPublic: allowPublic,
		loginRL:     newIPRateLimiter(5, 10*time.Second),
		setupRL:     newIPRateLimiter(5, 10*time.Second),
		static:      http.FileServerFS(sub),
		sessions:    map[string]time.Time{},
	}
}

func (a *adminServer) allowed(r *http.Request) bool {
	if a.allowPublic {
		return true
	}
	// A reverse proxy in front of the admin GUI would make every request look
	// local; refuse anything that announces itself as proxied, unless the
	// owner said the GUI sits behind one (then access control is the proxy's,
	// for example Cloudflare Access, plus the password).
	for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "Forwarded"} {
		if r.Header.Get(h) != "" && !a.behindProxy {
			return false
		}
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	return privateAddr(ap.Addr())
}

// clientKey identifies the caller for rate limiting. Behind a trusted proxy
// every connection comes from the proxy, so use the address it reports.
func (a *adminServer) clientKey(r *http.Request) string {
	if a.behindProxy {
		if v := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); v != "" && len(v) < 64 {
			return v
		}
	}
	return clientIP(r.RemoteAddr)
}

func (a *adminServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	if !a.allowed(r) {
		httpError(w, http.StatusForbidden, "this page is only reachable from the server itself, your local network or Tailscale")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		a.static.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet {
		// Browsers cannot send a custom header cross-origin without a
		// preflight we never grant, so this blocks cross-site request forgery.
		if r.Header.Get("X-Ndes-Admin") != "1" {
			httpError(w, http.StatusForbidden, "missing X-Ndes-Admin header")
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !strings.HasSuffix(o, "://"+r.Host) {
			httpError(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	a.route(w, r)
}

func (a *adminServer) route(w http.ResponseWriter, r *http.Request) {
	p, method := r.URL.Path, r.Method
	switch {
	case p == "/api/state" && method == http.MethodGet:
		a.handleState(w, r)
	case p == "/api/setup" && method == http.MethodPost:
		a.handleSetup(w, r)
	case p == "/api/login" && method == http.MethodPost:
		a.handleLogin(w, r)
	case p == "/api/logout" && method == http.MethodPost:
		a.handleLogout(w, r)
	default:
		if !a.authed(r) {
			apiErr(w, http.StatusUnauthorized, "please sign in")
			return
		}
		a.routeAuthed(w, r, p, method)
	}
}

func (a *adminServer) routeAuthed(w http.ResponseWriter, r *http.Request, p, method string) {
	switch {
	case p == "/api/status" && method == http.MethodGet:
		a.handleStatus(w, r)
	case p == "/api/interfaces" && method == http.MethodGet:
		writeJSON(w, http.StatusOK, listInterfaces())
	case p == "/api/keys" && method == http.MethodPost:
		a.handleKeys(w, r)
	case p == "/api/token" && method == http.MethodGet:
		tok, err := a.m.token()
		if err != nil {
			apiErr(w, http.StatusConflict, "link your vault first")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": tok})
	case p == "/api/token/regenerate" && method == http.MethodPost:
		tok, err := a.m.regenerateToken()
		if err != nil && tok == "" {
			apiErr(w, http.StatusConflict, err.Error())
			return
		}
		resp := map[string]string{"token": tok}
		if err != nil {
			resp["warning"] = err.Error()
		}
		writeJSON(w, http.StatusOK, resp)
	case p == "/api/settings" && method == http.MethodPost:
		a.handleSettings(w, r)
	case p == "/api/server/start" && method == http.MethodPost:
		a.serverAction(w, a.m.start)
	case p == "/api/server/stop" && method == http.MethodPost:
		a.serverAction(w, a.m.stop)
	case p == "/api/server/restart" && method == http.MethodPost:
		a.serverAction(w, a.m.restart)
	case p == "/api/setup/finish" && method == http.MethodPost:
		if err := a.m.finishSetup(); err != nil {
			apiErr(w, http.StatusInternalServerError, "could not save")
			return
		}
		writeJSON(w, http.StatusOK, a.m.status())
	case p == "/api/password" && method == http.MethodPost:
		a.handlePassword(w, r)
	case strings.HasPrefix(p, "/api/inbox/") && method == http.MethodDelete:
		if err := a.m.deleteFile(strings.TrimPrefix(p, "/api/inbox/")); err != nil {
			apiErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		apiErr(w, http.StatusNotFound, "not found")
	}
}

func (a *adminServer) serverAction(w http.ResponseWriter, fn func() error) {
	if err := fn(); err != nil {
		apiErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a.m.status())
}

// ---- sessions ----

func (a *adminServer) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(a.sessions, c.Value)
		return false
	}
	return true
}

func (a *adminServer) startSession(w http.ResponseWriter, r *http.Request) error {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	now := time.Now()
	a.mu.Lock()
	for k, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, k)
		}
	}
	a.sessions[tok] = now.Add(sessionTTL)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || (a.behindProxy && r.Header.Get("X-Forwarded-Proto") == "https"),
		MaxAge: int(sessionTTL.Seconds()),
	})
	return nil
}

func (a *adminServer) endSessions(keep string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k := range a.sessions {
		if k != keep {
			delete(a.sessions, k)
		}
	}
}

// ---- handlers ----

func (a *adminServer) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"setup_needed": !a.m.hasPassword(),
		"authed":       a.authed(r),
	})
}

func (a *adminServer) handleSetup(w http.ResponseWriter, r *http.Request) {
	if a.m.hasPassword() {
		apiErr(w, http.StatusConflict, "already set up")
		return
	}
	if !a.setupRL.allow(a.clientKey(r), time.Now()) {
		apiErr(w, http.StatusTooManyRequests, "too many attempts, wait a minute")
		return
	}
	var req struct{ Code, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	want := a.m.readSetupCode()
	got := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(req.Code), " ", ""))
	if want == "" || !constantTimeEqual([]byte(got), []byte(want)) {
		apiErr(w, http.StatusForbidden, "that setup code is not right")
		return
	}
	if err := a.m.setPassword(req.Password); err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.m.clearSetupCode()
	if err := a.startSession(w, r); err != nil {
		apiErr(w, http.StatusInternalServerError, "could not start a session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *adminServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !a.m.hasPassword() {
		apiErr(w, http.StatusConflict, "set a password first")
		return
	}
	if !a.loginRL.allow(a.clientKey(r), time.Now()) {
		apiErr(w, http.StatusTooManyRequests, "too many attempts, wait a minute")
		return
	}
	var req struct{ Password string }
	if !readJSON(w, r, &req) {
		return
	}
	if !a.m.checkPassword(req.Password) {
		apiErr(w, http.StatusUnauthorized, "wrong password")
		return
	}
	if err := a.startSession(w, r); err != nil {
		apiErr(w, http.StatusInternalServerError, "could not start a session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *adminServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *adminServer) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Current, New string }
	if !readJSON(w, r, &req) {
		return
	}
	if !a.loginRL.allow(a.clientKey(r), time.Now()) {
		apiErr(w, http.StatusTooManyRequests, "too many attempts, wait a minute")
		return
	}
	if !a.m.checkPassword(req.Current) {
		apiErr(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if err := a.m.setPassword(req.New); err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cur := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		cur = c.Value
	}
	a.endSessions(cur)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *adminServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	var req struct{ Text string }
	if !readJSON(w, r, &req) {
		return
	}
	if err := a.m.setKeys(req.Text); err != nil {
		// The keys were saved if the server merely failed to start; the
		// status panel shows the start error.
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a.m.status())
}

func (a *adminServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	var s syncSettings
	if !readJSON(w, r, &s) {
		return
	}
	if err := s.validate(); err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.TLSCert != "" {
		if _, err := tls.LoadX509KeyPair(s.TLSCert, s.TLSKey); err != nil {
			apiErr(w, http.StatusBadRequest, "TLS certificate or key could not be loaded: "+err.Error())
			return
		}
		if _, err := readProtectedFile(s.TLSKey); err != nil {
			apiErr(w, http.StatusBadRequest, "TLS key: "+err.Error())
			return
		}
	}
	if err := a.m.setSettings(s); err != nil {
		apiErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a.m.status())
}

func (a *adminServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	files, err := a.m.listFiles()
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "could not read the inbox")
		return
	}
	var total int64
	for _, f := range files {
		total += f.Size
	}
	count := len(files)
	if len(files) > maxListedFiles {
		files = files[:maxListedFiles]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sync":       a.m.status(),
		"files":      files,
		"file_count": count,
		"file_bytes": total,
		"free_bytes": a.m.freeBytes(),
	})
}

// ---- helpers ----

type ifaceInfo struct {
	Addr  string `json:"addr"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // loopback | tailscale | lan | public | all
}

func listInterfaces() []ifaceInfo {
	out := []ifaceInfo{{Addr: "127.0.0.1", Label: "This machine only", Kind: "loopback"}}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok || !ip.Unmap().Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		ip = ip.Unmap()
		switch {
		case cgnat.Contains(ip):
			out = append(out, ifaceInfo{ip.String(), "Tailscale", "tailscale"})
		case ip.IsPrivate():
			out = append(out, ifaceInfo{ip.String(), "Local network", "lan"})
		default:
			out = append(out, ifaceInfo{ip.String(), "Public address", "public"})
		}
	}
	out = append(out, ifaceInfo{"0.0.0.0", "Every network interface", "all"})
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) || errors.Is(err, io.ErrUnexpectedEOF) {
			apiErr(w, http.StatusBadRequest, "request too large or incomplete")
		} else {
			apiErr(w, http.StatusBadRequest, "invalid request")
		}
		return false
	}
	return true
}
