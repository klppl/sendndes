package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klppl/sendndes/core"
	"golang.org/x/sys/unix"
)

// Managed mode: ndesd keeps everything under one data directory and is set up
// from the admin web GUI instead of flags.
//
//	<data>/server.conf   inbox_pub, k_auth, token (mode 0600)
//	<data>/tokens        optional: more tokens with roles, one "<role> <label> <sha256-hex>" per line (mode 0600);
//	                     reloaded on SIGHUP. Managed mode holds inbox_pub and k_auth (they are pasted in the web
//	                     GUI), so it always has server-side sealing; for a server that holds no keys, use
//	                     classic mode with --tokens-file.
//	<data>/admin.json    admin password hash and sync settings (mode 0600)
//	<data>/inbox/        the sealed .inb files
const (
	confFileName   = "server.conf"
	stateFileName  = "admin.json"
	inboxDirName   = "inbox"
	setupCodeFile  = "setup-code"
	tokensFileName = "tokens"
)

// syncSettings are the owner-editable settings of the sync (Mode B) server.
type syncSettings struct {
	Listen               string `json:"listen"`
	TLSCert              string `json:"tls_cert,omitempty"`
	TLSKey               string `json:"tls_key,omitempty"`
	AckPlainHTTP         bool   `json:"ack_plain_http,omitempty"`
	MaxUploadBytes       int64  `json:"max_upload_bytes"`
	MaxInboxFiles        int    `json:"max_inbox_files"`
	MaxConcurrentUploads int    `json:"max_concurrent_uploads"`
}

func defaultSyncSettings(listen string) syncSettings {
	return syncSettings{
		Listen:               listen,
		MaxUploadBytes:       1 << 30,
		MaxInboxFiles:        100,
		MaxConcurrentUploads: defaultMaxConcurrentPUTs,
	}
}

func (s syncSettings) validate() error {
	host, port, err := net.SplitHostPort(s.Listen)
	if err != nil {
		return errors.New("listen address must look like host:port, for example 127.0.0.1:8485")
	}
	if host != "" && net.ParseIP(host) == nil && !strings.EqualFold(host, "localhost") {
		return errors.New("listen address must be an IP address")
	}
	n, err := net.LookupPort("tcp", port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("sync port must be between 1 and 65535")
	}
	if (s.TLSCert == "") != (s.TLSKey == "") {
		return errors.New("TLS certificate and key must be given together")
	}
	if s.TLSCert == "" && !isLoopbackListen(s.Listen) && !s.AckPlainHTTP {
		return errors.New("plain HTTP on a non-loopback address needs the confirmation box ticked (or a TLS certificate)")
	}
	if s.MaxUploadBytes < 1<<20 {
		return errors.New("max upload size must be at least 1 MiB")
	}
	if s.MaxInboxFiles < 1 || s.MaxInboxFiles > 1_000_000 {
		return errors.New("max files waiting must be between 1 and 1000000")
	}
	if s.MaxConcurrentUploads < 1 || s.MaxConcurrentUploads > 64 {
		return errors.New("concurrent uploads must be between 1 and 64")
	}
	return nil
}

// adminState is the persistent admin.json.
type adminState struct {
	PassSalt string `json:"pass_salt,omitempty"`
	PassHash string `json:"pass_hash,omitempty"`
	Stopped  bool   `json:"stopped,omitempty"` // owner stopped the sync server on purpose
	// SetupDone: the owner finished the guided setup in the web GUI (only steers which screen it shows).
	// Always written, so a file without the key is one from before the guided setup existed.
	SetupDone bool         `json:"setup_done"`
	Sync      syncSettings `json:"sync"`
}

type manager struct {
	dataDir string
	dir     *dirHandle
	reg     *tempRegistry
	stderr  io.Writer

	mu      sync.Mutex
	state   adminState
	run     *runningSync
	lastErr string

	defaultListen string
	ackDefault    bool

	tokens  *tokenStore // <data>/tokens: hashes of every device that was approved
	pair    *pairing
	handler atomic.Pointer[inboxServer]
}

type runningSync struct {
	srv     *http.Server
	handler *inboxServer
	cancel  context.CancelFunc
	done    chan struct{}
	addr    string
	tls     bool
}

func newManager(dataDir string, defaultListen string, ackDefault bool, stderr io.Writer) (*manager, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dataDir, inboxDirName), 0o700); err != nil {
		return nil, err
	}
	dir, err := openInboxDir(filepath.Join(dataDir, inboxDirName), stderr)
	if err != nil {
		return nil, err
	}
	m := &manager{dataDir: dataDir, dir: dir, reg: newTempRegistry(), stderr: stderr, defaultListen: defaultListen, ackDefault: ackDefault}
	m.tokens = newTokenStore(filepath.Join(dataDir, tokensFileName), nil, func(ts *tokenSet) {
		if h := m.handler.Load(); h != nil {
			h.setTokens(ts)
		}
	})
	m.pair = newPairing(m.tokens)
	m.state.Sync = defaultSyncSettings(defaultListen)
	m.state.Sync.AckPlainHTTP = ackDefault
	legacy := false
	data, err := os.ReadFile(filepath.Join(dataDir, stateFileName))
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &m.state); err != nil {
			dir.Close()
			return nil, fmt.Errorf("%s: %w", stateFileName, err)
		}
		var keys map[string]json.RawMessage
		if json.Unmarshal(data, &keys) == nil {
			_, hasSetupDone := keys["setup_done"]
			legacy = !hasSetupDone
		}
	case !errors.Is(err, os.ErrNotExist):
		dir.Close()
		return nil, err
	}
	// Installs linked before the guided setup existed have nothing left to set up.
	if legacy && m.configured() {
		m.state.SetupDone = true
	}
	return m, nil
}

// finishSetup records that the owner went through the guided setup.
func (m *manager) finishSetup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.SetupDone = true
	return m.saveStateLocked()
}

func (m *manager) path(name string) string { return filepath.Join(m.dataDir, name) }

// writePrivate atomically writes data to <data>/name with mode 0600.
func (m *manager) writePrivate(name string, data []byte) error {
	tmp, err := os.CreateTemp(m.dataDir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), m.path(name))
}

// saveStateLocked persists admin.json. Caller holds m.mu.
func (m *manager) saveStateLocked() error {
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return m.writePrivate(stateFileName, append(data, '\n'))
}

// configured reports whether the vault's server keys were pasted (server-side sealing is then possible). The
// server itself runs either way: devices pair with it and upload files they sealed themselves.
func (m *manager) configured() bool {
	cfg, err := m.readConfig()
	if err != nil {
		return false
	}
	defer cfg.Wipe()
	return cfg.HasKeys
}

// readConfig loads server.conf, which may be missing or hold no keys.
func (m *manager) readConfig() (*serverConfig, error) {
	return loadManagedConfig(m.path(confFileName))
}

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// writeConfig stores keys and token as server.conf.
func (m *manager) writeConfig(cfg *serverConfig) error {
	b64 := base64.StdEncoding
	out := ""
	if cfg.HasKeys {
		out += fmt.Sprintf("inbox_pub: %s\nk_auth: %s\n", b64.EncodeToString(cfg.InboxPub[:]), b64.EncodeToString(cfg.KAuth[:]))
	}
	if len(cfg.Token) > 0 {
		out += fmt.Sprintf("token: %s\n", cfg.Token)
	}
	return m.writePrivate(confFileName, []byte(out))
}

// setKeys installs pasted `inbox_pub:` / `k_auth:` text. It keeps the existing
// token, or generates one on first setup.
func (m *manager) setKeys(text string) error {
	if len(text) > maxServerConfigSize {
		return errors.New("that is too long to be the server keys")
	}
	pasted, err := parseServerConfigBytes([]byte(text))
	if err != nil {
		return fmt.Errorf("could not read the server keys: %w", err)
	}
	defer pasted.Wipe()
	m.mu.Lock()
	defer m.mu.Unlock()
	token := pasted.Token
	if len(token) == 0 {
		if old, err := m.readConfig(); err == nil {
			token = append([]byte(nil), old.Token...)
			old.Wipe()
		}
		if len(token) == 0 {
			t, err := newToken()
			if err != nil {
				return err
			}
			token = []byte(t)
		}
	}
	pasted.Token = token
	if err := m.writeConfig(pasted); err != nil {
		return err
	}
	m.state.Stopped = false
	if err := m.saveStateLocked(); err != nil {
		return err
	}
	// The keys are saved. If the server cannot start (port taken, bad
	// settings) the reason is shown in the status panel, not as a failed save.
	_ = m.restartLocked()
	return nil
}

// regenerateToken replaces the bearer token; every client must be updated.
func (m *manager) regenerateToken() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := m.readConfig()
	if err != nil || !cfg.HasKeys {
		return "", errors.New("link your vault first")
	}
	defer cfg.Wipe()
	t, err := newToken()
	if err != nil {
		return "", err
	}
	cfg.Token = []byte(t)
	if err := m.writeConfig(cfg); err != nil {
		return "", err
	}
	if m.run != nil {
		if err := m.restartLocked(); err != nil {
			return t, err
		}
	}
	return t, nil
}

func (m *manager) token() (string, error) {
	cfg, err := m.readConfig()
	if err != nil {
		return "", err
	}
	defer cfg.Wipe()
	if len(cfg.Token) == 0 {
		return "", errors.New("this server has no shared token: devices connect from the Devices card")
	}
	return string(cfg.Token), nil
}

// keyFingerprint is a short, non-secret check value of inbox_pub so the owner
// can see the server holds the keys of the vault they expect.
func (m *manager) keyFingerprint() string {
	cfg, err := m.readConfig()
	if err != nil || !cfg.HasKeys {
		return ""
	}
	defer cfg.Wipe()
	sum := sha256.Sum256(cfg.InboxPub[:])
	h := strings.ToUpper(hex.EncodeToString(sum[:4]))
	return h[:4] + "-" + h[4:]
}

func (m *manager) setSettings(s syncSettings) error {
	if err := s.validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.state.Sync
	m.state.Sync = s
	if err := m.saveStateLocked(); err != nil {
		m.state.Sync = old
		return err
	}
	if m.run != nil {
		return m.restartLocked()
	}
	return nil
}

// start launches the sync server if the vault is linked and it is not stopped.
func (m *manager) start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.Stopped = false
	if err := m.saveStateLocked(); err != nil {
		return err
	}
	return m.startLocked()
}

func (m *manager) stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.Stopped = true
	if err := m.saveStateLocked(); err != nil {
		return err
	}
	m.stopLocked()
	return nil
}

func (m *manager) restart() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restartLocked()
}

func (m *manager) restartLocked() error {
	m.stopLocked()
	if m.state.Stopped {
		return nil
	}
	return m.startLocked()
}

func (m *manager) startLocked() error {
	if m.run != nil {
		return nil
	}
	m.lastErr = ""
	fail := func(err error) error {
		m.lastErr = err.Error()
		return err
	}
	cfg, err := m.readConfig()
	if err != nil {
		return fail(err)
	}
	s := m.state.Sync
	if err := s.validate(); err != nil {
		cfg.Wipe()
		return fail(err)
	}
	useTLS := s.TLSCert != ""
	if useTLS {
		if _, err := readProtectedFile(s.TLSKey); err != nil {
			cfg.Wipe()
			return fail(fmt.Errorf("TLS key: %w", err))
		}
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		cfg.Wipe()
		return fail(fmt.Errorf("cannot listen on %s: %w", s.Listen, err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := newInboxServer(ctx, m.dir, m.reg, cfg, serverOpts{
		maxUploadBytes:    s.MaxUploadBytes,
		ioTimeout:         defaultIOTimeout,
		writeTimeout:      defaultWriteTimeout,
		maxConcurrentPUTs: s.MaxConcurrentUploads,
		maxConcurrentReqs: defaultMaxConcurrentReqs,
		maxInboxFiles:     s.MaxInboxFiles,
		slotWaitTimeout:   defaultSlotWaitTimeout,

		// Only if the owner pasted the vault's keys (an advanced choice): otherwise the server holds none.
		enableServerSealing: cfg.HasKeys,
		clientIPHeader:      os.Getenv("NDESD_CLIENT_IP_HEADER"),
	})
	var legacy *tokenSet
	if len(cfg.Token) > 0 {
		legacy = legacyTokenSet(cfg.Token)
	}
	cfg.Wipe()
	m.tokens.setLegacy(legacy)
	h.setPairing(m.pair)
	m.handler.Store(h)
	if terr := m.tokens.loadApply(); terr != nil {
		m.handler.Store(nil)
		cancel()
		_ = ln.Close()
		h.Wipe()
		return fail(fmt.Errorf("tokens file: %w", terr))
	}
	srv := newHTTPServer(h)
	r := &runningSync{srv: srv, handler: h, cancel: cancel, done: make(chan struct{}), addr: ln.Addr().String(), tls: useTLS}
	m.run = r
	go func() {
		defer close(r.done)
		var err error
		if useTLS {
			srv.TLSConfig = tlsConfig13()
			err = srv.ServeTLS(ln, s.TLSCert, s.TLSKey)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.mu.Lock()
			if m.run == r {
				m.lastErr = err.Error()
			}
			m.mu.Unlock()
		}
	}()
	fmt.Fprintf(m.stderr, "ndesd: sync server listening on %s\n", r.addr)
	return nil
}

// reloadTokens re-reads server.conf's token and <data>/tokens into the running server (SIGHUP). On any
// error the running server keeps what it has.
func (m *manager) reloadTokens() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.run == nil {
		return errNothingToReload
	}
	cfg, err := m.readConfig()
	if err != nil {
		return err
	}
	var legacy *tokenSet
	if len(cfg.Token) > 0 {
		legacy = legacyTokenSet(cfg.Token)
	}
	cfg.Wipe()
	m.tokens.setLegacy(legacy)
	return m.tokens.loadApply()
}

func (m *manager) stopLocked() {
	m.handler.Store(nil)
	r := m.run
	if r == nil {
		return
	}
	m.run = nil
	r.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.srv.Shutdown(ctx); err != nil {
		_ = r.srv.Close()
	}
	<-r.done
	r.handler.Wipe()
}

// shutdown stops everything and wipes secrets (called on signals and exit).
func (m *manager) shutdown() {
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
}

type inboxFile struct {
	ID    string `json:"id"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

// listFiles returns the sealed files waiting in the inbox (names are IDs only;
// the server cannot see real file names).
func (m *manager) listFiles() ([]inboxFile, error) {
	entries, err := m.dir.list()
	if err != nil {
		return nil, err
	}
	out := []inboxFile{}
	for _, e := range entries {
		if !e.Type().IsRegular() || isJunk(e) || isPartFile(e) {
			continue
		}
		id, err := core.ParseInboxName(e.Name())
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, inboxFile{ID: id.String(), Size: info.Size(), MTime: info.ModTime().Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MTime > out[j].MTime })
	return out, nil
}

func (m *manager) deleteFile(idStr string) error {
	id, err := core.ParseFileID(idStr)
	if err != nil {
		return errors.New("invalid file id")
	}
	if err := m.dir.unlink(core.InboxName(id)); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return errors.New("file is already gone")
		}
		return err
	}
	return nil
}

func (m *manager) freeBytes() int64 {
	var st unix.Statfs_t
	if err := unix.Statfs(m.dataDir, &st); err != nil {
		return -1
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize))
}

type syncStatus struct {
	Linked      bool         `json:"linked"`
	Running     bool         `json:"running"`
	Stopped     bool         `json:"stopped"`
	Addr        string       `json:"addr,omitempty"`
	TLS         bool         `json:"tls"`
	Error       string       `json:"error,omitempty"`
	Fingerprint string       `json:"fingerprint,omitempty"`
	SetupDone   bool         `json:"setup_done"`
	Settings    syncSettings `json:"settings"`
}

func (m *manager) status() syncStatus {
	linked := m.configured()
	fp := ""
	if linked {
		fp = m.keyFingerprint()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := syncStatus{Linked: linked, Stopped: m.state.Stopped, Error: m.lastErr, Fingerprint: fp, SetupDone: m.state.SetupDone, Settings: m.state.Sync}
	if m.run != nil {
		st.Running, st.Addr, st.TLS = true, m.run.addr, m.run.tls
	}
	return st
}

// ---- admin password ----

func (m *manager) hasPassword() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.PassHash != ""
}

func (m *manager) setPassword(pw string) error {
	if len([]rune(pw)) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	if len(pw) > 256 {
		return errors.New("password is too long")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.PassSalt = base64.RawStdEncoding.EncodeToString(salt)
	m.state.PassHash = base64.RawStdEncoding.EncodeToString(hashPassword(pw, salt))
	return m.saveStateLocked()
}

func (m *manager) checkPassword(pw string) bool {
	m.mu.Lock()
	saltS, hashS := m.state.PassSalt, m.state.PassHash
	m.mu.Unlock()
	salt, err1 := base64.RawStdEncoding.DecodeString(saltS)
	want, err2 := base64.RawStdEncoding.DecodeString(hashS)
	if err1 != nil || err2 != nil || len(want) == 0 || len(pw) > 256 {
		return false
	}
	return constantTimeEqual(hashPassword(pw, salt), want)
}

// ---- setup code ----

// ensureSetupCode creates the one-time code needed to set the first admin
// password, so that whoever reaches the page first cannot claim the server.
func (m *manager) ensureSetupCode() (string, error) {
	p := m.path(setupCodeFile)
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		return strings.TrimSpace(string(b)), nil
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var raw [10]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	code := make([]byte, 0, 11)
	for i, b := range raw {
		if i == 5 {
			code = append(code, '-')
		}
		code = append(code, alphabet[int(b)%len(alphabet)])
	}
	if err := m.writePrivate(setupCodeFile, append(code, '\n')); err != nil {
		return "", err
	}
	return string(code), nil
}

func (m *manager) readSetupCode() string {
	b, err := os.ReadFile(m.path(setupCodeFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (m *manager) clearSetupCode() { _ = os.Remove(m.path(setupCodeFile)) }

// pairingView is what the web page shows of device pairing.
func (m *manager) pairingView() map[string]any {
	return map[string]any{
		"open":         m.pair.secondsOpen() > 0,
		"seconds_left": m.pair.secondsOpen(),
		"requests":     m.pair.pending(),
		"devices":      m.tokens.devices(),
	}
}

// resetOptions say what "start over" removes. The admin password and the inbox files stay unless asked.
type resetOptions struct {
	Devices  bool `json:"devices"`  // every approved device and pending request; closes the pairing window
	Keys     bool `json:"keys"`     // pasted vault keys and the shared token (server.conf)
	Settings bool `json:"settings"` // reachability, limits and TLS back to the defaults
	Files    bool `json:"files"`    // the sealed files waiting in the inbox
}

// reset removes what the owner picked and shows the guided setup again. The sync server is restarted.
func (m *manager) reset(o resetOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	if o.Devices {
		m.pair.close()
		m.pair.mu.Lock()
		m.pair.reqs = map[string]*pairRequest{}
		m.pair.mu.Unlock()
		if err := os.Remove(m.path(tokensFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if o.Keys {
		if err := os.Remove(m.path(confFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if o.Settings {
		m.state.Sync = defaultSyncSettings(m.defaultListen)
		m.state.Sync.AckPlainHTTP = m.ackDefault
	}
	if o.Files {
		files, err := m.listFiles()
		if err != nil {
			return err
		}
		for _, f := range files {
			if err := m.deleteFile(f.ID); err != nil {
				return err
			}
		}
	}
	m.state.SetupDone = false
	m.state.Stopped = false
	if err := m.saveStateLocked(); err != nil {
		return err
	}
	_ = m.startLocked() // a failure shows in the status panel
	return nil
}
