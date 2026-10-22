package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Device pairing: a new device asks to connect, the owner compares a short code on both screens and approves, and the
// server hands the new token to that device only. No token is ever typed, pasted or copied by a person.
//
//	POST /v1/pair/request        (no token) a device asks; needs the pairing window to be open
//	GET  /v1/pair/status/{id}    (no token, header X-Pair-Secret) the device polls for the answer
//	GET  /v1/pair/pending, POST /v1/pair/{id}/approve|deny, POST /v1/pair/open|close   (role both)
//	GET  /v1/devices, DELETE /v1/devices/{label}                                        (role both)
//
// The admin web page (managed mode) uses the same functions.
const (
	pairRequestTTL   = 5 * time.Minute
	pairMaxPending   = 5
	pairPerClientMax = 2
	pairMaxWindow    = 60 * time.Minute
	pairDefaultOpen  = 10 * time.Minute
)

var (
	errPairClosed  = errors.New("pairing is closed")
	errPairBusy    = errors.New("too many pending requests")
	errPairBad     = errors.New("invalid pairing request")
	errPairUnknown = errors.New("unknown pairing request")
)

type pairState string

const (
	pairPending  pairState = "pending"
	pairApproved pairState = "approved"
	pairDone     pairState = "done"
	pairDenied   pairState = "denied"
	pairExpired  pairState = "expired"
)

type pairRequest struct {
	id         string
	label      string
	role       tokenRole
	secretHash [32]byte
	code       string // six digits
	client     string
	created    time.Time
	state      pairState
	approvedAt time.Time
	token      string // plaintext, only until the device has fetched it
	finalLabel string
}

// deviceInfo is what the owner sees of an accepted token.
type deviceInfo struct {
	Label string `json:"label"`
	Role  string `json:"role"`
}

// tokenStore keeps the tokens file: devices that were approved are appended, revoked ones removed. The file holds
// only hashes. Anything written is applied to the running server at once (no signal needed).
type tokenStore struct {
	mu     sync.Mutex
	path   string
	legacy *tokenSet
	apply  func(*tokenSet)
}

func newTokenStore(path string, legacy *tokenSet, apply func(*tokenSet)) *tokenStore {
	return &tokenStore{path: path, legacy: legacy, apply: apply}
}

func (t *tokenStore) setLegacy(l *tokenSet) {
	t.mu.Lock()
	t.legacy = l
	t.mu.Unlock()
}

func (t *tokenStore) readRaw() ([]byte, error) {
	data, err := os.ReadFile(t.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func (t *tokenStore) parseMerged(data []byte) (*tokenSet, *tokenSet, error) {
	file, err := parseTokensFile(data, true)
	if err != nil {
		return nil, nil, err
	}
	merged, err := mergeTokenSets(t.legacy, file)
	return merged, file, err
}

// loadApply re-reads the file and applies it (startup and reload).
func (t *tokenStore) loadApply() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, err := t.readRaw()
	if err != nil {
		return err
	}
	merged, _, err := t.parseMerged(data)
	if err != nil {
		return err
	}
	t.apply(merged)
	return nil
}

func (t *tokenStore) writeLocked(data []byte) error {
	merged, _, err := t.parseMerged(data)
	if err != nil {
		return err
	}
	dir := filepath.Dir(t.path)
	tmp, err := os.CreateTemp(dir, ".tokens-*")
	if err != nil {
		return fmt.Errorf("the tokens file cannot be written (is its folder writable by ndesd?): %w", err)
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
	if err := os.Rename(tmp.Name(), t.path); err != nil {
		return err
	}
	t.apply(merged)
	return nil
}

// add appends a token line, making the label unique, and returns the label that was used.
func (t *tokenStore) add(role tokenRole, label string, hash [32]byte) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, err := t.readRaw()
	if err != nil {
		return "", err
	}
	_, file, err := t.parseMerged(data)
	if err != nil {
		return "", err
	}
	taken := map[string]bool{}
	for _, e := range file.entries {
		taken[e.label] = true
	}
	if t.legacy != nil {
		for _, e := range t.legacy.entries {
			taken[e.label] = true
		}
	}
	final := label
	for n := 2; taken[final]; n++ {
		suffix := fmt.Sprintf("-%d", n)
		base := label
		if len(base)+len(suffix) > maxTokenLabelLen {
			base = base[:maxTokenLabelLen-len(suffix)]
		}
		final = base + suffix
	}
	roleName := map[tokenRole]string{roleUpload: "upload", rolePull: "pull", roleBoth: "both"}[role]
	out := string(data)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += roleName + " " + final + " " + hex.EncodeToString(hash[:]) + "\n"
	if err := t.writeLocked([]byte(out)); err != nil {
		return "", err
	}
	return final, nil
}

// remove deletes the line of a device (revoking its token).
func (t *tokenStore) remove(label string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, err := t.readRaw()
	if err != nil {
		return err
	}
	var out []string
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && !strings.HasPrefix(strings.TrimSpace(line), "#") && f[1] == label {
			found = true
			continue
		}
		out = append(out, line)
	}
	if !found {
		return errPairUnknown
	}
	return t.writeLocked([]byte(strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"))
}

func (t *tokenStore) devices() []deviceInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, _ := t.readRaw()
	var out []deviceInfo
	file, err := parseTokensFile(data, true)
	if err != nil {
		return out
	}
	for _, e := range file.entries {
		role := "upload"
		switch e.role {
		case roleBoth:
			role = "both"
		case rolePull:
			role = "pull"
		}
		out = append(out, deviceInfo{Label: e.label, Role: role})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// pairing holds the window and the requests. Requests live in memory only.
type pairing struct {
	mu        sync.Mutex
	store     *tokenStore
	now       func() time.Time
	openUntil time.Time
	reqs      map[string]*pairRequest
}

func newPairing(store *tokenStore) *pairing {
	return &pairing{store: store, now: time.Now, reqs: map[string]*pairRequest{}}
}

func (p *pairing) open(d time.Duration) time.Time {
	if d <= 0 {
		d = pairDefaultOpen
	}
	d = min(d, pairMaxWindow)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.openUntil = p.now().Add(d)
	return p.openUntil
}

func (p *pairing) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.openUntil = time.Time{}
}

func (p *pairing) secondsOpen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if left := p.openUntil.Sub(p.now()); left > 0 {
		return int(left.Seconds()) + 1
	}
	return 0
}

// gcLocked expires old requests. An approved token that was never fetched is revoked again.
func (p *pairing) gcLocked() {
	now := p.now()
	for id, r := range p.reqs {
		switch r.state {
		case pairPending:
			if now.Sub(r.created) > pairRequestTTL {
				r.state = pairExpired
			}
		case pairApproved:
			if r.token != "" && now.Sub(r.approvedAt) > pairRequestTTL {
				_ = p.store.remove(r.finalLabel)
				r.token, r.state = "", pairExpired
			}
		}
		if r.state != pairPending && r.state != pairApproved && now.Sub(r.created) > 3*pairRequestTTL {
			delete(p.reqs, id)
		}
	}
}

func randomDigits(n int) (string, error) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + d.Int64()))
	}
	return b.String(), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// request registers a device's ask. secretHash is the SHA-256 of a secret only the device knows.
func (p *pairing) request(label, roleName string, secretHashHex, client string) (id, code string, err error) {
	if validTokenLabel(label) != nil {
		return "", "", errPairBad
	}
	role, ok := parseRole(roleName)
	if !ok || role == rolePull {
		return "", "", errPairBad
	}
	raw, derr := hex.DecodeString(secretHashHex)
	if derr != nil || len(raw) != 32 || secretHashHex != strings.ToLower(secretHashHex) {
		return "", "", errPairBad
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	if !p.now().Before(p.openUntil) {
		return "", "", errPairClosed
	}
	pending, mine := 0, 0
	for _, r := range p.reqs {
		if r.state == pairPending {
			pending++
			if r.client == client {
				mine++
			}
		}
	}
	if pending >= pairMaxPending || mine >= pairPerClientMax {
		return "", "", errPairBusy
	}
	code, err = randomDigits(6)
	if err != nil {
		return "", "", err
	}
	r := &pairRequest{id: randomHex(16), label: label, role: role, code: code, client: client, created: p.now(), state: pairPending}
	copy(r.secretHash[:], raw)
	p.reqs[r.id] = r
	return r.id, code, nil
}

type pairStatus struct {
	State pairState `json:"state"`
	Token string    `json:"token,omitempty"`
	Role  string    `json:"role,omitempty"`
	Label string    `json:"label,omitempty"`
}

// status is what the device sees. The token is released exactly once, to the holder of the secret.
func (p *pairing) status(id, secret string) (pairStatus, error) {
	h := sha256.Sum256([]byte(secret))
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	r := p.reqs[id]
	if r == nil || subtle.ConstantTimeCompare(h[:], r.secretHash[:]) != 1 {
		return pairStatus{}, errPairUnknown
	}
	switch r.state {
	case pairApproved:
		if r.token == "" {
			return pairStatus{State: pairDone}, nil
		}
		st := pairStatus{State: pairApproved, Token: r.token, Role: roleString(r.role), Label: r.finalLabel}
		r.token, r.state = "", pairDone
		return st, nil
	default:
		return pairStatus{State: r.state}, nil
	}
}

func roleString(r tokenRole) string {
	switch r {
	case roleBoth:
		return "both"
	case rolePull:
		return "pull"
	}
	return "upload"
}

type pendingInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Role  string `json:"role"`
	Code  string `json:"code"`
	Age   int    `json:"age_seconds"`
}

func (p *pairing) pending() []pendingInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	out := []pendingInfo{}
	for _, r := range p.reqs {
		if r.state == pairPending {
			out = append(out, pendingInfo{ID: r.id, Label: r.label, Role: roleString(r.role), Code: r.code, Age: int(p.now().Sub(r.created).Seconds())})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Age < out[j].Age })
	return out
}

// approve mints the token and stores its hash. The plaintext waits in memory for the device to fetch it.
func (p *pairing) approve(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	r := p.reqs[id]
	if r == nil || r.state != pairPending {
		return errPairUnknown
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(tok)
	final, err := p.store.add(r.role, r.label, sha256.Sum256([]byte(token)))
	if err != nil {
		return err
	}
	r.token, r.finalLabel, r.state, r.approvedAt = token, final, pairApproved, p.now()
	return nil
}

func (p *pairing) deny(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.reqs[id]
	if r == nil || r.state != pairPending {
		return errPairUnknown
	}
	r.state = pairDenied
	return nil
}
