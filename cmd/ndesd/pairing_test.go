package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type pairRig struct {
	env  *testServerEnv
	pair *pairing
	path string
	now  *fakeNow
}

type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeNow) Now() time.Time          { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeNow) Advance(d time.Duration) { f.mu.Lock(); f.t = f.t.Add(d); f.mu.Unlock() }

// newPairRig: a keyless sealed-only server whose owner token (role both) is the legacy token, with pairing on.
func newPairRig(t *testing.T) *pairRig {
	t.Helper()
	opts := defaultServerOpts()
	opts.enableServerSealing = false
	env := startTestServer(t, opts)
	path := filepath.Join(t.TempDir(), "tokens")
	store := newTokenStore(path, legacyTokenSet([]byte(testBearerToken)), env.srv.setTokens)
	if err := store.loadApply(); err != nil {
		t.Fatal(err)
	}
	p := newPairing(store)
	now := &fakeNow{t: time.Now()}
	p.now = now.Now
	env.srv.setPairing(p)
	return &pairRig{env: env, pair: p, path: path, now: now}
}

func secretHash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

type reqResp struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	ExpiresIn int    `json:"expires_in"`
}

func (r *pairRig) request(label, role, secret string) (int, reqResp, string) {
	body, _ := json.Marshal(map[string]string{"label": label, "role": role, "secret_hash": secretHash(secret)})
	code, out := r.env.call("POST", "/v1/pair/request", "", body, nil)
	var rr reqResp
	json.Unmarshal([]byte(out), &rr)
	return code, rr, out
}

func (r *pairRig) status(id, secret string) (int, pairStatus) {
	code, out := r.env.call("GET", "/v1/pair/status/"+id, "", nil, map[string]string{"X-Pair-Secret": secret})
	var st pairStatus
	json.Unmarshal([]byte(out), &st)
	return code, st
}

func (r *pairRig) owner(method, path string, body []byte) (int, string) {
	return r.env.call(method, path, testBearerToken, body, nil)
}

func TestPairingFullFlow(t *testing.T) {
	r := newPairRig(t)
	// Closed by default: a device is turned away and nothing is stored.
	if code, _, out := r.request("iphone", "upload", "s1"); code != 403 || !strings.Contains(out, "not accepting") {
		t.Fatalf("closed window: %d %s", code, out)
	}
	if code, _ := r.owner("POST", "/v1/pair/open", []byte(`{"minutes":10}`)); code != 200 {
		t.Fatal("open")
	}
	code, rr, _ := r.request("iphone", "upload", "secret-one")
	if code != 201 || len(rr.ID) != 32 || len(rr.Code) != 6 || rr.ExpiresIn != 300 {
		t.Fatalf("request: %d %+v", code, rr)
	}
	// While pending the device learns nothing; a wrong secret or unknown id is a plain 404.
	if c, st := r.status(rr.ID, "secret-one"); c != 200 || st.State != pairPending || st.Token != "" {
		t.Fatalf("pending status: %d %+v", c, st)
	}
	if c, _ := r.status(rr.ID, "wrong"); c != 404 {
		t.Fatalf("wrong secret: %d", c)
	}
	if c, _ := r.status(strings.Repeat("0", 32), "secret-one"); c != 404 {
		t.Fatalf("unknown id: %d", c)
	}
	// The owner sees the code and the name, and approves.
	c, out := r.owner("GET", "/v1/pair/pending", nil)
	var pend struct {
		Open     bool          `json:"open"`
		Requests []pendingInfo `json:"requests"`
	}
	json.Unmarshal([]byte(out), &pend)
	if c != 200 || !pend.Open || len(pend.Requests) != 1 || pend.Requests[0].Code != rr.Code || pend.Requests[0].Label != "iphone" || pend.Requests[0].Role != "upload" {
		t.Fatalf("pending list: %d %s", c, out)
	}
	if c, _ := r.owner("POST", "/v1/pair/"+rr.ID+"/approve", nil); c != 200 {
		t.Fatalf("approve: %d", c)
	}
	// The device gets the token once.
	c, st := r.status(rr.ID, "secret-one")
	if c != 200 || st.State != pairApproved || len(st.Token) != 43 || st.Role != "upload" || st.Label != "iphone" {
		t.Fatalf("approved status: %d %+v", c, st)
	}
	if c, st2 := r.status(rr.ID, "secret-one"); c != 200 || st2.State != pairDone || st2.Token != "" {
		t.Fatalf("token was released twice: %+v", st2)
	}
	// The token works at once, with exactly its role.
	if c, _ := r.env.call("GET", "/v1/ping", st.Token, nil, nil); c != 204 {
		t.Fatalf("new token ping: %d", c)
	}
	if c, _ := r.env.call("GET", "/inbox", st.Token, nil, nil); c != 403 {
		t.Fatalf("an upload token listed the inbox: %d", c)
	}
	if c, _ := r.env.call("GET", "/v1/pair/pending", st.Token, nil, nil); c != 403 {
		t.Fatalf("an upload token reached the owner endpoints: %d", c)
	}
	// The file holds only a hash, with mode 0600.
	data, _ := os.ReadFile(r.path)
	if !strings.Contains(string(data), "upload iphone "+secretHash(st.Token)) || strings.Contains(string(data), st.Token) {
		t.Fatalf("tokens file: %q", data)
	}
	if fi, _ := os.Stat(r.path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	// Device list, then revoke: the token stops working at once.
	_, devs := r.owner("GET", "/v1/devices", nil)
	if !strings.Contains(devs, `"label":"iphone"`) {
		t.Fatalf("devices: %s", devs)
	}
	if c, _ := r.owner("DELETE", "/v1/devices/iphone", nil); c != 200 {
		t.Fatalf("revoke: %d", c)
	}
	if c, _ := r.env.call("GET", "/v1/ping", st.Token, nil, nil); c != 401 {
		t.Fatalf("a revoked token still works: %d", c)
	}
	if c, _ := r.owner("DELETE", "/v1/devices/iphone", nil); c != 404 {
		t.Fatalf("revoking twice: %d", c)
	}
}

func TestPairingBothRoleAndLabelCollisions(t *testing.T) {
	r := newPairRig(t)
	r.pair.open(time.Hour)
	var labels []string
	for i, secret := range []string{"a", "b"} {
		_, rr, _ := r.request("macbook", "both", secret)
		if err := r.pair.approve(rr.ID); err != nil {
			t.Fatal(err)
		}
		_, st := r.status(rr.ID, secret)
		labels = append(labels, st.Label)
		if i == 0 && st.Role != "both" {
			t.Fatalf("role %s", st.Role)
		}
		if c, _ := r.owner("GET", "/v1/pair/pending", nil); c != 200 {
			t.Fatal("owner")
		}
	}
	if labels[0] != "macbook" || labels[1] != "macbook-2" {
		t.Fatalf("labels %v", labels)
	}
	// A "both" token can pull and reach the owner endpoints.
	_, rr, _ := r.request("mac3", "both", "c")
	r.pair.approve(rr.ID)
	_, st := r.status(rr.ID, "c")
	if c, _ := r.env.call("GET", "/inbox", st.Token, nil, nil); c != 200 {
		t.Fatalf("both token cannot list: %d", c)
	}
}

func TestPairingDenyExpiryAndLimits(t *testing.T) {
	r := newPairRig(t)
	r.pair.open(time.Hour)
	// Deny.
	_, a, _ := r.request("a", "upload", "sa")
	if c, _ := r.owner("POST", "/v1/pair/"+a.ID+"/deny", nil); c != 200 {
		t.Fatal("deny")
	}
	if _, st := r.status(a.ID, "sa"); st.State != pairDenied {
		t.Fatalf("denied: %+v", st)
	}
	if c, _ := r.owner("POST", "/v1/pair/"+a.ID+"/approve", nil); c != 404 {
		t.Fatalf("approving a denied request: %d", c)
	}
	// Expiry of a pending request.
	_, b, _ := r.request("b", "upload", "sb")
	r.now.Advance(pairRequestTTL + time.Second)
	if _, st := r.status(b.ID, "sb"); st.State != pairExpired {
		t.Fatalf("expired: %+v", st)
	}
	if c, _ := r.owner("POST", "/v1/pair/"+b.ID+"/approve", nil); c != 404 {
		t.Fatalf("approving an expired request: %d", c)
	}
	// The window closes by itself.
	r.pair.open(time.Minute)
	r.now.Advance(2 * time.Minute)
	if code, _, _ := r.request("late", "upload", "sl"); code != 403 {
		t.Fatalf("window did not close: %d", code)
	}
	// Per-client and total limits (all test requests come from one pipe address).
	r.pair.open(time.Hour)
	ok, busy := 0, 0
	for i := 0; i < 8; i++ {
		switch code, _, _ := r.request("d"+string(rune('a'+i)), "upload", "x"+string(rune('a'+i))); code {
		case 201:
			ok++
		case 429:
			busy++
		}
	}
	if ok != pairPerClientMax || busy == 0 {
		t.Fatalf("limits: %d accepted, %d refused", ok, busy)
	}
	// Bad input (the request limiter is out of the way for this part).
	r.env.srv.pairReqRL = newIPRateLimiter(1000, time.Millisecond)
	for name, body := range map[string]string{
		"role pull":     `{"label":"x","role":"pull","secret_hash":"` + secretHash("s") + `"}`,
		"role admin":    `{"label":"x","role":"admin","secret_hash":"` + secretHash("s") + `"}`,
		"empty label":   `{"label":"","role":"upload","secret_hash":"` + secretHash("s") + `"}`,
		"space label":   `{"label":"a b","role":"upload","secret_hash":"` + secretHash("s") + `"}`,
		"long label":    `{"label":"` + strings.Repeat("l", 33) + `","role":"upload","secret_hash":"` + secretHash("s") + `"}`,
		"short hash":    `{"label":"x","role":"upload","secret_hash":"abcd"}`,
		"upper hash":    `{"label":"x","role":"upload","secret_hash":"` + strings.ToUpper(secretHash("s")) + `"}`,
		"unknown field": `{"label":"x","role":"upload","secret_hash":"` + secretHash("s") + `","admin":true}`,
		"not json":      `nope`,
		"huge":          `{"label":"` + strings.Repeat("x", 5000) + `"}`,
	} {
		r.pair.mu.Lock()
		r.pair.reqs = map[string]*pairRequest{}
		r.pair.mu.Unlock()
		if code, _ := r.env.call("POST", "/v1/pair/request", "", []byte(body), nil); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
}

func TestPairingUndeliveredTokenIsRevoked(t *testing.T) {
	r := newPairRig(t)
	r.pair.open(time.Hour)
	_, rr, _ := r.request("ghost", "upload", "sg")
	if err := r.pair.approve(rr.ID); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(r.path); !strings.Contains(string(data), "ghost") {
		t.Fatal("not written")
	}
	// The device never fetched it: after the time is up the line is gone again.
	r.now.Advance(pairRequestTTL + time.Second)
	if _, st := r.status(rr.ID, "sg"); st.State != pairExpired {
		t.Fatalf("%+v", st)
	}
	if data, _ := os.ReadFile(r.path); strings.Contains(string(data), "ghost") {
		t.Fatalf("an undelivered token was left active: %q", data)
	}
}

func TestPairingKeepsHandEditedLinesAndComments(t *testing.T) {
	r := newPairRig(t)
	os.WriteFile(r.path, []byte("# my devices\nupload old-phone "+secretHash("old")+"\n"), 0o600)
	r.pair.store.loadApply()
	r.pair.open(time.Hour)
	_, rr, _ := r.request("new", "upload", "sn")
	r.pair.approve(rr.ID)
	data, _ := os.ReadFile(r.path)
	if !strings.HasPrefix(string(data), "# my devices\nupload old-phone ") || !strings.Contains(string(data), "upload new ") {
		t.Fatalf("%q", data)
	}
	if c, _ := r.env.call("GET", "/v1/ping", "old", nil, nil); c != 204 {
		t.Fatalf("the old device lost access: %d", c)
	}
	r.pair.store.remove("new")
	data, _ = os.ReadFile(r.path)
	if !strings.Contains(string(data), "# my devices") || strings.Contains(string(data), " new ") {
		t.Fatalf("%q", data)
	}
}

func TestPairingNotOfferedWithoutIt(t *testing.T) {
	opts := defaultServerOpts()
	opts.enableServerSealing = false
	env := startTestServer(t, opts) // no setPairing
	if c, _ := env.call("POST", "/v1/pair/request", "", []byte(`{}`), nil); c != 401 {
		t.Fatalf("pairing endpoints exist without --pairing: %d", c)
	}
	if c, _ := env.call("GET", "/v1/pair/pending", testBearerToken, nil, nil); c != 404 {
		t.Fatalf("owner endpoints exist without --pairing: %d", c)
	}
}

func TestPairingRateLimitsAndNoSecretsInResponses(t *testing.T) {
	r := newPairRig(t)
	r.pair.open(time.Hour)
	hits429 := false
	for i := 0; i < 30; i++ {
		if c, _ := r.status(strings.Repeat("a", 32), "x"); c == 429 {
			hits429 = true
		}
	}
	if !hits429 {
		// 60 per half second burst: poll a bit more to prove it exists at all.
		for i := 0; i < 200 && !hits429; i++ {
			c, _ := r.status(strings.Repeat("a", 32), "x")
			hits429 = c == 429
		}
	}
	if !hits429 {
		t.Fatal("status polling is not rate limited")
	}
	// A request with a bearer token of the wrong kind still gets the same answer as without one.
	_, rr, out := r.request("p", "upload", "sp")
	if strings.Contains(out, "secret") || strings.Contains(out, secretHash("sp")) {
		t.Fatalf("response echoes the secret: %s", out)
	}
	_ = rr
}
