package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type senderPayload struct {
	V        int    `json:"v"`
	URL      string `json:"url"`
	InboxPub string `json:"inbox_pub"`
	KAuth    string `json:"k_auth"`
	Token    string `json:"token"`
	Label    string `json:"label"`
	FP       string `json:"fp"`
}

func decodeSenderPayload(t *testing.T, payload string) senderPayload {
	t.Helper()
	body, ok := strings.CutPrefix(payload, "ndes-sender1:")
	if !ok {
		t.Fatalf("payload has no prefix: %q", payload)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("payload is not unpadded base64url: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var p senderPayload
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("payload JSON: %v (%s)", err, raw)
	}
	return p
}

func TestSenderConfigPayloadAndTokenLine(t *testing.T) {
	v := newVault(t)
	pub, kAuth := v.serverConfig()
	r := ok(t, v.run("sender-config", "--server", "https://Inbox.Example.com/", "--label", "iphone-1"))
	if !strings.Contains(r.stderr, "secret") || strings.Contains(r.stderr, "ndes-sender1:") {
		t.Fatalf("stderr must warn and hold no secret: %q", r.stderr)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
		k, val, _ := strings.Cut(line, ": ")
		fields[k] = val
	}
	p := decodeSenderPayload(t, fields["payload"])
	if p.V != 1 || p.URL != "https://inbox.example.com" || p.Label != "iphone-1" {
		t.Fatalf("payload: %+v", p)
	}
	if p.InboxPub != base64.StdEncoding.EncodeToString(pub[:]) || p.KAuth != base64.StdEncoding.EncodeToString(kAuth[:]) {
		t.Fatal("payload keys differ from server-config")
	}
	sum := sha256.Sum256(pub[:])
	if p.FP != hex.EncodeToString(sum[:])[:8] || fields["fp"] != p.FP {
		t.Fatalf("fp %q", p.FP)
	}
	tok, err := base64.RawURLEncoding.DecodeString(p.Token)
	if err != nil || len(tok) != 32 || len(p.Token) != 43 {
		t.Fatalf("token is not 32 random bytes in base64url: %q", p.Token)
	}
	h := sha256.Sum256([]byte(p.Token))
	if want := "upload iphone-1 " + hex.EncodeToString(h[:]); fields["token-line"] != want {
		t.Fatalf("token line %q, want %q", fields["token-line"], want)
	}
	// The token line holds only the hash, never the token.
	if strings.Contains(fields["token-line"], p.Token) {
		t.Fatal("the token line holds the token")
	}

	// Tokens are fresh every time.
	r2 := ok(t, v.run("sender-config", "--server", "https://inbox.example.com", "--label", "iphone-1"))
	p2 := decodeSenderPayload(t, strings.TrimPrefix(strings.Split(r2.stdout, "\n")[0], "payload: "))
	if p2.Token == p.Token {
		t.Fatal("two runs made the same token")
	}
}

func TestSenderConfigRejectsBadArguments(t *testing.T) {
	v := newVault(t)
	for name, args := range map[string][]string{
		"http":             {"--server", "http://inbox.example.com", "--label", "a"},
		"no scheme":        {"--server", "inbox.example.com", "--label", "a"},
		"userinfo":         {"--server", "https://user:pw@inbox.example.com", "--label", "a"},
		"user only":        {"--server", "https://user@inbox.example.com", "--label", "a"},
		"query":            {"--server", "https://inbox.example.com?x=1", "--label", "a"},
		"empty query":      {"--server", "https://inbox.example.com/?", "--label", "a"},
		"fragment":         {"--server", "https://inbox.example.com/#x", "--label", "a"},
		"path":             {"--server", "https://inbox.example.com/api", "--label", "a"},
		"no host":          {"--server", "https://", "--label", "a"},
		"missing server":   {"--label", "a"},
		"missing label":    {"--server", "https://inbox.example.com"},
		"space in label":   {"--server", "https://inbox.example.com", "--label", "my phone"},
		"long label":       {"--server", "https://inbox.example.com", "--label", strings.Repeat("l", 33)},
		"non-ascii label":  {"--server", "https://inbox.example.com", "--label", "teléfono"},
		"newline in label": {"--server", "https://inbox.example.com", "--label", "a\nb"},
		"space in server":  {"--server", "https://inbox .example.com", "--label", "a"},
	} {
		r := v.run(append([]string{"sender-config"}, args...)...)
		if r.code == 0 {
			t.Errorf("%s: accepted", name)
		}
		if strings.Contains(r.stdout, "ndes-sender1:") {
			t.Errorf("%s: printed a payload", name)
		}
	}
	// A port is fine.
	ok(t, v.run("sender-config", "--server", "https://inbox.example.com:8443", "--label", "a"))
}

func TestSenderConfigJSON(t *testing.T) {
	v := newVault(t)
	r := ok(t, v.run("sender-config", "--json", "--server", "https://inbox.example.com", "--label", "pixel"))
	var types []string
	var payload, line string
	for _, l := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		types = append(types, rec["type"].(string))
		switch rec["type"] {
		case "payload":
			payload = rec["payload"].(string)
		case "token-line":
			line = rec["line"].(string)
		}
	}
	if strings.Join(types, ",") != "payload,token-line,end" {
		t.Fatalf("records %v", types)
	}
	p := decodeSenderPayload(t, payload)
	if !strings.HasPrefix(line, "upload pixel ") || strings.Contains(line, p.Token) {
		t.Fatalf("token line %q", line)
	}
	if strings.Contains(r.stderr, p.Token) || strings.Contains(r.stderr, payload) {
		t.Fatal("stderr holds a secret")
	}

	// Errors end with one error record and no payload.
	bad := v.run("sender-config", "--json", "--server", "http://inbox.example.com", "--label", "a")
	if bad.code == 0 || !strings.Contains(bad.stdout, `{"type":"error","code":"bad-argument"}`) || strings.Contains(bad.stdout, "payload") {
		t.Fatalf("bad argument: code=%d stdout=%q", bad.code, bad.stdout)
	}
	wrong := ndes(t, "wrong passphrase\n", "sender-config", "--vault", v.dir, "--passphrase-stdin", "--json", "--server", "https://inbox.example.com", "--label", "a")
	if wrong.code == 0 || !strings.Contains(wrong.stdout, `"code":"wrong-passphrase"`) || strings.Contains(wrong.stdout, "ndes-sender1:") {
		t.Fatalf("wrong passphrase: code=%d stdout=%q", wrong.code, wrong.stdout)
	}
}

func TestSenderConfigRedirectedOutputIsPrivate(t *testing.T) {
	v := newVault(t)
	out := v.tmp + "/payload.txt"
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], v.args("sender-config", "--server", "https://inbox.example.com", "--label", "a")...)
	cmd.Env = append(os.Environ(), "NDES_TEST_RUN_MAIN=1")
	cmd.Stdin = strings.NewReader(v.pass)
	cmd.Stdout = f
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("redirected output mode %v", st.Mode().Perm())
	}
}
