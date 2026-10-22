package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	senderPayloadPrefix  = "ndes-sender1:" // carries an upload token made here (the owner adds its hash to the server)
	senderPayload2Prefix = "ndes-sender2:" // no token: the phone asks the server to pair and the owner approves
)

var errSenderConfig = errors.New("invalid sender-config argument")

// senderHTTPS checks and normalizes the server URL for a phone: https only, a host, and nothing else
// (no userinfo, query, fragment or path). The result is scheme://host[:port] with the host lower-cased.
func senderHTTPS(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("%w: --server must be an https URL such as https://inbox.example.com", errSenderConfig)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || strings.ContainsAny(raw, " \t\r\n") {
		return "", fmt.Errorf("%w: --server must be just https://host[:port] (no user, path, query or fragment)", errSenderConfig)
	}
	host := strings.ToLower(u.Hostname())
	if !senderDNSName(host) {
		return "", fmt.Errorf("%w: --server needs a plain host name such as inbox.example.com (letters, digits, hyphens; no IP address)", errSenderConfig)
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") && port == "" {
		return "", fmt.Errorf("%w: --server has an empty port", errSenderConfig)
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", fmt.Errorf("%w: --server has an invalid port", errSenderConfig)
		}
		return "https://" + host + ":" + port, nil
	}
	return "https://" + host, nil
}

// senderDNSName: at least two labels of ASCII letters, digits and hyphens (no empty label, no trailing dot),
// and not all digits (an IP address in disguise).
func senderDNSName(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	allDigits := true
	numeric := func(l string) bool {
		if strings.HasPrefix(l, "0x") {
			l = l[2:]
			for i := 0; i < len(l); i++ {
				c := l[i]
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					return false
				}
			}
			return true
		}
		for i := 0; i < len(l); i++ {
			if l[i] < '0' || l[i] > '9' {
				return false
			}
		}
		return len(l) > 0
	}
	if numeric(labels[len(labels)-1]) { // a numeric or hex last label is an IP address in disguise
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c == '-':
				allDigits = false
			case c >= '0' && c <= '9':
			default:
				return false
			}
		}
	}
	return !allDigits
}

// senderLabel: 1 to 32 printable ASCII characters, no spaces (it becomes a column of the server's tokens file).
func senderLabel(s string) error {
	if s == "" || len(s) > 32 {
		return fmt.Errorf("%w: --label must be 1 to 32 characters", errSenderConfig)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return fmt.Errorf("%w: --label must be printable ASCII without spaces", errSenderConfig)
		}
	}
	return nil
}

// cmdSenderConfig pairs a phone: it unlocks the vault, makes a random upload token, and prints the payload for
// the QR code and the line to add to the server's tokens file. The vault key never leaves the vault: the
// payload holds only inbox_pub and k_auth (what the server could already hold) and the new token.
func (a *app) cmdSenderConfig(args []string) error {
	fs := a.flags("sender-config", true, false)
	server := fs.String("server", "", "https URL of the inbox server")
	label := fs.String("label", "", "name for this device (letters, digits, punctuation; no spaces)")
	jsonFlag := fs.Bool("json", false, "one JSON object per line (for the Mac app)")
	pairFlag := fs.Bool("pair", false, "no token: the phone asks the server to pair and the owner approves there")
	js := jsonLines{a.stdout}
	fail := func(err error) error {
		if *jsonFlag {
			js.rec("error", "code", senderErrCode(err))
		}
		return err
	}
	if _, err := parse(fs, args, 0, 0); err != nil {
		return fail(err)
	}
	base, err := senderHTTPS(*server)
	if err != nil {
		return fail(err)
	}
	if err := senderLabel(*label); err != nil {
		return fail(err)
	}
	v, err := a.openVault(a.vaultDir())
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	keys, err := a.unlock(v)
	if err != nil {
		return fail(err)
	}
	defer keys.Wipe()

	token, tokenLine := "", ""
	if !*pairFlag {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return fail(fmt.Errorf("no random numbers: %w", err))
		}
		defer clear(raw[:])
		token = base64.RawURLEncoding.EncodeToString(raw[:])
		th := sha256.Sum256([]byte(token))
		tokenLine = "upload " + *label + " " + hex.EncodeToString(th[:])
	}
	ph := sha256.Sum256(keys.InboxPub[:])
	fp := hex.EncodeToString(ph[:])[:8]

	std := base64.StdEncoding
	var sb strings.Builder
	if *pairFlag {
		sb.WriteString(`{"v":2,"url":`)
	} else {
		sb.WriteString(`{"v":1,"url":`)
	}
	sb.WriteString(jsonString(base))
	sb.WriteString(`,"inbox_pub":"` + std.EncodeToString(keys.InboxPub[:]) + `"`)
	sb.WriteString(`,"k_auth":"` + std.EncodeToString(keys.InboxAuth[:]) + `"`)
	if !*pairFlag {
		sb.WriteString(`,"token":"` + token + `"`)
	}
	sb.WriteString(`,"label":` + jsonString(*label))
	sb.WriteString(`,"fp":"` + fp + `"}`)
	prefix := senderPayloadPrefix
	if *pairFlag {
		prefix = senderPayload2Prefix
	}
	payload := prefix + base64.RawURLEncoding.EncodeToString([]byte(sb.String()))

	// A redirect to a regular file gets mode 0600 before the secrets are written.
	if f, ok := a.stdout.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode().IsRegular() {
			if err := f.Chmod(0o600); err != nil {
				return fail(fmt.Errorf("could not restrict the output file to mode 0600: %w", err))
			}
		}
	}
	fmt.Fprintln(a.stderr, "warning: the payload holds a secret upload token and k_auth. Show it only to the phone you are pairing (scan the QR code, then clear the screen); do not save it or send it. Add the token line to the server's tokens file and reload it.")
	if *jsonFlag {
		js.rec("payload", "payload", payload, "fp", fp)
		if !*pairFlag {
			js.rec("token-line", "line", tokenLine)
		}
		js.rec("end")
		return nil
	}
	if *pairFlag {
		_, err = fmt.Fprintf(a.stdout, "payload: %s\nfp: %s\n", payload, fp)
		return err
	}
	_, err = fmt.Fprintf(a.stdout, "payload: %s\ntoken-line: %s\nfp: %s\n", payload, tokenLine, fp)
	return err
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func senderErrCode(err error) string {
	if errors.Is(err, errSenderConfig) {
		return "bad-argument"
	}
	return jsonErrCode(err)
}
