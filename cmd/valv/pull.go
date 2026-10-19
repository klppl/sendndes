package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/klppl/valv/core"
)

const (
	maxPullListBytes     = 1 << 20 // 1 MiB
	maxPullTokenFileSize = 4096
)

var (
	pullPartRE        = regexp.MustCompile(`^\.valv-[0-9a-f]{16}\.part$`)
	pullTestTransport http.RoundTripper // set only by in-process tests
)

func (a *app) cmdPull(args []string) error {
	fs := a.flags("pull", true, false)
	serverFlag := fs.String("server", "", "valvd server base URL (or $VALV_SERVER)")
	tokenFileFlag := fs.String("token-file", "", "file containing the bearer token")
	allowInsecure := fs.Bool("allow-insecure-http", false, "allow plain HTTP to a non-loopback, non-Tailscale host")
	if _, err := parse(fs, args, 0, 0); err != nil {
		return err
	}

	serverURL := *serverFlag
	if serverURL == "" {
		serverURL = os.Getenv("VALV_SERVER")
	}
	if serverURL == "" {
		return errors.New("pull: --server (or $VALV_SERVER) is required")
	}
	baseURL, err := validatePullServerURL(serverURL, *allowInsecure)
	if err != nil {
		return fmt.Errorf("pull: %w", err)
	}
	if *tokenFileFlag == "" {
		return errors.New("pull: --token-file is required")
	}
	token, err := readPullTokenFile(*tokenFileFlag)
	if err != nil {
		return fmt.Errorf("pull: %w", err)
	}
	defer func() {
		// Strings are immutable in Go, but we keep token scoped to cmdPull.
		token = ""
	}()

	// Open the vault directory once before any passphrase prompt (SPEC 8).
	v, err := a.openVault(a.vaultDir())
	if err != nil {
		return err
	}
	defer v.Close()

	inboxD, err := v.openSub(core.InboxDir)
	if err != nil {
		return err
	}
	defer inboxD.Close()

	// Recommendation #4 (D-R2): clean up stale .valv-*.part files in <vault>/inbox/
	// left by any earlier crashed pull before prompting or downloading.
	cleanStaleInboxParts(inboxD)

	keys, err := a.unlock(v)
	if err != nil {
		return err
	}
	defer keys.Wipe()

	var rt http.RoundTripper = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if pullTestTransport != nil {
		rt = pullTestTransport
	}
	client := &http.Client{
		Timeout:   0, // streaming downloads can be large; headers/idle/redirects are guarded
		Transport: rt,
		// Never follow redirects so the Bearer token cannot be leaked to another host.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ids, err := fetchInboxIDs(client, baseURL, token)
	if err != nil {
		return fmt.Errorf("pull: %w", err)
	}

	var ingested, already, failed int
	report := func(msg string) {
		failed++
		fmt.Fprintf(a.stderr, "error: %s\n", msg)
	}

	for _, idStr := range ids {
		id, err := core.ParseFileID(idStr)
		if err != nil {
			report(fmt.Sprintf("server returned invalid file_id %s: %v", display(idStr), err))
			continue
		}
		inName := core.InboxName(id)
		rel := path.Join(core.InboxDir, inName)

		// Download to <vault>/inbox/<id>.inb via a .valv-*.part temp file unless
		// it already exists locally from an earlier interrupted run.
		if _, lerr := inboxD.lstat(inName); errors.Is(lerr, os.ErrNotExist) {
			if err := downloadInboxFile(client, baseURL, token, id, inboxD, inName); err != nil {
				report(fmt.Sprintf("%s: download failed: %v", display(rel), err))
				continue
			}
		} else if lerr != nil {
			report(fmt.Sprintf("%s: %v", display(rel), lerr))
			continue
		}

		// Authenticate and ingest into <vault>/objects/<xx>/<id>.obj (with
		// read-back verification or CheckAlreadyIngested, SPEC 6.3).
		f := vaultFile{rel: rel, name: inName, id: id}
		result, err := ingestOne(v, inboxD, f, keys)
		switch {
		case errors.Is(err, core.ErrAuth):
			report(fmt.Sprintf("%s: not authentic (made without this vault's K_auth, or damaged): %v (inbox file kept, not deleted from server)", display(rel), err))
			continue
		case err != nil:
			report(fmtProblem(rel, err) + " (inbox file kept, not deleted from server)")
			continue
		case result == "already":
			already++
		default:
			ingested++
		}

		// CRITICAL GATE (SPEC 6.3, 8): DELETE /inbox/{id} on the server is called
		// ONLY after ingestOne has succeeded with nil error (meaning either
		// verified read-back of the new object or verified CheckAlreadyIngested).
		if err := deleteRemoteInboxFile(client, baseURL, token, id); err != nil {
			fmt.Fprintf(a.stderr, "warning: %s ingested locally, but server delete failed (%v); next pull will absorb it via idempotency\n", id, err)
		}
	}

	fmt.Fprintf(a.stdout, "ingested %d, already ingested %d, failed %d\n", ingested, already, failed)
	if failed > 0 {
		return fmt.Errorf("%d inbox file(s) could not be pulled", failed)
	}
	return nil
}

func cleanStaleInboxParts(inboxD *dirHandle) {
	entries, err := inboxD.list()
	if err != nil {
		return
	}
	for _, e := range entries {
		if pullPartRE.MatchString(e.Name()) && e.Type().IsRegular() {
			_ = inboxD.unlink(e.Name())
		}
	}
}

func validatePullServerURL(raw string, allowInsecure bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	if u.User != nil {
		return "", errors.New("server URL must not contain userinfo credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("server URL must not contain query parameters or fragments")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure && !isTrustedPlainHTTPHost(u.Hostname()) {
			return "", fmt.Errorf("refusing plain HTTP to %s (use https://, a loopback/Tailscale IP, or --allow-insecure-http)", display(u.Host))
		}
	default:
		return "", fmt.Errorf("unsupported URL scheme %q (want https or http)", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", errors.New("server URL is missing host")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

var (
	tailscaleIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleIPv6Prefix = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

func isTrustedPlainHTTPHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback() || tailscaleIPv4Prefix.Contains(addr) || tailscaleIPv6Prefix.Contains(addr)
}

func readPullTokenFile(p string) (string, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return "", fmt.Errorf("%s: refusing to follow symlink", display(p))
		}
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", display(p))
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s: permissions %04o are too open (chmod 0600)", display(p), st.Mode().Perm())
	}
	if st.Size() > maxPullTokenFileSize {
		return "", fmt.Errorf("%s: larger than %d bytes", display(p), maxPullTokenFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPullTokenFileSize+1))
	if err != nil {
		return "", err
	}
	defer clear(data)
	if len(data) > maxPullTokenFileSize {
		return "", fmt.Errorf("%s: larger than %d bytes", display(p), maxPullTokenFileSize)
	}
	tok := strings.TrimRight(string(data), "\r\n")
	if tok == "" || len(tok) > 512 {
		return "", fmt.Errorf("%s: invalid token length", display(p))
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= 0x20 || tok[i] >= 0x7f {
			return "", fmt.Errorf("%s: token contains invalid characters", display(p))
		}
	}
	return tok, nil
}

func fetchInboxIDs(client *http.Client, baseURL, token string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/inbox", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /inbox: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPullListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPullListBytes {
		return nil, errors.New("GET /inbox response exceeds 1 MiB")
	}
	var parsed struct {
		IDs []string `json:"ids"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("GET /inbox: invalid JSON: %w", err)
	}
	if parsed.IDs == nil {
		return nil, errors.New("GET /inbox: missing ids field")
	}
	return parsed.IDs, nil
}

func downloadInboxFile(client *http.Client, baseURL, token string, id core.FileID, inboxD *dirHandle, inName string) error {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/inbox/"+id.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /inbox/%s: HTTP %d", id, resp.StatusCode)
	}
	return writeAt(inboxD, inName, writeOpts{overwrite: false}, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, core.StoredChunkSize)
		n, err := io.Copy(bw, resp.Body)
		if err != nil {
			return err
		}
		if resp.ContentLength >= 0 && n != resp.ContentLength {
			return io.ErrUnexpectedEOF
		}
		return bw.Flush()
	})
}

func deleteRemoteInboxFile(client *http.Client, baseURL, token string, id core.FileID) error {
	req, err := http.NewRequest(http.MethodDelete, baseURL+"/inbox/"+id.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("DELETE /inbox/%s: HTTP %d", id, resp.StatusCode)
	}
	return nil
}
