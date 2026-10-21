package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/klppl/sendndes/core"
)

const (
	maxPullListBytes            = 1 << 20        // 1 MiB
	maxPullTokenFileSize        = 4096           // 4 KiB
	defaultMaxPullDownloadBytes = int64(4) << 30 // 4 GiB
	defaultPullIOTimeout        = 30 * time.Second
	defaultMaxPullTotalBytes    = int64(16) << 30 // 16 GiB per pull run
)

type pullOpts struct {
	maxDownloadBytes int64
	maxTotalBytes    int64
	ioTimeout        time.Duration
}

var (
	pullPartRE        = regexp.MustCompile(`^\.ndes-[0-9a-f]{16}\.part$`)
	pullTestTransport http.RoundTripper // set only by in-process tests
)

func (a *app) cmdPull(args []string) error {
	fs := a.flags("pull", true, false)
	serverFlag := fs.String("server", "", "ndesd server base URL (or $NDES_SERVER)")
	tokenFileFlag := fs.String("token-file", "", "file containing the bearer token")
	allowInsecure := fs.Bool("allow-insecure-http", false, "allow plain HTTP to a non-loopback, non-Tailscale host")
	maxDownloadBytes := fs.Int64("max-download-bytes", defaultMaxPullDownloadBytes, "maximum size in bytes per downloaded inbox file")
	maxTotalBytes := fs.Int64("max-total-bytes", defaultMaxPullTotalBytes, "maximum total bytes downloaded in one pull")
	ioTimeout := fs.Duration("io-timeout", defaultPullIOTimeout, "per-read I/O timeout for server requests")
	tsIfaces := fs.String("tailscale-interfaces", "", "extra interface names accepted as Tailscale for plain http to 100.64.0.0/10 (comma separated; utun* and tailscale* always are)")
	jsonFlag := fs.Bool("json", false, "one JSON object per line (for the Mac app)")
	js := jsonLines{a.stdout}
	// fail prints the final "error" record in --json mode (fixed code, no text).
	fail := func(code string, err error) error {
		if *jsonFlag {
			if code == "" {
				code = jsonErrCode(err)
			}
			js.rec("error", "code", code)
		}
		return err
	}
	if _, err := parse(fs, args, 0, 0); err != nil {
		return fail("", err)
	}
	if *maxDownloadBytes <= 0 {
		return fail("", errors.New("pull: --max-download-bytes must be positive"))
	}
	if *maxTotalBytes <= 0 {
		return fail("", errors.New("pull: --max-total-bytes must be positive"))
	}
	if *ioTimeout <= 0 {
		return fail("", errors.New("pull: --io-timeout must be positive"))
	}
	opts := pullOpts{
		maxDownloadBytes: *maxDownloadBytes,
		maxTotalBytes:    *maxTotalBytes,
		ioTimeout:        *ioTimeout,
	}

	serverURL := *serverFlag
	if serverURL == "" {
		serverURL = os.Getenv("NDES_SERVER")
	}
	if serverURL == "" {
		return fail("server-url", errors.New("pull: --server (or $NDES_SERVER) is required"))
	}
	baseURL, err := validatePullServerURL(serverURL, *allowInsecure)
	if err != nil {
		return fail("server-url", fmt.Errorf("pull: %w", err))
	}
	extraIfaces := splitList(*tsIfaces)
	if err := checkTailscaleRoute(baseURL, extraIfaces); err != nil {
		return fail("route", fmt.Errorf("pull: %w", err))
	}
	if *tokenFileFlag == "" {
		return fail("token-file", errors.New("pull: --token-file is required"))
	}
	token, err := readPullTokenFile(*tokenFileFlag)
	if err != nil {
		return fail("token-file", fmt.Errorf("pull: %w", err))
	}
	if *jsonFlag {
		// The token file has been read and closed; no network request yet.
		js.rec("started")
	}
	defer func() {
		// Strings are immutable in Go, but we keep token scoped to cmdPull.
		token = ""
	}()

	// Open the vault directory once before any passphrase prompt (SPEC 8).
	v, err := a.openVault(a.vaultDir())
	if err != nil {
		return fail("", err)
	}
	defer v.Close()

	inboxD, err := v.openSub(core.InboxDir)
	if err != nil {
		return fail("vault-unreadable", err)
	}
	defer inboxD.Close()

	// Recommendation #4 (D-R2): clean up stale .ndes-*.part files in <vault>/inbox/
	// left by any earlier crashed pull before prompting or downloading.
	cleanStaleInboxParts(inboxD)

	keys, err := a.unlock(v)
	if err != nil {
		return fail("", err)
	}
	defer keys.Wipe()

	var rt http.RoundTripper = newPullTransport(opts.ioTimeout)
	if pullTestTransport != nil {
		rt = pullTestTransport
	}
	client := &http.Client{
		Timeout:   0, // streaming downloads can be large; per-read progress is guarded by pullProgressReader
		Transport: rt,
		// Never follow redirects so the Bearer token cannot be leaked to another host.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ids, err := fetchInboxIDs(client, baseURL, token, opts)
	if err != nil {
		return fail("", fmt.Errorf("pull: %w", err))
	}

	scratch, err := os.MkdirTemp("", "ndes-pull-") // 0700, unpredictable name, local temp (not the vault)
	if err != nil {
		return fail("", fmt.Errorf("pull: %w", err))
	}
	removeHook := addCleanupHook(func() { os.RemoveAll(scratch) })
	defer func() { removeHook(); os.RemoveAll(scratch) }()
	totalLeft := opts.maxTotalBytes

	var ingested, already, failed, deleteFailed int
	// report counts a failed file; typ/id/code feed the --json record (id ""
	// when the server's id was not valid).
	report := func(msg, typ, id, code string) {
		failed++
		fmt.Fprintf(a.stderr, "error: %s\n", msg)
		if !*jsonFlag {
			return
		}
		if typ == "error" {
			if id == "" {
				js.rec("error", "code", code, "item", true)
			} else {
				js.rec("error", "id", id, "code", code)
			}
		} else {
			js.rec(typ, "id", id)
		}
	}

	for _, idStr := range ids {
		id, err := core.ParseFileID(idStr)
		if err != nil {
			report(fmt.Sprintf("server returned invalid file_id %s: %v", display(idStr), err), "error", "", "invalid-id")
			continue
		}
		inName := core.InboxName(id)
		rel := path.Join(core.InboxDir, inName)
		// H1: the route can change after sleep; check again before each file and never
		// fall back to another route.
		if err := checkTailscaleRoute(baseURL, extraIfaces); err != nil {
			return fail("route", fmt.Errorf("pull: %w (this and the remaining files stay on the server)", err))
		}

		// M2: a download is authenticated in a private temp directory outside the
		// vault first. Only a file that passes is copied into <vault>/inbox/. A file
		// already in the inbox (an earlier run, or `ndes ingest` input) is used as is.
		if _, lerr := inboxD.lstat(inName); errors.Is(lerr, os.ErrNotExist) {
			if totalLeft <= 0 {
				report(fmt.Sprintf("%s: --max-total-bytes (%d) reached; remaining files stay on the server", display(rel), opts.maxTotalBytes), "error", id.String(), "too-large")
				break
			}
			n, err := fetchAuthenticated(client, baseURL, token, id, keys, inboxD, inName, scratch, opts, totalLeft)
			totalLeft -= n
			if errors.Is(err, errNotAuthentic) {
				report(fmt.Sprintf("%s: not authentic (made without this vault's K_auth, or damaged): %v (left on the server, nothing stored in the vault)", display(rel), err), "not-authentic", id.String(), "")
				continue
			}
			if err != nil {
				report(fmt.Sprintf("%s: download failed: %v", display(rel), err), "error", id.String(), "download")
				continue
			}
		} else if lerr != nil {
			report(fmt.Sprintf("%s: %v", display(rel), lerr), "error", id.String(), "local")
			continue
		}

		// Authenticate and ingest into <vault>/objects/<xx>/<id>.obj (with
		// read-back verification or CheckAlreadyIngested, SPEC 6.3).
		f := vaultFile{rel: rel, name: inName, id: id}
		result, err := ingestOne(v, inboxD, f, keys)
		switch {
		case errors.Is(err, core.ErrAuth):
			report(fmt.Sprintf("%s: not authentic (made without this vault's K_auth, or damaged): %v (inbox file kept, not deleted from server)", display(rel), err), "not-authentic", id.String(), "")
			continue
		case errors.Is(err, core.ErrConflict):
			report(fmtProblem(rel, err)+" (inbox file kept, not deleted from server)", "conflict", id.String(), "")
			continue
		case err != nil:
			report(fmtProblem(rel, err)+" (inbox file kept, not deleted from server)", "error", id.String(), "ingest")
			continue
		case result == "already":
			already++
			if *jsonFlag {
				js.rec("already-ingested", "id", id.String())
			}
		default:
			ingested++
			if *jsonFlag {
				js.rec("ingested", "id", id.String())
			}
		}

		// CRITICAL GATE (SPEC 6.3, 8): DELETE /inbox/{id} on the server is called
		// ONLY after ingestOne has succeeded with nil error (meaning either
		// verified read-back of the new object or verified CheckAlreadyIngested).
		if err := deleteRemoteInboxFile(client, baseURL, token, id, opts); err != nil {
			deleteFailed++
			fmt.Fprintf(a.stderr, "warning: %s ingested locally, but server delete failed (%v); next pull will absorb it via idempotency\n", id, err)
		}
	}

	if *jsonFlag {
		js.rec("end", "ingested", ingested, "already", already, "failed", failed, "delete_failed", deleteFailed)
	} else {
		fmt.Fprintf(a.stdout, "ingested %d, already ingested %d, failed %d\n", ingested, already, failed)
	}
	if failed > 0 {
		return fmt.Errorf("%d inbox file(s) could not be pulled", failed)
	}
	return nil
}

// newPullTransport never uses HTTP_PROXY/HTTPS_PROXY/ALL_PROXY (L4): the bearer token and the
// sealed files go straight to the configured server, never through a proxy that the
// environment names. (This also means a proxy cannot be used on purpose; the Mac app already
// behaves the same way.)
func newPullTransport(ioTimeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: ioTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func cleanStaleInboxParts(inboxD *dirHandle) {
	entries, err := inboxD.list()
	if err != nil {
		return
	}
	for _, e := range entries {
		if pullPartRE.MatchString(e.Name()) && e.Type().IsRegular() {
			inboxD.removeIfStale(e.Name()) // only old, unlocked leftovers (L10)
		}
	}
}

var (
	tailscaleIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleIPv6Prefix = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

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

func fetchInboxIDs(client *http.Client, baseURL, token string, opts pullOpts) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opts.ioTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/inbox", nil)
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
		return nil, &httpStatusError{resp.StatusCode, fmt.Sprintf("GET /inbox: HTTP %d", resp.StatusCode)}
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

// pullProgressReader wraps a download response body with a per-Read watchdog
// timer so a stalling server cancels the request context and closes the body
// after opts.ioTimeout of inactivity (VALV-REV2-02).
type pullProgressReader struct {
	r       io.ReadCloser
	timeout time.Duration
	ctx     context.Context
	cancel  context.CancelCauseFunc
}

func (p *pullProgressReader) Read(buf []byte) (int, error) {
	timer := time.AfterFunc(p.timeout, func() {
		p.cancel(fmt.Errorf("download read timed out after %v", p.timeout))
		_ = p.r.Close()
	})
	n, err := p.r.Read(buf)
	timer.Stop()
	if err != nil {
		if cause := context.Cause(p.ctx); cause != nil && !errors.Is(cause, context.Canceled) {
			return n, cause
		}
	}
	return n, err
}

var errNotAuthentic = errors.New("not authentic")

// fetchAuthenticated downloads inbox file id into scratch (outside the vault),
// authenticates it with core.VerifyInbox, and only then copies it to
// <vault>/inbox/<inName>. It returns the bytes downloaded (for the total cap).
// A file that fails authentication returns core.ErrAuth and leaves no trace.
func fetchAuthenticated(client *http.Client, baseURL, token string, id core.FileID, keys *core.VaultKeys, inboxD *dirHandle, inName, scratch string, opts pullOpts, totalLeft int64) (int64, error) {
	var nameBytes [8]byte
	if _, err := rand.Read(nameBytes[:]); err != nil {
		return 0, err
	}
	tmp := filepath.Join(scratch, hex.EncodeToString(nameBytes[:])+".dl")
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp)
	defer f.Close()
	limit := min(opts.maxDownloadBytes, totalLeft)
	n, err := downloadInboxFile(client, baseURL, token, id, f, limit, opts)
	if err != nil {
		return n, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return n, err
	}
	if _, err := core.VerifyInbox(bufio.NewReaderSize(f, core.StoredChunkSize), n, id, keys); err != nil {
		if errors.Is(err, core.ErrAuth) || errors.Is(err, core.ErrMalformed) || errors.Is(err, core.ErrUnsupported) {
			return n, fmt.Errorf("%w: %v", errNotAuthentic, err)
		}
		return n, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return n, err
	}
	err = writeAt(inboxD, inName, writeOpts{overwrite: false}, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, core.StoredChunkSize)
		if _, err := io.Copy(bw, f); err != nil {
			return err
		}
		return bw.Flush()
	})
	return n, err
}

// downloadInboxFile streams GET /inbox/{id} into dst, at most limit bytes.
func downloadInboxFile(client *http.Client, baseURL, token string, id core.FileID, dst io.Writer, limit int64, opts pullOpts) (int64, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/inbox/"+id.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	hdrTimer := time.AfterFunc(opts.ioTimeout, func() {
		cancel(fmt.Errorf("download timed out after %v", opts.ioTimeout))
	})
	resp, err := client.Do(req)
	hdrTimer.Stop()
	if err != nil {
		if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
			return 0, cause
		}
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET /inbox/%s: HTTP %d", id, resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return 0, fmt.Errorf("remote inbox file size (%d bytes) exceeds maximum download size (%d bytes)", resp.ContentLength, limit)
	}
	pr := &pullProgressReader{r: resp.Body, timeout: opts.ioTimeout, ctx: ctx, cancel: cancel}
	bw := bufio.NewWriterSize(dst, core.StoredChunkSize)
	n, err := io.Copy(bw, io.LimitReader(pr, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, fmt.Errorf("remote inbox file exceeds maximum download size (%d bytes)", limit)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return n, io.ErrUnexpectedEOF
	}
	return n, bw.Flush()
}

func deleteRemoteInboxFile(client *http.Client, baseURL, token string, id core.FileID, opts pullOpts) error {
	ctx, cancel := context.WithTimeout(context.Background(), opts.ioTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/inbox/"+id.String(), nil)
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
