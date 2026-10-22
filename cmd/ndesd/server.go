package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/klppl/sendndes/core"
	"golang.org/x/sys/unix"
)

const (
	defaultMaxUploadBytes = 4 << 30 // 4 GiB
	// maxPlaintextBytes is the per-file limit the phone app enforces (90 MiB); a sealed upload is that plus
	// padding, tags and the header, so the server's limit for it is one MiB more.
	maxPlaintextBytes        = 90 << 20
	defaultMaxSealedBytes    = maxPlaintextBytes + 1<<20
	defaultIOTimeout         = 30 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultReadHeaderTimeout = 10 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultMaxHeaderBytes    = 65536
	defaultMaxConcurrentPUTs = 4
	defaultMaxConcurrentReqs = 32
	defaultMaxInboxFiles     = 10000
	defaultSlotWaitTimeout   = 5 * time.Second
	defaultMaxInboxBytes     = int64(2) << 30   // 2 GiB of stored inbox files
	defaultMinFreeBytes      = int64(256) << 20 // free space left alone on the file system
	defaultMinUploadRate     = int64(64) << 10  // bytes per second, for the overall upload deadline
	uploadBaseTimeout        = 60 * time.Second // fixed part of the overall upload deadline
	authRateBurst            = 5
	authRateRefillInterval   = time.Second
	maxRateLimiterTrackedIPs = 4096
)

type serverOpts struct {
	maxUploadBytes    int64
	ioTimeout         time.Duration
	writeTimeout      time.Duration
	maxConcurrentPUTs int
	maxConcurrentReqs int
	maxInboxFiles     int
	slotWaitTimeout   time.Duration
	maxInboxBytes     int64         // sum of stored .inb bytes (L2)
	minFreeBytes      int64         // 0 = no margin
	minUploadRate     int64         // bytes/s: deadline = uploadBase + length/rate (L3)
	uploadBase        time.Duration // fixed part of that deadline (default uploadBaseTimeout)

	maxSealedBytes      int64  // largest PUT /inbox/{id} body (default defaultMaxSealedBytes)
	enableServerSealing bool   // PUT /inbox with X-Ndes-* headers; needs inbox_pub and k_auth (off by default)
	clientIPHeader      string // header that names the client behind a loopback proxy (empty = ignore headers)
}

func defaultServerOpts() serverOpts {
	return serverOpts{
		maxUploadBytes:    defaultMaxUploadBytes,
		ioTimeout:         defaultIOTimeout,
		writeTimeout:      defaultWriteTimeout,
		maxConcurrentPUTs: defaultMaxConcurrentPUTs,
		maxConcurrentReqs: defaultMaxConcurrentReqs,
		maxInboxFiles:     defaultMaxInboxFiles,
		slotWaitTimeout:   defaultSlotWaitTimeout,
		maxInboxBytes:     defaultMaxInboxBytes,
		minFreeBytes:      defaultMinFreeBytes,
		minUploadRate:     defaultMinUploadRate,
		maxSealedBytes:    defaultMaxSealedBytes,

		enableServerSealing: true, // tests only: main and managed mode set their own options
	}
}

// inboxServer implements the SPEC 8 Mode B HTTP API.
// It holds the SHA-256 of each accepted token and, only when server-side sealing is
// enabled, inbox_pub and k_auth. It never logs filenames, metadata, sizes,
// contents, or tokens (SPEC 10 rule 4).
type inboxServer struct {
	dir      *dirHandle
	reg      *tempRegistry
	inboxPub [core.KeySize]byte // only with opts.enableServerSealing
	kAuth    [core.KeySize]byte // only with opts.enableServerSealing
	tokens   atomic.Pointer[tokenSet]
	opts     serverOpts
	putSem   chan struct{}
	reqSem   chan struct{}
	quotaMu  sync.Mutex
	bytes    byteQuota // guarded by quotaMu
	authRL   *ipRateLimiter
	baseCtx  context.Context
	slotMu   sync.Mutex
	slots    map[string]int // uploads in progress per token label

	pair       *pairing // nil: device pairing is not offered
	pairReqRL  *ipRateLimiter
	pairStatRL *ipRateLimiter
}

// setPairing turns on device pairing (see pairing.go).
func (s *inboxServer) setPairing(p *pairing) {
	s.pair = p
	s.pairReqRL = newIPRateLimiter(5, 20*time.Second)
	s.pairStatRL = newIPRateLimiter(60, 500*time.Millisecond)
}

// newInboxServer builds the handler. cfg may be nil unless opts.enableServerSealing is set; a token in
// cfg (the legacy single token) is accepted with the role both. Further tokens come from setTokens.
func newInboxServer(baseCtx context.Context, dir *dirHandle, reg *tempRegistry, cfg *serverConfig, opts serverOpts) *inboxServer {
	if opts.maxSealedBytes <= 0 {
		opts.maxSealedBytes = defaultMaxSealedBytes
	}
	if opts.maxUploadBytes <= 0 {
		opts.maxUploadBytes = defaultMaxUploadBytes
	}
	if opts.ioTimeout <= 0 {
		opts.ioTimeout = defaultIOTimeout
	}
	if opts.writeTimeout <= 0 {
		opts.writeTimeout = defaultWriteTimeout
	}
	if opts.maxConcurrentPUTs <= 0 {
		opts.maxConcurrentPUTs = defaultMaxConcurrentPUTs
	}
	if opts.maxConcurrentReqs <= 0 {
		opts.maxConcurrentReqs = defaultMaxConcurrentReqs
	}
	if opts.maxInboxFiles <= 0 {
		opts.maxInboxFiles = defaultMaxInboxFiles
	}
	if opts.slotWaitTimeout <= 0 {
		opts.slotWaitTimeout = defaultSlotWaitTimeout
	}
	if opts.maxInboxBytes <= 0 {
		opts.maxInboxBytes = defaultMaxInboxBytes
	}
	if opts.minFreeBytes < 0 {
		opts.minFreeBytes = defaultMinFreeBytes
	}
	if opts.minUploadRate <= 0 {
		opts.minUploadRate = defaultMinUploadRate
	}
	if opts.uploadBase <= 0 {
		opts.uploadBase = uploadBaseTimeout
	}
	s := &inboxServer{
		bytes:   byteQuota{max: opts.maxInboxBytes, minFree: opts.minFreeBytes},
		dir:     dir,
		reg:     reg,
		opts:    opts,
		putSem:  make(chan struct{}, opts.maxConcurrentPUTs),
		reqSem:  make(chan struct{}, opts.maxConcurrentReqs),
		authRL:  newIPRateLimiter(authRateBurst, authRateRefillInterval),
		baseCtx: baseCtx,
	}
	if cfg != nil {
		if opts.enableServerSealing {
			s.inboxPub, s.kAuth = cfg.InboxPub, cfg.KAuth
		}
		if len(cfg.Token) > 0 {
			s.tokens.Store(legacyTokenSet(cfg.Token))
		}
	}
	if s.tokens.Load() == nil {
		s.tokens.Store(&tokenSet{})
	}
	return s
}

// setTokens swaps the accepted tokens atomically (startup, SIGHUP reload).
func (s *inboxServer) setTokens(t *tokenSet) { s.tokens.Store(t) }

func (s *inboxServer) Wipe() {
	clear(s.inboxPub[:])
	clear(s.kAuth[:])
}

func (s *inboxServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Global concurrency limit.
	select {
	case s.reqSem <- struct{}{}:
		defer func() { <-s.reqSem }()
	default:
		httpError(w, http.StatusTooManyRequests, "too many concurrent requests")
		return
	}

	// Nothing here may be cached by a proxy (an authenticated GET must never be served to someone else).
	w.Header().Set("Cache-Control", "no-store")
	key := s.clientKey(r)
	if s.pair != nil && s.servePairPublic(w, r, key) {
		return
	}
	role, label, ok := s.authenticate(r)
	if !ok {
		// A wrong or missing token costs the caller a point in its bucket; a valid token is never
		// looked at by the limiter (S4), so a flood of bad guesses cannot lock out the real client.
		if !s.authRL.allow(key, time.Now()) {
			httpError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Reject any query string on all endpoints.
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		httpError(w, http.StatusBadRequest, "unexpected query parameters")
		return
	}

	path := r.URL.Path
	if s.pair != nil && (strings.HasPrefix(path, "/v1/pair/") || strings.HasPrefix(path, "/v1/devices")) {
		if role != roleBoth {
			forbidden(w)
			return
		}
		s.servePairOwner(w, r)
		return
	}
	switch {
	case path == "/v1/ping":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case path == "/inbox":
		switch r.Method {
		case http.MethodPut:
			if !s.opts.enableServerSealing {
				httpError(w, http.StatusNotFound, "not found")
				return
			}
			// Server-side sealing makes files that ingest accepts (it holds k_auth), so an upload-only token must
			// not reach it: only a token that may also pull (the owner's) can.
			if role != roleBoth {
				forbidden(w)
				return
			}
			s.handlePutInbox(w, r)
		case http.MethodGet:
			if !role.canPull() {
				forbidden(w)
				return
			}
			s.handleListInbox(w, r)
		default:
			w.Header().Set("Allow", "GET, PUT")
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case strings.HasPrefix(path, "/inbox/"):
		idStr := strings.TrimPrefix(path, "/inbox/")
		if idStr == "" || strings.ContainsRune(idStr, '/') {
			httpError(w, http.StatusBadRequest, "invalid file_id")
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !role.canPull() {
				forbidden(w)
				return
			}
			s.handleGetInboxFile(w, r, idStr)
		case http.MethodDelete:
			if !role.canPull() {
				forbidden(w)
				return
			}
			s.handleDeleteInboxFile(w, r, idStr)
		case http.MethodPut:
			if !role.canUpload() {
				forbidden(w)
				return
			}
			release, ok := s.acquireTokenSlot(label)
			if !ok {
				httpError(w, http.StatusTooManyRequests, "too many uploads in progress for this token")
				return
			}
			defer release()
			s.handlePutClientSealedInbox(w, r, idStr)
		default:
			w.Header().Set("Allow", "GET, DELETE, PUT")
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		httpError(w, http.StatusNotFound, "not found")
	}
}

func forbidden(w http.ResponseWriter) {
	httpError(w, http.StatusForbidden, "this token may not do that")
}

// clientKey names the caller for the failed-authentication limiter: the TCP peer, or, only when
// --client-ip-header is set AND the peer is loopback (a proxy or tunnel on this host) AND the header
// holds exactly one IP address, that address. X-Forwarded-For is never used.
func (s *inboxServer) clientKey(r *http.Request) string {
	peer := clientIP(r.RemoteAddr)
	if s.opts.clientIPHeader == "" {
		return limiterKey(peer)
	}
	if ip := net.ParseIP(peer); ip == nil || !ip.IsLoopback() {
		return limiterKey(peer)
	}
	vals := r.Header.Values(s.opts.clientIPHeader)
	if len(vals) != 1 {
		return limiterKey(peer)
	}
	v := strings.TrimSpace(vals[0])
	if strings.ContainsAny(v, ", %") {
		return limiterKey(peer)
	}
	if ip := net.ParseIP(v); ip != nil {
		return limiterKey(ip.String())
	}
	return limiterKey(peer)
}

// limiterKey is the address the failed-attempt limiter counts: an IPv6 client is counted per /64 (one
// customer's whole prefix), so rotating through addresses of one prefix does not give a fresh bucket.
func limiterKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// authenticate checks the Authorization: Bearer <token> header against the accepted tokens in
// constant time and returns the token's role. len(token) <= 512 is enforced before hashing (D-R2).
func (s *inboxServer) authenticate(r *http.Request) (tokenRole, string, bool) {
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		return 0, "", false
	}
	auth := vals[0]
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return 0, "", false
	}
	got := auth[len(prefix):]
	if len(got) == 0 || len(got) > maxTokenLen {
		return 0, "", false
	}
	return s.tokens.Load().lookup(got)
}

// maxUploadsPerToken keeps one token (a phone, or someone holding its token) from taking every upload slot.
const maxUploadsPerToken = 2

func (s *inboxServer) acquireTokenSlot(label string) (func(), bool) {
	s.slotMu.Lock()
	defer s.slotMu.Unlock()
	if s.slots == nil {
		s.slots = map[string]int{}
	}
	if s.slots[label] >= maxUploadsPerToken {
		return nil, false
	}
	s.slots[label]++
	return func() {
		s.slotMu.Lock()
		defer s.slotMu.Unlock()
		if s.slots[label]--; s.slots[label] <= 0 {
			delete(s.slots, label)
		}
	}, true
}

// knownNdesHeaders lists every X-Ndes-* header accepted by PUT /inbox.
var knownNdesHeaders = map[string]bool{
	"X-Ndes-Name":     true,
	"X-Ndes-Name-B64": true,
	"X-Ndes-Dir":      true,
	"X-Ndes-Dir-B64":  true,
	"X-Ndes-Mtime":    true,
	"X-Ndes-Mime":     true,
	"X-Ndes-Mime-B64": true,
}

// parseUploadMetadata extracts and validates metadata from PUT /inbox headers.
// Per review recommendation #1 (D-R2), any duplicate X-Ndes-* header
// (len(r.Header.Values(h)) > 1) or unknown X-Ndes-* header is rejected.
func parseUploadMetadata(h http.Header) (core.Metadata, error) {
	for k, vals := range h {
		ck := http.CanonicalHeaderKey(k)
		if strings.HasPrefix(ck, "X-Ndes-") {
			if !knownNdesHeaders[ck] {
				return core.Metadata{}, errors.New("unknown X-Ndes-* header")
			}
			if len(vals) > 1 {
				return core.Metadata{}, errors.New("duplicate metadata header")
			}
		}
	}

	name, hasName, err := extractDualHeader(h, "X-Ndes-Name", "X-Ndes-Name-B64", true)
	if err != nil || !hasName {
		return core.Metadata{}, errors.New("invalid or missing file name header")
	}
	dir, _, err := extractDualHeader(h, "X-Ndes-Dir", "X-Ndes-Dir-B64", false)
	if err != nil {
		return core.Metadata{}, errors.New("invalid dir header")
	}
	mimeVal, _, err := extractDualHeader(h, "X-Ndes-Mime", "X-Ndes-Mime-B64", false)
	if err != nil {
		return core.Metadata{}, errors.New("invalid mime header")
	}

	mtime := time.Now().UnixNano()
	if mtimeVals := h.Values("X-Ndes-Mtime"); len(mtimeVals) == 1 {
		parsed, ok := parseStrictInt64(mtimeVals[0])
		if !ok {
			return core.Metadata{}, errors.New("invalid mtime header")
		}
		mtime = parsed
	}

	meta := core.Metadata{
		Name:  name,
		Dir:   dir,
		MTime: mtime,
		MIME:  mimeVal,
		Rev:   1,
	}
	// Validate and normalize before touching disk (SPEC 5.2).
	if _, meta, err = core.EncodeMetadata(meta); err != nil {
		return core.Metadata{}, errors.New("invalid metadata")
	}
	return meta, nil
}

func extractDualHeader(h http.Header, plainKey, b64Key string, disallowTrimmedSpace bool) (string, bool, error) {
	plainVals := h.Values(plainKey)
	b64Vals := h.Values(b64Key)
	if len(plainVals) > 1 || len(b64Vals) > 1 {
		return "", false, errors.New("duplicate header")
	}
	if len(plainVals) == 1 && len(b64Vals) == 1 {
		return "", false, errors.New("both plain and b64 headers specified")
	}
	if len(b64Vals) == 1 {
		if b64Vals[0] == "" {
			return "", true, nil
		}
		raw, err := strictB64.DecodeString(b64Vals[0])
		if err != nil || !utf8.Valid(raw) {
			return "", false, errors.New("invalid base64 or UTF-8")
		}
		return string(raw), true, nil
	}
	if len(plainVals) == 1 {
		s := plainVals[0]
		if disallowTrimmedSpace && (strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ")) {
			return "", false, errors.New("plain header has leading or trailing space")
		}
		for i := 0; i < len(s); i++ {
			if s[i] < 0x20 || s[i] > 0x7e {
				return "", false, errors.New("plain header contains non-ASCII or control bytes")
			}
		}
		return s, true, nil
	}
	return "", false, nil
}

// parseStrictInt64 parses a canonical decimal int64 (no '+', no leading zeros,
// no "-0", no whitespace).
func parseStrictInt64(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	start := 0
	if s[0] == '-' {
		start = 1
	}
	digits := s[start:]
	if len(digits) == 0 {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	if digits[0] == '0' && (len(digits) > 1 || start > 0) {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func (s *inboxServer) handlePutInbox(w http.ResponseWriter, r *http.Request) {
	// Parse and validate metadata before acquiring an upload slot or creating a temp file.
	meta, err := parseUploadMetadata(r.Header)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The stored content is padded (SPEC 5.3), and the size goes into the metadata
	// before the content is read, so the length must be declared up front.
	if r.ContentLength < 0 {
		httpError(w, http.StatusLengthRequired, "Content-Length required")
		return
	}
	meta.Size = r.ContentLength

	// Reject known Content-Length exceeding maxUploadBytes immediately.
	if r.ContentLength > s.opts.maxUploadBytes {
		httpError(w, http.StatusRequestEntityTooLarge, "upload exceeds maximum size")
		return
	}

	// Concurrency semaphore for uploads.
	timer := time.NewTimer(s.opts.slotWaitTimeout)
	defer timer.Stop()
	select {
	case s.putSem <- struct{}{}:
		defer func() { <-s.putSem }()
	case <-timer.C:
		httpError(w, http.StatusTooManyRequests, "upload concurrency limit reached")
		return
	case <-r.Context().Done():
		return
	}

	rc := http.NewResponseController(w)
	limitedBody := http.MaxBytesReader(w, r.Body, s.opts.maxUploadBytes)
	defer limitedBody.Close()

	bodyReader := &streamBodyReader{
		r:             limitedBody,
		rc:            rc,
		ioTimeout:     s.opts.ioTimeout,
		contentLength: r.ContentLength,
		reqCtx:        r.Context(),
		srvCtx:        s.baseCtx,
		deadline:      s.uploadDeadline(r.ContentLength, time.Now()),
	}

	// L2: refuse at once what cannot fit (declared length vs the byte quota and the free space).
	need := sealedEstimate(r.ContentLength)
	id, err := writeInboxAt(s.dir, s.reg, &s.quotaMu, s.opts.maxInboxFiles, &s.bytes, need, func(fileWriter io.Writer, budget int64) (core.FileID, int64, error) {
		cw := &countingWriter{w: &budgetWriter{w: fileWriter, left: budget, limited: budget > 0}}
		bw := bufio.NewWriterSize(cw, core.StoredChunkSize)
		sealedID, err := core.SealInbox(bw, s.inboxPub, s.kAuth, meta, bodyReader)
		if err != nil {
			return core.FileID{}, 0, err
		}
		if err := bodyReader.verifyComplete(); err != nil {
			return core.FileID{}, 0, err
		}
		if err := bw.Flush(); err != nil {
			return core.FileID{}, 0, err
		}
		return sealedID, cw.n, nil
	})
	if err != nil {
		status, msg := putErrorResponse(err)
		httpError(w, status, msg)
		return
	}

	_ = rc.SetWriteDeadline(time.Now().Add(s.opts.writeTimeout))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"id":"`+id.String()+`"}`+"\n")
}

// putErrorResponse maps a failed upload to its HTTP status and (fixed) message. 507 has three
// distinct bodies so clients can tell them apart: file limit, byte limit, out of space (L2).
func putErrorResponse(err error) (int, string) {
	var maxBytesErr *http.MaxBytesError
	switch {
	case errors.Is(err, errQuotaExceeded):
		return http.StatusInsufficientStorage, "inbox file limit reached"
	case errors.Is(err, errBytesQuota):
		return http.StatusInsufficientStorage, "inbox byte limit reached"
	case errors.Is(err, errNoSpace) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT):
		return http.StatusInsufficientStorage, "server out of space"
	case errors.Is(err, errStorage):
		return http.StatusInternalServerError, "storage error"
	case errors.As(err, &maxBytesErr):
		return http.StatusRequestEntityTooLarge, "upload exceeds maximum size"
	case errors.Is(err, errUploadTooSlow):
		return http.StatusRequestTimeout, "upload too slow"
	case errors.Is(err, errStreamTruncated) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, core.ErrContentSize):
		return http.StatusBadRequest, "incomplete upload stream"
	case isTimeoutError(err):
		return http.StatusRequestTimeout, "upload timed out"
	case errors.Is(err, core.ErrMalformed) || errors.Is(err, core.ErrUnsupported) || errors.Is(err, core.ErrPathMismatch):
		return http.StatusBadRequest, "malformed inbox file"
	default:
		return http.StatusBadRequest, "upload failed"
	}
}

func (s *inboxServer) handlePutClientSealedInbox(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := core.ParseFileID(idStr)
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid file_id")
		return
	}

	// Reject any metadata headers: client-sealed uploads contain sealed metadata inside meta_blob.
	for k := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Ndes-") {
			httpError(w, http.StatusBadRequest, "metadata headers not allowed on client-sealed upload")
			return
		}
	}

	// Every upload declares its length (budget admission and the overall deadline need it).
	if r.ContentLength < 0 {
		httpError(w, http.StatusLengthRequired, "Content-Length required")
		return
	}

	// Reject known Content-Length exceeding the sealed-upload limit immediately.
	if r.ContentLength > s.opts.maxSealedBytes {
		httpError(w, http.StatusRequestEntityTooLarge, "upload exceeds maximum size")
		return
	}

	// Concurrency semaphore for uploads.
	timer := time.NewTimer(s.opts.slotWaitTimeout)
	defer timer.Stop()
	select {
	case s.putSem <- struct{}{}:
		defer func() { <-s.putSem }()
	case <-timer.C:
		httpError(w, http.StatusTooManyRequests, "upload concurrency limit reached")
		return
	case <-r.Context().Done():
		return
	}

	rc := http.NewResponseController(w)
	limitedBody := http.MaxBytesReader(w, r.Body, s.opts.maxSealedBytes)
	defer limitedBody.Close()

	bodyReader := &streamBodyReader{
		r:             limitedBody,
		rc:            rc,
		ioTimeout:     s.opts.ioTimeout,
		contentLength: r.ContentLength,
		reqCtx:        r.Context(),
		srvCtx:        s.baseCtx,
		deadline:      s.uploadDeadline(r.ContentLength, time.Now()),
	}

	// L11: Idempotency check. If the file already exists, check whether the incoming
	// stream is identical. If identical, return 200 OK (no-op). If different, return 409 Conflict.
	name := core.InboxName(id)
	existingFile, existingSize, openErr := s.dir.openFile(name)
	if openErr == nil {
		defer existingFile.Close()
		same, compErr := compareStreams(existingFile, existingSize, bodyReader)
		if compErr != nil {
			status, msg := putErrorResponse(compErr)
			httpError(w, status, msg)
			return
		}
		if err := bodyReader.verifyComplete(); err != nil {
			status, msg := putErrorResponse(err)
			httpError(w, status, msg)
			return
		}
		if !same {
			httpError(w, http.StatusConflict, "file_id already exists with different content")
			return
		}
		_ = rc.SetWriteDeadline(time.Now().Add(s.opts.writeTimeout))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"`+id.String()+`"}`+"\n")
		return
	}

	need := r.ContentLength

	writtenID, err := writeInboxAt(s.dir, s.reg, &s.quotaMu, s.opts.maxInboxFiles, &s.bytes, need, func(fileWriter io.Writer, budget int64) (core.FileID, int64, error) {
		cw := &countingWriter{w: &budgetWriter{w: fileWriter, left: budget, limited: budget > 0}}
		bw := bufio.NewWriterSize(cw, core.StoredChunkSize)
		n, valErr := core.ValidateAndCopyInbox(bw, bodyReader, id)
		if valErr != nil {
			return core.FileID{}, 0, valErr
		}
		if err := bodyReader.verifyComplete(); err != nil {
			return core.FileID{}, 0, err
		}
		if err := bw.Flush(); err != nil {
			return core.FileID{}, 0, err
		}
		return id, n, nil
	})
	if err != nil {
		// Two uploads of one id raced and this one lost: identical bytes are a successful retry.
		if errors.Is(err, errExists) {
			if errors.Is(err, errExistsIdentical) {
				_ = rc.SetWriteDeadline(time.Now().Add(s.opts.writeTimeout))
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"id":"`+id.String()+`"}`+"\n")
				return
			}
			httpError(w, http.StatusConflict, "file_id already exists with different content")
			return
		}
		status, msg := putErrorResponse(err)
		httpError(w, status, msg)
		return
	}

	_ = rc.SetWriteDeadline(time.Now().Add(s.opts.writeTimeout))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"id":"`+writtenID.String()+`"}`+"\n")
}

// compareStreams compares an existing file stream with an incoming reader byte-for-byte.
func compareStreams(existing io.Reader, existingSize int64, incoming io.Reader) (bool, error) {
	buf1 := make([]byte, core.StoredChunkSize)
	buf2 := make([]byte, core.StoredChunkSize)
	var totalRead int64
	for {
		n1, err1 := io.ReadFull(existing, buf1)
		if err1 != nil && !errors.Is(err1, io.EOF) && !errors.Is(err1, io.ErrUnexpectedEOF) {
			return false, err1
		}
		n2, err2 := io.ReadFull(incoming, buf2)
		if err2 != nil && !errors.Is(err2, io.EOF) && !errors.Is(err2, io.ErrUnexpectedEOF) {
			return false, err2
		}
		if n1 != n2 || !bytes.Equal(buf1[:n1], buf2[:n2]) {
			return false, nil
		}
		totalRead += int64(n1)
		if errors.Is(err1, io.EOF) || errors.Is(err1, io.ErrUnexpectedEOF) {
			if !errors.Is(err2, io.EOF) && !errors.Is(err2, io.ErrUnexpectedEOF) {
				var extra [1]byte
				ne, _ := incoming.Read(extra[:])
				if ne > 0 {
					return false, nil
				}
			}
			break
		}
	}
	if existingSize >= 0 && totalRead != existingSize {
		return false, nil
	}
	return true, nil
}

func (s *inboxServer) handleListInbox(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(s.opts.writeTimeout))
	ids, _, err := s.dir.listInboxIDs()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "storage error")
		return
	}
	resp := struct {
		IDs []string `json:"ids"`
	}{IDs: ids}
	data, err := json.Marshal(resp)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "encoding error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(data, '\n'))
}

func (s *inboxServer) handleGetInboxFile(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := core.ParseFileID(idStr)
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid file_id")
		return
	}
	name := core.InboxName(id)
	f, size, err := s.dir.openFile(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpError(w, http.StatusNotFound, "not found")
			return
		}
		httpError(w, http.StatusBadRequest, "cannot open inbox file")
		return
	}
	defer f.Close()

	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	dw := &deadlineWriter{w: w, rc: rc, ioTimeout: s.opts.ioTimeout}
	buf := make([]byte, core.StoredChunkSize)
	_, _ = io.CopyBuffer(dw, io.LimitReader(f, size), buf)
}

func (s *inboxServer) handleDeleteInboxFile(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := core.ParseFileID(idStr)
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid file_id")
		return
	}
	name := core.InboxName(id)
	st, err := s.dir.lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpError(w, http.StatusNotFound, "not found")
			return
		}
		httpError(w, http.StatusBadRequest, "cannot stat inbox file")
		return
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		// Never unlink directories, symlinks, FIFOs, or devices.
		httpError(w, http.StatusBadRequest, "not a regular file")
		return
	}
	if err := s.dir.unlink(name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpError(w, http.StatusNotFound, "not found")
			return
		}
		httpError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(s.opts.writeTimeout))
	w.WriteHeader(http.StatusNoContent)
}

var errStreamTruncated = errors.New("stream ended before Content-Length")
var errUploadTooSlow = errors.New("upload exceeded its overall deadline")

// uploadDeadline (L3) bounds the whole upload, not just each read: a fixed base plus the declared
// length at the minimum rate. A client that drips one byte per read timeout still loses its slot.
func (s *inboxServer) uploadDeadline(contentLength int64, now time.Time) time.Time {
	secs := contentLength / s.opts.minUploadRate
	if secs > 1<<31 {
		secs = 1 << 31
	}
	return now.Add(s.opts.uploadBase + time.Duration(secs)*time.Second)
}

// budgetWriter fails once more than `left` bytes would be written (the admitted byte budget).
type budgetWriter struct {
	w       io.Writer
	left    int64
	limited bool
}

func (b *budgetWriter) Write(p []byte) (int, error) {
	if b.limited && int64(len(p)) > b.left {
		return 0, errBytesQuota
	}
	b.left -= int64(len(p))
	return b.w.Write(p)
}

// streamBodyReader refreshes the per-read deadline via ResponseController and
// enforces exact Content-Length matching so truncated uploads are rejected.
type streamBodyReader struct {
	r             io.Reader
	rc            *http.ResponseController
	ioTimeout     time.Duration
	contentLength int64
	readBytes     int64
	reqCtx        context.Context
	srvCtx        context.Context
	deadline      time.Time // overall deadline of the upload (zero = none)
}

func (b *streamBodyReader) Read(p []byte) (int, error) {
	if err := b.reqCtx.Err(); err != nil {
		return 0, err
	}
	if b.srvCtx != nil {
		if err := b.srvCtx.Err(); err != nil {
			return 0, err
		}
	}
	now := time.Now()
	rd := now.Add(b.ioTimeout)
	if !b.deadline.IsZero() {
		if !now.Before(b.deadline) {
			return 0, errUploadTooSlow
		}
		if b.deadline.Before(rd) {
			rd = b.deadline
		}
	}
	_ = b.rc.SetReadDeadline(rd)
	n, err := b.r.Read(p)
	if err != nil && !b.deadline.IsZero() && !time.Now().Before(b.deadline) && errors.Is(err, os.ErrDeadlineExceeded) {
		err = errUploadTooSlow
	}
	b.readBytes += int64(n)
	if b.readBytes > b.contentLength {
		return n, errStreamTruncated
	}
	if err == io.EOF && b.readBytes < b.contentLength {
		return n, errStreamTruncated
	}
	return n, err
}

func (b *streamBodyReader) verifyComplete() error {
	if err := b.reqCtx.Err(); err != nil {
		return err
	}
	if b.srvCtx != nil {
		if err := b.srvCtx.Err(); err != nil {
			return err
		}
	}
	if b.readBytes != b.contentLength {
		return errStreamTruncated
	}
	return nil
}

type deadlineWriter struct {
	w         io.Writer
	rc        *http.ResponseController
	ioTimeout time.Duration
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	_ = d.rc.SetWriteDeadline(time.Now().Add(d.ioTimeout))
	return d.w.Write(p)
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func isTimeoutError(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func httpError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

type rateBucket struct {
	tokens   float64
	lastTime time.Time
}

// ipRateLimiter is a bounded per-IP token bucket for failed auth attempts.
type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
	burst   float64
	refill  time.Duration
}

func newIPRateLimiter(burst int, refill time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		buckets: make(map[string]*rateBucket),
		burst:   float64(burst),
		refill:  refill,
	}
}

func (l *ipRateLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= maxRateLimiterTrackedIPs {
			// Evict expired entries; if still full, drop the least recently seen one (never everyone's).
			for k, v := range l.buckets {
				if now.Sub(v.lastTime) > time.Duration(l.burst)*l.refill {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= maxRateLimiterTrackedIPs {
				oldest, first := "", true
				var oldestT time.Time
				for k, v := range l.buckets {
					if first || v.lastTime.Before(oldestT) {
						oldest, oldestT, first = k, v.lastTime, false
					}
				}
				delete(l.buckets, oldest)
			}
		}
		l.buckets[ip] = &rateBucket{tokens: l.burst - 1, lastTime: now}
		return true
	}
	elapsed := now.Sub(b.lastTime)
	if elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+float64(elapsed)/float64(l.refill))
		b.lastTime = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

// ---- device pairing endpoints ----

// servePairPublic answers the two calls a device makes before it has a token. It reports whether it handled r.
func (s *inboxServer) servePairPublic(w http.ResponseWriter, r *http.Request, key string) bool {
	switch {
	case r.URL.Path == "/v1/pair/request":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		if !s.pairReqRL.allow(key, time.Now()) {
			httpError(w, http.StatusTooManyRequests, "too many requests")
			return true
		}
		var req struct {
			Label      string `json:"label"`
			Role       string `json:"role"`
			SecretHash string `json:"secret_hash"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		if !readJSON(w, r, &req) {
			return true
		}
		id, code, err := s.pair.request(req.Label, req.Role, req.SecretHash, key)
		switch {
		case errors.Is(err, errPairClosed):
			apiErr(w, http.StatusForbidden, "this server is not accepting new devices right now; open the pairing window first")
		case errors.Is(err, errPairBusy):
			apiErr(w, http.StatusTooManyRequests, "too many pairing requests are waiting")
		case err != nil:
			apiErr(w, http.StatusBadRequest, "invalid pairing request")
		default:
			writeJSON(w, http.StatusCreated, map[string]any{"id": id, "code": code, "expires_in": int(pairRequestTTL.Seconds())})
		}
		return true
	case strings.HasPrefix(r.URL.Path, "/v1/pair/status/"):
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			return true
		}
		if !s.pairStatRL.allow(key, time.Now()) {
			httpError(w, http.StatusTooManyRequests, "too many requests")
			return true
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/pair/status/")
		if len(id) != 32 || r.URL.RawQuery != "" {
			httpError(w, http.StatusNotFound, "not found")
			return true
		}
		st, err := s.pair.status(id, r.Header.Get("X-Pair-Secret"))
		if err != nil {
			httpError(w, http.StatusNotFound, "not found")
			return true
		}
		writeJSON(w, http.StatusOK, st)
		return true
	}
	return false
}

// servePairOwner is for tokens with the role both (the owner's Mac).
func (s *inboxServer) servePairOwner(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	switch {
	case p == "/v1/pair/pending" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"open": s.pair.secondsOpen() > 0, "seconds_left": s.pair.secondsOpen(), "requests": s.pair.pending()})
	case p == "/v1/pair/open" && r.Method == http.MethodPost:
		var req struct {
			Minutes int `json:"minutes"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.Minutes < 1 || req.Minutes > int(pairMaxWindow.Minutes()) {
			apiErr(w, http.StatusBadRequest, "minutes must be between 1 and 60")
			return
		}
		s.pair.open(time.Duration(req.Minutes) * time.Minute)
		writeJSON(w, http.StatusOK, map[string]any{"open": true, "seconds_left": s.pair.secondsOpen()})
	case p == "/v1/pair/close" && r.Method == http.MethodPost:
		s.pair.close()
		writeJSON(w, http.StatusOK, map[string]any{"open": false})
	case strings.HasPrefix(p, "/v1/pair/") && r.Method == http.MethodPost && (strings.HasSuffix(p, "/approve") || strings.HasSuffix(p, "/deny")):
		parts := strings.Split(strings.TrimPrefix(p, "/v1/pair/"), "/")
		if len(parts) != 2 || len(parts[0]) != 32 {
			apiErr(w, http.StatusNotFound, "not found")
			return
		}
		var err error
		if parts[1] == "approve" {
			err = s.pair.approve(parts[0])
		} else {
			err = s.pair.deny(parts[0])
		}
		switch {
		case errors.Is(err, errPairUnknown):
			apiErr(w, http.StatusNotFound, "that request is gone (it may have expired)")
		case err != nil:
			apiErr(w, http.StatusInternalServerError, "could not save the new device")
		default:
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}
	case p == "/v1/devices" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"devices": s.pair.store.devices()})
	case strings.HasPrefix(p, "/v1/devices/") && r.Method == http.MethodDelete:
		label := strings.TrimPrefix(p, "/v1/devices/")
		if validTokenLabel(label) != nil {
			apiErr(w, http.StatusBadRequest, "invalid label")
			return
		}
		if err := s.pair.store.remove(label); err != nil {
			apiErr(w, http.StatusNotFound, "no such device")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		apiErr(w, http.StatusNotFound, "not found")
	}
}
