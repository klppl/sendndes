package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/klppl/valv/core"
	"golang.org/x/sys/unix"
)

const (
	defaultMaxUploadBytes     = 4 << 30 // 4 GiB
	defaultIOTimeout          = 30 * time.Second
	defaultWriteTimeout       = 30 * time.Second
	defaultReadHeaderTimeout  = 10 * time.Second
	defaultIdleTimeout        = 60 * time.Second
	defaultMaxHeaderBytes     = 65536
	defaultMaxConcurrentPUTs  = 4
	defaultMaxConcurrentReqs  = 32
	defaultMaxInboxFiles      = 10000
	defaultSlotWaitTimeout    = 5 * time.Second
	defaultMaxInboxBytes      = int64(2) << 30   // 2 GiB of stored inbox files
	defaultMinFreeBytes       = int64(256) << 20 // free space left alone on the file system
	defaultMinUploadRate      = int64(64) << 10  // bytes per second, for the overall upload deadline
	defaultMaxChunkedDuration = 10 * time.Minute // hard cap when the upload length is not declared
	uploadBaseTimeout         = 60 * time.Second // fixed part of the overall upload deadline
	authRateBurst             = 5
	authRateRefillInterval    = time.Second
	maxRateLimiterTrackedIPs  = 4096
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
	maxChunkedTime    time.Duration // total time cap when Content-Length is unknown (L3)
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
		maxChunkedTime:    defaultMaxChunkedDuration,
	}
}

// inboxServer implements the SPEC 8 Mode B HTTP API.
// It holds only inbox_pub, k_auth, and the bearer token digest, and never
// logs filenames, metadata, sizes, contents, or tokens (SPEC 10 rule 4).
type inboxServer struct {
	dir       *dirHandle
	reg       *tempRegistry
	inboxPub  [core.KeySize]byte
	kAuth     [core.KeySize]byte
	token     []byte
	tokenHash [32]byte
	opts      serverOpts
	putSem    chan struct{}
	reqSem    chan struct{}
	quotaMu   sync.Mutex
	bytes     byteQuota // guarded by quotaMu
	authRL    *ipRateLimiter
	baseCtx   context.Context
}

func newInboxServer(baseCtx context.Context, dir *dirHandle, reg *tempRegistry, cfg *serverConfig, opts serverOpts) *inboxServer {
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
	if opts.maxChunkedTime <= 0 {
		opts.maxChunkedTime = defaultMaxChunkedDuration
	}
	tokCopy := make([]byte, len(cfg.Token))
	copy(tokCopy, cfg.Token)
	s := &inboxServer{
		bytes:     byteQuota{max: opts.maxInboxBytes, minFree: opts.minFreeBytes},
		dir:       dir,
		reg:       reg,
		inboxPub:  cfg.InboxPub,
		kAuth:     cfg.KAuth,
		token:     tokCopy,
		tokenHash: sha256.Sum256(tokCopy),
		opts:      opts,
		putSem:    make(chan struct{}, opts.maxConcurrentPUTs),
		reqSem:    make(chan struct{}, opts.maxConcurrentReqs),
		authRL:    newIPRateLimiter(authRateBurst, authRateRefillInterval),
		baseCtx:   baseCtx,
	}
	return s
}

func (s *inboxServer) Wipe() {
	clear(s.inboxPub[:])
	clear(s.kAuth[:])
	clear(s.token)
	clear(s.tokenHash[:])
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

	remoteIP := clientIP(r.RemoteAddr)
	if !s.authenticate(r, remoteIP) {
		if !s.authRL.allow(remoteIP, time.Now()) {
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
	switch {
	case path == "/inbox":
		switch r.Method {
		case http.MethodPut:
			s.handlePutInbox(w, r)
		case http.MethodGet:
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
			s.handleGetInboxFile(w, r, idStr)
		case http.MethodDelete:
			s.handleDeleteInboxFile(w, r, idStr)
		default:
			w.Header().Set("Allow", "GET, DELETE")
			httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		httpError(w, http.StatusNotFound, "not found")
	}
}

// authenticate checks the Authorization: Bearer <token> header in constant
// time. Per review recommendation #2 (D-R2), it enforces len(token) <= 512
// before hashing.
func (s *inboxServer) authenticate(r *http.Request, _ string) bool {
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		return false
	}
	auth := vals[0]
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := auth[len(prefix):]
	if len(got) == 0 || len(got) > maxTokenLen {
		return false
	}
	gotHash := sha256.Sum256([]byte(got))
	hashMatch := subtle.ConstantTimeCompare(gotHash[:], s.tokenHash[:])
	lenMatch := subtle.ConstantTimeEq(int32(len(got)), int32(len(s.token)))
	return (hashMatch & lenMatch) == 1
}

// knownValvHeaders lists every X-Valv-* header accepted by PUT /inbox.
var knownValvHeaders = map[string]bool{
	"X-Valv-Name":     true,
	"X-Valv-Name-B64": true,
	"X-Valv-Dir":      true,
	"X-Valv-Dir-B64":  true,
	"X-Valv-Mtime":    true,
	"X-Valv-Mime":     true,
	"X-Valv-Mime-B64": true,
}

// parseUploadMetadata extracts and validates metadata from PUT /inbox headers.
// Per review recommendation #1 (D-R2), any duplicate X-Valv-* header
// (len(r.Header.Values(h)) > 1) or unknown X-Valv-* header is rejected.
func parseUploadMetadata(h http.Header) (core.Metadata, error) {
	for k, vals := range h {
		ck := http.CanonicalHeaderKey(k)
		if strings.HasPrefix(ck, "X-Valv-") {
			if !knownValvHeaders[ck] {
				return core.Metadata{}, errors.New("unknown X-Valv-* header")
			}
			if len(vals) > 1 {
				return core.Metadata{}, errors.New("duplicate metadata header")
			}
		}
	}

	name, hasName, err := extractDualHeader(h, "X-Valv-Name", "X-Valv-Name-B64", true)
	if err != nil || !hasName {
		return core.Metadata{}, errors.New("invalid or missing file name header")
	}
	dir, _, err := extractDualHeader(h, "X-Valv-Dir", "X-Valv-Dir-B64", false)
	if err != nil {
		return core.Metadata{}, errors.New("invalid dir header")
	}
	mimeVal, _, err := extractDualHeader(h, "X-Valv-Mime", "X-Valv-Mime-B64", false)
	if err != nil {
		return core.Metadata{}, errors.New("invalid mime header")
	}

	mtime := time.Now().UnixNano()
	if mtimeVals := h.Values("X-Valv-Mtime"); len(mtimeVals) == 1 {
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
	need := int64(-1)
	if r.ContentLength >= 0 {
		need = sealedEstimate(r.ContentLength)
	}
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
	case errors.Is(err, errStreamTruncated) || errors.Is(err, io.ErrUnexpectedEOF):
		return http.StatusBadRequest, "incomplete upload stream"
	case isTimeoutError(err):
		return http.StatusRequestTimeout, "upload timed out"
	default:
		return http.StatusBadRequest, "upload failed"
	}
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
// length at the minimum rate, or a hard cap when the length is not declared. A client that
// drips one byte per read timeout still loses its slot.
func (s *inboxServer) uploadDeadline(contentLength int64, now time.Time) time.Time {
	if contentLength < 0 {
		return now.Add(s.opts.maxChunkedTime)
	}
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
	if b.contentLength >= 0 && b.readBytes > b.contentLength {
		return n, errStreamTruncated
	}
	if err == io.EOF && b.contentLength >= 0 && b.readBytes < b.contentLength {
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
	if b.contentLength >= 0 && b.readBytes != b.contentLength {
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
			// Evict expired entries; if still full, clear map to bound memory.
			for k, v := range l.buckets {
				if now.Sub(v.lastTime) > time.Duration(l.burst)*l.refill {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= maxRateLimiterTrackedIPs {
				clear(l.buckets)
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
