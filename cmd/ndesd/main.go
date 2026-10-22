// Command ndesd is the Ndes Mode B write-only inbox server (SPEC 8, 11 step 4).
//
// Usage:
//
//	ndesd --config <file> --inbox <dir> [--token-file <file>] [--listen <addr>]
//
// ndesd holds inbox_pub, K_auth, and a bearer token. It never reads vault.json,
// never holds VK or the inbox private key, and cannot decrypt anything it stores.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const usage = `usage: ndesd [--data <dir>] [web GUI flags]
       ndesd --config <file> --inbox <dir> [flags]

With no --config/--inbox, ndesd runs with a web GUI for setup (managed mode):
  --data <dir>                     where everything is kept (default $NDESD_DATA or ./ndesd-data)
  --admin-listen <addr>            web GUI address (default $NDESD_ADMIN_LISTEN or 127.0.0.1:8080)
  --admin-behind-proxy             trust a reverse proxy/tunnel (Cloudflare Tunnel) on this host; proxy headers allowed
  --admin-allow-public             let the web GUI answer public addresses (not recommended)
  --sync-listen <addr>             first-run default for the sync server (default $NDESD_SYNC_LISTEN or 127.0.0.1:8485);
                                   after setup, change it in the web GUI

Classic mode (no web GUI), flags:
  --tokens-file <file>             accepted tokens (mode 0600): one line per token, "<role> <label> <sha256-hex>" with the
                                   role upload, pull or both. "ndes sender-config" prints a line to add. Reloaded on
                                   SIGHUP (systemctl reload ndesd); a broken file keeps the old tokens.
  --inbox <dir>                    inbox storage directory
  --client-ip-header <name>        trust this header (for example CF-Connecting-IP) for the address behind a proxy on
                                   this host, only when the TCP peer is loopback and the header is exactly one IP
                                   (default: off; X-Forwarded-For is never used)
  --max-sealed-bytes <n>           largest PUT /inbox/{id} body (default 95420416, the 90 MiB phone limit plus 1 MiB)

Server-side sealing (the old PUT /inbox with X-Ndes-* headers) is off. It makes this server see plaintext, and
needs inbox_pub and k_auth, which a sealed-upload server must not hold:
  --enable-server-sealing          turn it on; needs --config
  --config <file>                  server config file (mode 0600, with inbox_pub and k_auth, and token); only with
                                   --enable-server-sealing, otherwise ndesd refuses to start
  --token-file <file>              one plaintext bearer token (mode 0600), role both; deprecated, use --tokens-file
  --listen <addr>                  listen address (default 127.0.0.1:8485)
  --tls-cert <file>                TLS certificate file (enables HTTPS)
  --tls-key <file>                 TLS private key file (mode 0600)
  --allow-insecure-http            allow plain HTTP on a non-loopback address (e.g. Tailscale IP)
  --max-upload-bytes <n>           maximum upload size in bytes (default 4294967296)
  --io-timeout <duration>          per-chunk streaming I/O timeout (default 30s)
  --max-concurrent-uploads <n>     maximum concurrent PUT /inbox uploads (default 4)
  --max-inbox-files <n>            maximum number of files in the inbox directory (default 10000)
  --max-inbox-bytes <n>            maximum total size of stored inbox files (default 2147483648); uploads that
                                   would not fit, by their declared Content-Length, get 507
  --min-free-bytes <n>             free space to leave on the file system (default 268435456); an upload
                                   that would eat into it gets 507 "server out of space"
  --min-upload-rate <n>            slowest accepted upload in bytes/s (default 65536): an upload must finish
                                   within 60s + Content-Length / rate
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	fs := flag.NewFlagSet("ndesd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		configPath     string
		tokenFile      string
		tokensPath     string
		enableSealing  bool
		clientIPHdr    string
		maxSealedBytes int64
		inboxPath      string
		listenAddr     string
		tlsCert        string
		tlsKey         string
		allowInsecure  bool
		maxUploadBytes int64
		ioTimeout      time.Duration
		maxPUTs        int
		maxFiles       int
		maxInboxBytes  int64
		minFreeBytes   int64
		minUploadRate  int64
		dataDir        string
		adminListen    string
		adminPublic    bool
		adminProxy     bool
		syncListen     string
	)
	fs.StringVar(&configPath, "config", "", "server config file")
	fs.StringVar(&tokenFile, "token-file", "", "bearer token file")
	fs.StringVar(&tokensPath, "tokens-file", "", "accepted tokens (role, label, sha256)")
	fs.BoolVar(&enableSealing, "enable-server-sealing", false, "enable server-side sealing (PUT /inbox with headers)")
	fs.StringVar(&clientIPHdr, "client-ip-header", "", "header with the client IP behind a loopback proxy")
	fs.Int64Var(&maxSealedBytes, "max-sealed-bytes", defaultMaxSealedBytes, "largest sealed upload")
	fs.StringVar(&inboxPath, "inbox", "", "inbox directory")
	fs.StringVar(&listenAddr, "listen", "127.0.0.1:8485", "listen address")
	fs.StringVar(&tlsCert, "tls-cert", "", "TLS certificate file")
	fs.StringVar(&tlsKey, "tls-key", "", "TLS key file")
	fs.BoolVar(&allowInsecure, "allow-insecure-http", false, "allow plain HTTP on non-loopback")
	fs.Int64Var(&maxUploadBytes, "max-upload-bytes", defaultMaxUploadBytes, "max upload bytes")
	fs.DurationVar(&ioTimeout, "io-timeout", defaultIOTimeout, "streaming I/O timeout")
	fs.IntVar(&maxPUTs, "max-concurrent-uploads", defaultMaxConcurrentPUTs, "max concurrent uploads")
	fs.IntVar(&maxFiles, "max-inbox-files", defaultMaxInboxFiles, "max inbox files")
	fs.Int64Var(&maxInboxBytes, "max-inbox-bytes", defaultMaxInboxBytes, "max stored inbox bytes")
	fs.Int64Var(&minFreeBytes, "min-free-bytes", defaultMinFreeBytes, "free space to keep")
	fs.Int64Var(&minUploadRate, "min-upload-rate", defaultMinUploadRate, "minimum upload rate in bytes/s")

	fs.StringVar(&dataDir, "data", os.Getenv("NDESD_DATA"), "data directory (managed mode)")
	fs.StringVar(&adminListen, "admin-listen", envOr("NDESD_ADMIN_LISTEN", "127.0.0.1:8080"), "web GUI address")
	fs.BoolVar(&adminPublic, "admin-allow-public", false, "let the web GUI answer public addresses")
	fs.BoolVar(&adminProxy, "admin-behind-proxy", os.Getenv("NDESD_ADMIN_BEHIND_PROXY") == "1", "web GUI is behind a reverse proxy/tunnel")
	fs.StringVar(&syncListen, "sync-listen", envOr("NDESD_SYNC_LISTEN", "127.0.0.1:8485"), "first-run sync address")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintf(stderr, "ndesd: %v\n", err)
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "ndesd: unexpected positional arguments (see ndesd --help)")
		return 1
	}
	if configPath == "" && inboxPath == "" {
		if dataDir == "" {
			dataDir = "ndesd-data"
		}
		return runManaged(dataDir, adminListen, adminPublic, adminProxy, syncListen, stderr)
	}
	if inboxPath == "" {
		fmt.Fprintln(stderr, "ndesd: --inbox is required (see ndesd --help)")
		return 1
	}
	if configPath != "" && !enableSealing {
		fmt.Fprintln(stderr, "ndesd: --config holds inbox_pub and k_auth, which this server must not hold unless it seals files itself; "+
			"use --tokens-file for a server that only stores sealed uploads, or add --enable-server-sealing (see ndesd --help)")
		return 1
	}
	if enableSealing && configPath == "" {
		fmt.Fprintln(stderr, "ndesd: --enable-server-sealing needs --config with inbox_pub and k_auth")
		return 1
	}
	if configPath == "" && tokensPath == "" && tokenFile == "" {
		fmt.Fprintln(stderr, "ndesd: no tokens: give --tokens-file (see ndesd --help)")
		return 1
	}
	if maxSealedBytes <= 0 {
		fmt.Fprintln(stderr, "ndesd: --max-sealed-bytes must be positive")
		return 1
	}
	if clientIPHdr != "" && !validHeaderName(clientIPHdr) {
		fmt.Fprintln(stderr, "ndesd: --client-ip-header is not a valid header name")
		return 1
	}
	if maxInboxBytes <= 0 || minFreeBytes < 0 || minUploadRate <= 0 {
		fmt.Fprintln(stderr, "ndesd: --max-inbox-bytes and --min-upload-rate must be positive; --min-free-bytes must not be negative")
		return 1
	}
	if (tlsCert == "") != (tlsKey == "") {
		fmt.Fprintln(stderr, "ndesd: --tls-cert and --tls-key must be given together")
		return 1
	}
	useTLS := tlsCert != ""
	if !useTLS && !isLoopbackListen(listenAddr) && !allowInsecure {
		fmt.Fprintf(stderr, "ndesd: refusing plain HTTP on non-loopback address %s without --tls-cert/--tls-key (pass --allow-insecure-http for Tailscale or trusted private interfaces)\n", listenAddr)
		return 1
	}
	if useTLS {
		if _, err := readProtectedFile(tlsKey); err != nil {
			fmt.Fprintf(stderr, "ndesd: tls-key: %v\n", err)
			return 1
		}
	}

	var cfg *serverConfig
	if configPath != "" {
		c, err := loadServerConfig(configPath, tokenFile, tokensPath != "")
		if err != nil {
			fmt.Fprintf(stderr, "ndesd: %v\n", err)
			return 1
		}
		cfg = c
	} else {
		cfg = &serverConfig{}
		if tokenFile != "" {
			tok, err := readLegacyTokenFile(tokenFile)
			if err != nil {
				fmt.Fprintf(stderr, "ndesd: %v\n", err)
				return 1
			}
			cfg.Token = tok
		}
	}
	defer cfg.Wipe()
	if len(cfg.Token) > 0 {
		fmt.Fprintln(stderr, "ndesd: warning: a plaintext token (--token-file, or `token:` in --config) is deprecated; it is accepted with the role both. Use --tokens-file")
	}
	var fileTokens *tokenSet
	if tokensPath != "" {
		t, err := readTokensFile(tokensPath, true)
		if err != nil {
			fmt.Fprintf(stderr, "ndesd: %v\n", err)
			return 1
		}
		fileTokens = t
	}

	dir, err := openInboxDir(inboxPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "ndesd: %v\n", err)
		return 1
	}
	defer dir.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := newTempRegistry()
	opts := serverOpts{
		maxUploadBytes:    maxUploadBytes,
		ioTimeout:         ioTimeout,
		writeTimeout:      defaultWriteTimeout,
		maxConcurrentPUTs: maxPUTs,
		maxConcurrentReqs: defaultMaxConcurrentReqs,
		maxInboxFiles:     maxFiles,
		slotWaitTimeout:   defaultSlotWaitTimeout,
		maxInboxBytes:     maxInboxBytes,
		minFreeBytes:      minFreeBytes,
		minUploadRate:     minUploadRate,

		maxSealedBytes:      maxSealedBytes,
		enableServerSealing: enableSealing,
		clientIPHeader:      clientIPHdr,
	}
	srvHandler := newInboxServer(ctx, dir, reg, cfg, opts)
	defer srvHandler.Wipe()
	var legacySet *tokenSet
	if len(cfg.Token) > 0 {
		legacySet = legacyTokenSet(cfg.Token)
	}
	merged, err := mergeTokenSets(legacySet, fileTokens)
	if err != nil {
		fmt.Fprintf(stderr, "ndesd: %v\n", err)
		return 1
	}
	if len(merged.entries) == 0 {
		fmt.Fprintln(stderr, "ndesd: no tokens: the tokens file has no entries")
		return 1
	}
	srvHandler.setTokens(merged)
	// SIGHUP reloads the tokens file (an empty file revokes everything in it). Without one there is nothing to
	// reload, but the signal still must not stop the server (systemctl reload).
	stopReload := installReload(stderr, func() error {
		if tokensPath == "" {
			return errNothingToReload
		}
		t, err := readTokensFile(tokensPath, true)
		if err != nil {
			return err
		}
		m, err := mergeTokenSets(legacySet, t)
		if err != nil {
			return err
		}
		srvHandler.setTokens(m)
		return nil
	})
	defer stopReload()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(stderr, "ndesd: listen: %v\n", err)
		return 1
	}
	defer ln.Close()

	httpSrv := newHTTPServer(srvHandler)
	reg.addHook(func() {
		cancel()
		_ = ln.Close()
		srvHandler.Wipe()
		cfg.Wipe()
	})
	stopSig := installSignalCleanup(reg, os.Exit, true)
	defer stopSig()

	if !useTLS && !isLoopbackListen(listenAddr) {
		fmt.Fprintf(stderr, "ndesd: warning: listening without TLS on %s (--allow-insecure-http)\n", ln.Addr())
	}
	fmt.Fprintf(stderr, "ndesd: listening on %s\n", ln.Addr())

	if useTLS {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		err = httpSrv.ServeTLS(ln, tlsCert, tlsKey)
	} else {
		err = httpSrv.Serve(ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "ndesd: %v\n", err)
		return 1
	}
	return 0
}

func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		IdleTimeout:       defaultIdleTimeout,
		// Discard net/http internal error logs so URLs, headers, or tokens are never logged.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// validHeaderName accepts a plain HTTP header name (token characters only).
func validHeaderName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

var errNothingToReload = errors.New("nothing to reload")

// installReload runs reload on every SIGHUP. A failure is reported without any detail beyond the
// parser's message (which never holds a token or hash) and the old configuration stays in force.
func installReload(stderr io.Writer, reload func() error) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				if err := reload(); errors.Is(err, errNothingToReload) {
					fmt.Fprintln(stderr, "ndesd: nothing to reload (no --tokens-file)")
				} else if err != nil {
					fmt.Fprintf(stderr, "ndesd: reload failed, keeping the previous tokens: %v\n", err)
				} else {
					fmt.Fprintln(stderr, "ndesd: tokens reloaded")
				}
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(ch); close(done) }
}
