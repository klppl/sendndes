// Command valvd is the Valv Mode B write-only inbox server (SPEC 8, 11 step 4).
//
// Usage:
//
//	valvd --config <file> --inbox <dir> [--token-file <file>] [--listen <addr>]
//
// valvd holds inbox_pub, K_auth, and a bearer token. It never reads vault.json,
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
	"strings"
	"time"
)

const usage = `usage: valvd [--data <dir>] [web GUI flags]
       valvd --config <file> --inbox <dir> [flags]

With no --config/--inbox, valvd runs with a web GUI for setup (managed mode):
  --data <dir>                     where everything is kept (default $VALVD_DATA or ./valvd-data)
  --admin-listen <addr>            web GUI address (default $VALVD_ADMIN_LISTEN or 127.0.0.1:8080)
  --admin-behind-proxy             trust a reverse proxy/tunnel (Cloudflare Tunnel) on this host; proxy headers allowed
  --admin-allow-public             let the web GUI answer public addresses (not recommended)
  --sync-listen <addr>             first-run default for the sync server (default $VALVD_SYNC_LISTEN or 127.0.0.1:8485);
                                   after setup, change it in the web GUI

Classic mode (no web GUI), flags:
  --config <file>                  server config file (mode 0600, with inbox_pub, k_auth, and token)
  --token-file <file>              bearer token file (mode 0600, if token is not in --config)
  --inbox <dir>                    inbox storage directory
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
  --max-chunked-duration <d>       longest total time for an upload without Content-Length (default 10m)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	fs := flag.NewFlagSet("valvd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		configPath     string
		tokenFile      string
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
		maxChunkedTime time.Duration
		dataDir        string
		adminListen    string
		adminPublic    bool
		adminProxy     bool
		syncListen     string
	)
	fs.StringVar(&configPath, "config", "", "server config file")
	fs.StringVar(&tokenFile, "token-file", "", "bearer token file")
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
	fs.DurationVar(&maxChunkedTime, "max-chunked-duration", defaultMaxChunkedDuration, "max duration of an upload without Content-Length")

	fs.StringVar(&dataDir, "data", os.Getenv("VALVD_DATA"), "data directory (managed mode)")
	fs.StringVar(&adminListen, "admin-listen", envOr("VALVD_ADMIN_LISTEN", "127.0.0.1:8080"), "web GUI address")
	fs.BoolVar(&adminPublic, "admin-allow-public", false, "let the web GUI answer public addresses")
	fs.BoolVar(&adminProxy, "admin-behind-proxy", os.Getenv("VALVD_ADMIN_BEHIND_PROXY") == "1", "web GUI is behind a reverse proxy/tunnel")
	fs.StringVar(&syncListen, "sync-listen", envOr("VALVD_SYNC_LISTEN", "127.0.0.1:8485"), "first-run sync address")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintf(stderr, "valvd: %v\n", err)
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "valvd: unexpected positional arguments (see valvd --help)")
		return 1
	}
	if configPath == "" && inboxPath == "" {
		if dataDir == "" {
			dataDir = "valvd-data"
		}
		return runManaged(dataDir, adminListen, adminPublic, adminProxy, syncListen, stderr)
	}
	if configPath == "" || inboxPath == "" {
		fmt.Fprintln(stderr, "valvd: --config and --inbox are required (see valvd --help)")
		return 1
	}
	if maxInboxBytes <= 0 || minFreeBytes < 0 || minUploadRate <= 0 || maxChunkedTime <= 0 {
		fmt.Fprintln(stderr, "valvd: --max-inbox-bytes, --min-upload-rate and --max-chunked-duration must be positive; --min-free-bytes must not be negative")
		return 1
	}
	if (tlsCert == "") != (tlsKey == "") {
		fmt.Fprintln(stderr, "valvd: --tls-cert and --tls-key must be given together")
		return 1
	}
	useTLS := tlsCert != ""
	if !useTLS && !isLoopbackListen(listenAddr) && !allowInsecure {
		fmt.Fprintf(stderr, "valvd: refusing plain HTTP on non-loopback address %s without --tls-cert/--tls-key (pass --allow-insecure-http for Tailscale or trusted private interfaces)\n", listenAddr)
		return 1
	}
	if useTLS {
		if _, err := readProtectedFile(tlsKey); err != nil {
			fmt.Fprintf(stderr, "valvd: tls-key: %v\n", err)
			return 1
		}
	}

	cfg, err := loadServerConfig(configPath, tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "valvd: %v\n", err)
		return 1
	}
	defer cfg.Wipe()

	dir, err := openInboxDir(inboxPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "valvd: %v\n", err)
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
		maxChunkedTime:    maxChunkedTime,
	}
	srvHandler := newInboxServer(ctx, dir, reg, cfg, opts)
	defer srvHandler.Wipe()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(stderr, "valvd: listen: %v\n", err)
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
	stopSig := installSignalCleanup(reg, os.Exit)
	defer stopSig()

	if !useTLS && !isLoopbackListen(listenAddr) {
		fmt.Fprintf(stderr, "valvd: warning: listening without TLS on %s (--allow-insecure-http)\n", ln.Addr())
	}
	fmt.Fprintf(stderr, "valvd: listening on %s\n", ln.Addr())

	if useTLS {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		err = httpSrv.ServeTLS(ln, tlsCert, tlsKey)
	} else {
		err = httpSrv.Serve(ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "valvd: %v\n", err)
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
