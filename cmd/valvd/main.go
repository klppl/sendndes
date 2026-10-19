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

const usage = `usage: valvd --config <file> --inbox <dir> [flags]

flags:
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
	if configPath == "" || inboxPath == "" {
		fmt.Fprintln(stderr, "valvd: --config and --inbox are required (see valvd --help)")
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
