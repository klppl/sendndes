package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
)

// runManaged runs valvd with the owner-only web GUI. The sync server is
// started from the saved settings and is controlled from the GUI.
func runManaged(dataDir, adminListen string, allowPublic, behindProxy bool, syncListen string, stderr io.Writer) int {
	host, _, err := net.SplitHostPort(adminListen)
	if err != nil {
		fmt.Fprintf(stderr, "valvd: --admin-listen: %v\n", err)
		return 1
	}
	// Binding the GUI to a specific public address is refused. 0.0.0.0 is
	// allowed because every request is still checked against its source
	// address (needed for containers).
	if ip, perr := netip.ParseAddr(host); perr == nil && !ip.IsUnspecified() && !privateAddr(ip) && !allowPublic {
		fmt.Fprintf(stderr, "valvd: refusing to serve the web GUI on public address %s (the GUI is for the owner only; use 127.0.0.1, a LAN or Tailscale address, or --admin-allow-public)\n", host)
		return 1
	}
	m, err := newManager(dataDir, syncListen, os.Getenv("VALVD_SYNC_LISTEN") != "", stderr)
	if err != nil {
		fmt.Fprintf(stderr, "valvd: %v\n", err)
		return 1
	}
	defer m.dir.Close()
	defer m.shutdown()

	ln, err := net.Listen("tcp", adminListen)
	if err != nil {
		fmt.Fprintf(stderr, "valvd: admin listen: %v\n", err)
		return 1
	}
	defer ln.Close()

	m.reg.addHook(m.shutdown)
	stopSig := installSignalCleanup(m.reg, os.Exit)
	defer stopSig()

	if m.configured() && !m.state.Stopped {
		if err := m.start(); err != nil {
			fmt.Fprintf(stderr, "valvd: sync server did not start: %v (fix it in the web GUI)\n", err)
		}
	}
	if !m.hasPassword() {
		code, err := m.ensureSetupCode()
		if err != nil {
			fmt.Fprintf(stderr, "valvd: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "valvd: first run. Open the web GUI and enter this setup code: %s\n", code)
		fmt.Fprintf(stderr, "valvd: (the code is also stored in %s)\n", m.path(setupCodeFile))
	}
	fmt.Fprintf(stderr, "valvd: web GUI on http://%s\n", ln.Addr())

	adm := newAdminServer(m, allowPublic)
	adm.behindProxy = behindProxy
	if behindProxy {
		fmt.Fprintln(stderr, "valvd: web GUI is set to run behind a reverse proxy or tunnel. Keep it reachable only through that (for example Cloudflare Access) and the proxy's own login in front.")
	}
	srv := newHTTPServer(adm)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "valvd: %v\n", err)
		return 1
	}
	return 0
}
