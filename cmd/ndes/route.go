package main

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// H1: plain http is only acceptable inside the Tailscale tunnel. The policy trusts
// the destination address, which says nothing about the path: with Tailscale off
// (or after sleep) packets to 100.x leave through the default gateway. So before
// talking plain http to a Tailscale address, find the interface the OS would use
// for that destination and require it to be a Tailscale interface. Fail closed.

var errNotTailscaleRoute = errors.New("the route to this address does not go through Tailscale; is Tailscale connected?")

// routeInterfaceLookup is a test seam: it returns the name of the local interface the
// OS would use to reach dst.
var routeInterfaceLookup = osRouteInterface

// osRouteInterface asks the kernel for the route with a connected UDP socket (no
// packet is sent), then finds the interface that owns the chosen source address.
func osRouteInterface(dst netip.Addr) (string, error) {
	network := "udp4"
	if dst.Is6() {
		network = "udp6"
	}
	c, err := net.DialUDP(network, nil, &net.UDPAddr{IP: dst.AsSlice(), Port: 9})
	if err != nil {
		return "", err
	}
	local, ok := netip.AddrFromSlice(c.LocalAddr().(*net.UDPAddr).IP)
	c.Close()
	if !ok {
		return "", errors.New("no local address")
	}
	local = local.Unmap()
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Unmap() == local {
				return ifc.Name, nil
			}
		}
	}
	return "", errors.New("no interface owns the source address")
}

// isTailscaleInterface: utun* (macOS), tailscale* (Linux), or a name the user listed.
func isTailscaleInterface(name string, extra []string) bool {
	if strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "tailscale") {
		return true
	}
	for _, e := range extra {
		if e != "" && e == name {
			return true
		}
	}
	return false
}

// needsTailscaleRoute: plain http to a Tailscale address. Loopback and https need nothing.
func needsTailscaleRoute(rawURL string) (netip.Addr, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return netip.Addr{}, false
	}
	if tailscaleIPv4Prefix.Contains(addr) || tailscaleIPv6Prefix.Contains(addr) {
		return addr, true
	}
	return netip.Addr{}, false
}

// checkTailscaleRoute returns nil when no check applies or the route is through Tailscale.
func checkTailscaleRoute(rawURL string, extra []string) error {
	addr, need := needsTailscaleRoute(rawURL)
	if !need {
		return nil
	}
	name, err := routeInterfaceLookup(addr)
	if err != nil || !isTailscaleInterface(name, extra) {
		return errNotTailscaleRoute
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
