package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// validatePullServerURL is the server-address policy of `ndes pull`. It must accept and reject
// exactly what the Mac app's URLPolicy (app/Sources/AppCore/URLPolicy.swift) does, so the app can hand
// its canonical string to this helper (L12). Both are tested against the same list,
// app/Tests/AppCoreTests/url-policy-cases.tsv.
//
//   - printable ASCII only (no space, '%' or '\'), at most 300 bytes, no '?' or '#';
//   - scheme://host[:port] with an empty path or "/", no userinfo, port 1-65535;
//   - https: a DNS-style host ([a-z0-9.-], no empty label, at most 253 bytes);
//   - http: only an IPv4 loopback (127/8) or Tailscale (100.64.0.0/10) literal without leading zeros,
//     or the IPv6 loopback ::1, unless allowInsecure is set (--allow-insecure-http).
//
// It returns the canonical form "scheme://host[:port]" (lowercase, IPv6 in brackets).
func validatePullServerURL(raw string, allowInsecure bool) (string, error) {
	invalid := errors.New("invalid server URL (want https://host[:port] or http://100.x.y.z[:port])")
	if raw == "" || len(raw) > 300 {
		return "", invalid
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= 0x20 || c >= 0x7f || c == '%' || c == '\\' {
			return "", invalid
		}
	}
	if strings.ContainsAny(raw, "?#@") {
		return "", invalid
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return "", invalid
	}
	scheme = strings.ToLower(scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("unsupported URL scheme %q (want https or http)", scheme)
	}
	authority, path, _ := strings.Cut(rest, "/")
	if hasPath := strings.Contains(rest, "/"); hasPath && path != "" {
		return "", invalid
	}
	host, portText := authority, ""
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", invalid
		}
		host, portText = authority[1:end], authority[end+1:]
		if portText != "" && !strings.HasPrefix(portText, ":") {
			return "", invalid
		}
	} else if i := strings.IndexByte(authority, ':'); i >= 0 {
		host, portText = authority[:i], authority[i:]
	}
	port := ""
	if portText != "" {
		digits := portText[1:]
		n, err := strconv.Atoi(digits)
		if err != nil || digits == "" || strings.Trim(digits, "0123456789") != "" || n < 1 || n > 65535 {
			return "", invalid
		}
		port = ":" + strconv.Itoa(n)
	}
	host = strings.ToLower(host)
	if host == "" {
		return "", invalid
	}
	hostText := host
	switch scheme {
	case "https":
		labels := strings.Split(host, ".")
		if len(host) > 253 {
			return "", invalid
		}
		for _, l := range labels {
			if l == "" {
				return "", invalid
			}
		}
		for i := 0; i < len(host); i++ {
			c := host[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				return "", invalid
			}
		}
	case "http":
		if !allowInsecure && !isTrustedPlainHTTPHost(host) {
			return "", fmt.Errorf("refusing plain HTTP to %s (use https://, a loopback/Tailscale IP, or --allow-insecure-http)", display(host))
		}
		if strings.Contains(host, ":") {
			hostText = "[" + host + "]"
		}
	}
	return scheme + "://" + hostText + port, nil
}

// isTrustedPlainHTTPHost: IPv4 loopback or Tailscale literal (no leading zeros), or exactly ::1.
func isTrustedPlainHTTPHost(host string) bool {
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(host)
		return err == nil && addr == netip.IPv6Loopback() && !addr.Is4In6()
	}
	addr, err := netip.ParseAddr(host) // rejects leading zeros and anything but dotted decimal
	if err != nil || !addr.Is4() {
		return false
	}
	return addr.IsLoopback() || tailscaleIPv4Prefix.Contains(addr)
}
