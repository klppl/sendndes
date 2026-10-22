package main

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/klppl/sendndes/core"
)

const (
	maxServerConfigSize = 4096
	minTokenLen         = 32
	maxTokenLen         = 512
)

var strictB64 = base64.StdEncoding.Strict()

// serverConfig holds the cryptographic keys and bearer token for ndesd.
// ndesd never reads vault.json and never holds VK or inbox_priv (SPEC 3, 6.2).
type serverConfig struct {
	InboxPub [core.KeySize]byte
	KAuth    [core.KeySize]byte
	Token    []byte
}

func (c *serverConfig) Wipe() {
	clear(c.InboxPub[:])
	clear(c.KAuth[:])
	clear(c.Token)
}

// readProtectedFile opens p with O_NOFOLLOW, verifies it is a regular file of
// at most maxServerConfigSize bytes with mode permissions that forbid group or
// world access (mode & 0o077 == 0), and returns its contents.
func readProtectedFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: refusing to follow symlink", display(p))
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", display(p))
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions %04o are too open (must not be accessible by group or others; chmod 0600)", display(p), st.Mode().Perm())
	}
	if st.Size() > maxServerConfigSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", display(p), maxServerConfigSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxServerConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxServerConfigSize {
		clear(data)
		return nil, fmt.Errorf("%s: larger than %d bytes", display(p), maxServerConfigSize)
	}
	return data, nil
}

// loadServerConfig parses the server config file (inbox_pub, k_auth, and
// optionally token) and optional separate token file.
func loadServerConfig(configPath, tokenFilePath string, tokenOptional bool) (*serverConfig, error) {
	data, err := readProtectedFile(configPath)
	if err != nil {
		return nil, err
	}
	defer clear(data)

	cfg, err := parseServerConfigBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", display(configPath), err)
	}

	if tokenFilePath != "" {
		if len(cfg.Token) > 0 {
			cfg.Wipe()
			return nil, fmt.Errorf("%s: token is specified in both config file and --token-file", display(configPath))
		}
		tokData, err := readProtectedFile(tokenFilePath)
		if err != nil {
			cfg.Wipe()
			return nil, err
		}
		tok := strings.TrimRight(string(tokData), "\r\n")
		clear(tokData)
		if err := validateToken(tok); err != nil {
			cfg.Wipe()
			return nil, fmt.Errorf("%s: %w", display(tokenFilePath), err)
		}
		cfg.Token = []byte(tok)
	} else if len(cfg.Token) == 0 && !tokenOptional {
		cfg.Wipe()
		return nil, fmt.Errorf("%s: missing token (add 'token: <secret>' or pass --token-file)", display(configPath))
	}

	return cfg, nil
}

func parseServerConfigBytes(data []byte) (*serverConfig, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("config is not valid UTF-8")
	}
	var cfg serverConfig
	seen := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			cfg.Wipe()
			return nil, errors.New("malformed line (expected 'key: value')")
		}
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if seen[key] {
			cfg.Wipe()
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		switch key {
		case "inbox_pub":
			if err := decodeKey32(&cfg.InboxPub, val, "inbox_pub"); err != nil {
				cfg.Wipe()
				return nil, err
			}
		case "k_auth":
			if err := decodeKey32(&cfg.KAuth, val, "k_auth"); err != nil {
				cfg.Wipe()
				return nil, err
			}
		case "token":
			if err := validateToken(val); err != nil {
				cfg.Wipe()
				return nil, err
			}
			cfg.Token = []byte(val)
		default:
			cfg.Wipe()
			return nil, fmt.Errorf("unknown key %q", key)
		}
	}
	if !seen["inbox_pub"] {
		cfg.Wipe()
		return nil, errors.New("missing inbox_pub")
	}
	if !seen["k_auth"] {
		cfg.Wipe()
		return nil, errors.New("missing k_auth")
	}
	return &cfg, nil
}

func decodeKey32(dst *[core.KeySize]byte, s, name string) error {
	b, err := strictB64.DecodeString(s)
	if err != nil || len(b) != core.KeySize {
		clear(b)
		return fmt.Errorf("invalid %s (must be canonical base64 of 32 bytes)", name)
	}
	defer clear(b)
	var zero [core.KeySize]byte
	if subtle.ConstantTimeCompare(b, zero[:]) == 1 {
		return fmt.Errorf("invalid %s (all-zero key)", name)
	}
	copy(dst[:], b)
	return nil
}

func validateToken(s string) error {
	if len(s) < minTokenLen {
		return fmt.Errorf("token must be at least %d bytes", minTokenLen)
	}
	if len(s) > maxTokenLen {
		return fmt.Errorf("token must be at most %d bytes", maxTokenLen)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return errors.New("token must contain only printable ASCII characters without spaces")
		}
	}
	return nil
}

// readTokensFile reads and parses a tokens file (mode 0600, SPEC 8). Nothing it returns or says holds a token.
func readTokensFile(path string, allowEmpty bool) (*tokenSet, error) {
	data, err := readProtectedFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	set, err := parseTokensFile(data, allowEmpty)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", display(path), err)
	}
	return set, nil
}

// readLegacyTokenFile reads a file holding one plaintext token.
func readLegacyTokenFile(path string) ([]byte, error) {
	data, err := readProtectedFile(path)
	if err != nil {
		return nil, err
	}
	tok := strings.TrimRight(string(data), "\r\n")
	clear(data)
	if err := validateToken(tok); err != nil {
		return nil, fmt.Errorf("%s: %w", display(path), err)
	}
	return []byte(tok), nil
}
