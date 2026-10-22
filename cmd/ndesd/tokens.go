package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// tokenRole says which calls a token may make. A phone that only sends gets roleUpload, so a stolen phone
// cannot read or delete anything in the inbox.
type tokenRole uint8

const (
	roleUpload tokenRole = 1 << iota
	rolePull
	roleBoth = roleUpload | rolePull
)

func (r tokenRole) canUpload() bool { return r&roleUpload != 0 }
func (r tokenRole) canPull() bool   { return r&rolePull != 0 }

func parseRole(s string) (tokenRole, bool) {
	switch s {
	case "upload":
		return roleUpload, true
	case "pull":
		return rolePull, true
	case "both":
		return roleBoth, true
	}
	return 0, false
}

const (
	maxTokenLabelLen  = 32
	maxTokensFileSize = 64 << 10
	maxTokenEntries   = 256
)

// tokenEntry is one accepted token, known only by its SHA-256 (the server never holds the token itself).
type tokenEntry struct {
	role  tokenRole
	label string
	hash  [32]byte
}

// tokenSet is immutable once built; a reload swaps the whole set.
type tokenSet struct {
	entries []tokenEntry
}

// lookup checks a presented token against every entry without stopping at the first match, so the
// time taken does not depend on which entry (if any) matched.
func (t *tokenSet) lookup(token string) (tokenRole, string, bool) {
	h := sha256.Sum256([]byte(token))
	var role tokenRole
	var label string
	found := 0
	for i := range t.entries {
		eq := subtle.ConstantTimeCompare(h[:], t.entries[i].hash[:])
		if eq == 1 {
			role, label = t.entries[i].role, t.entries[i].label
		}
		found |= eq
	}
	return role, label, found == 1
}

// legacyTokenSet is the single plaintext token of the old configuration, with the role both.
func legacyTokenSet(token []byte) *tokenSet {
	return &tokenSet{entries: []tokenEntry{{role: roleBoth, label: "legacy", hash: sha256.Sum256(token)}}}
}

// merge returns a set holding the entries of both, or an error if a hash or label repeats.
func mergeTokenSets(a, b *tokenSet) (*tokenSet, error) {
	out := &tokenSet{}
	seenHash := map[[32]byte]bool{}
	seenLabel := map[string]bool{}
	for _, s := range []*tokenSet{a, b} {
		if s == nil {
			continue
		}
		for _, e := range s.entries {
			if seenHash[e.hash] {
				return nil, errors.New("the same token appears twice")
			}
			if seenLabel[e.label] {
				return nil, fmt.Errorf("label %q appears twice", e.label)
			}
			seenHash[e.hash], seenLabel[e.label] = true, true
			out.entries = append(out.entries, e)
		}
	}
	return out, nil
}

// parseTokensFile reads lines of `<role> <label> <sha256-hex>`: role upload, pull or both; a label of
// 1 to 32 printable ASCII characters without spaces; the lowercase hex SHA-256 of the token. Blank lines
// and lines starting with # are ignored. Error messages never repeat a hash.
func parseTokensFile(data []byte, allowEmpty bool) (*tokenSet, error) {
	if len(data) > maxTokensFileSize {
		return nil, fmt.Errorf("tokens file is larger than %d bytes", maxTokensFileSize)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("tokens file is not valid UTF-8")
	}
	set := &tokenSet{}
	seenHash := map[[32]byte]bool{}
	seenLabel := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("line %d: expected `<role> <label> <sha256-hex>`", i+1)
		}
		role, ok := parseRole(f[0])
		if !ok {
			return nil, fmt.Errorf("line %d: role must be upload, pull or both", i+1)
		}
		if err := validTokenLabel(f[1]); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if len(f[2]) != 64 || f[2] != strings.ToLower(f[2]) {
			return nil, fmt.Errorf("line %d: the token hash must be 64 lowercase hex characters", i+1)
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil {
			return nil, fmt.Errorf("line %d: the token hash must be 64 lowercase hex characters", i+1)
		}
		var h [32]byte
		copy(h[:], raw)
		if seenHash[h] {
			return nil, fmt.Errorf("line %d: the same token appears twice", i+1)
		}
		if seenLabel[f[1]] {
			return nil, fmt.Errorf("line %d: label %q appears twice", i+1, f[1])
		}
		seenHash[h], seenLabel[f[1]] = true, true
		set.entries = append(set.entries, tokenEntry{role: role, label: f[1], hash: h})
		if len(set.entries) > maxTokenEntries {
			return nil, fmt.Errorf("more than %d tokens", maxTokenEntries)
		}
	}
	if len(set.entries) == 0 && !allowEmpty {
		return nil, errors.New("no tokens in the file")
	}
	return set, nil
}

func validTokenLabel(s string) error {
	if s == "" || len(s) > maxTokenLabelLen {
		return fmt.Errorf("label must be 1 to %d characters", maxTokenLabelLen)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return errors.New("label must be printable ASCII without spaces")
		}
	}
	return nil
}
