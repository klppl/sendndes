package core

import (
	"encoding/base32"
	"fmt"
	"strings"
)

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const recoveryKeyChars = 52

// EncodeRecoveryKey formats VK as a recovery key (SPEC 3).
func EncodeRecoveryKey(vk [KeySize]byte) string {
	s := recoveryEncoding.EncodeToString(vk[:])
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}

// DecodeRecoveryKey parses a recovery key, ignoring case, spaces and hyphens.
func DecodeRecoveryKey(s string) ([KeySize]byte, error) {
	var vk [KeySize]byte
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(s))
	if len(s) != recoveryKeyChars {
		return vk, fmt.Errorf("%w: recovery key must have %d characters", ErrMalformed, recoveryKeyChars)
	}
	b, err := recoveryEncoding.DecodeString(s)
	if err != nil || len(b) != KeySize || recoveryEncoding.EncodeToString(b) != s {
		clear(b)
		return vk, fmt.Errorf("%w: invalid recovery key", ErrMalformed)
	}
	copy(vk[:], b)
	clear(b)
	return vk, nil
}

// UnlockWithRecoveryKey unlocks the vault from a recovery key (SPEC 4.3).
// sampleObjectHeader is the start of any one object file (at least the first
// 82 bytes), or nil if the vault has no objects. It is only used to tell
// ErrVaultAltered from ErrWrongRecoveryKey when inbox_pub does not match.
func UnlockWithRecoveryKey(c *Config, recoveryKey string, sampleObjectHeader []byte) (*VaultKeys, error) {
	vk, err := DecodeRecoveryKey(recoveryKey)
	if err != nil {
		return nil, err
	}
	defer clear(vk[:])
	keys, err := keysCheckingInboxPub(c, vk)
	if err == nil {
		return keys, nil
	}
	if err != ErrInboxKeyMismatch {
		return nil, err
	}
	if sampleObjectHeader != nil {
		derived, err := DeriveVaultKeys(vk)
		if err != nil {
			return nil, err
		}
		defer derived.Wipe()
		if fk, err := unwrapFKFromPrefix(sampleObjectHeader, derived); err == nil {
			clear(fk[:])
			return nil, ErrVaultAltered
		}
	}
	return nil, ErrWrongRecoveryKey
}
