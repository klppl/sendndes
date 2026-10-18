package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"strings"
)

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	recoveryChecksumLabel = "valv/v1/recovery-checksum"
	recoveryChecksumSize  = 3
	recoveryKeyChars      = (KeySize + recoveryChecksumSize) * 8 / 5 // 56, no unused bits
)

func recoveryChecksum(vk *[KeySize]byte) []byte {
	h := sha256.New()
	h.Write([]byte(recoveryChecksumLabel))
	h.Write(vk[:])
	return h.Sum(nil)[:recoveryChecksumSize]
}

// EncodeRecoveryKey formats VK and its checksum as a recovery key (SPEC 3).
func EncodeRecoveryKey(vk [KeySize]byte) string {
	raw := append(append([]byte{}, vk[:]...), recoveryChecksum(&vk)...)
	s := recoveryEncoding.EncodeToString(raw)
	clear(raw)
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}

// DecodeRecoveryKey parses a recovery key. Spaces and hyphens are ignored and
// ASCII letters are uppercased; nothing else is changed.
func DecodeRecoveryKey(s string) ([KeySize]byte, error) {
	var vk [KeySize]byte
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' || c == '-':
		case c >= 'a' && c <= 'z':
			b = append(b, c-'a'+'A')
		default:
			b = append(b, c)
		}
	}
	defer clear(b)
	if len(b) != recoveryKeyChars {
		return vk, fmt.Errorf("%w: a recovery key has %d characters, not counting hyphens", ErrMalformed, recoveryKeyChars)
	}
	raw := make([]byte, recoveryEncoding.DecodedLen(len(b)))
	defer clear(raw)
	n, err := recoveryEncoding.Decode(raw, b)
	if err != nil || n != KeySize+recoveryChecksumSize {
		return vk, fmt.Errorf("%w: the recovery key contains characters outside A-Z and 2-7", ErrMalformed)
	}
	copy(vk[:], raw[:KeySize])
	if subtle.ConstantTimeCompare(raw[KeySize:n], recoveryChecksum(&vk)) != 1 {
		clear(vk[:])
		return vk, ErrRecoveryKeyTypo
	}
	return vk, nil
}

// ObjectSample is the start of an existing object, used to check a recovery
// key against the vault. Prefix holds at least the first 86 bytes, Size is the
// full file length and ID the file_id from its path.
type ObjectSample struct {
	Prefix []byte
	Size   int64
	ID     FileID
}

// RecoverVault rebuilds vault.json from the recovery key and a new passphrase
// (SPEC 4.5). If samples is non-empty, the recovered VK must unwrap at least
// one of them, or RecoverVault fails with ErrWrongRecoveryKey and returns
// nothing to write. checked reports whether that check ran; if it did not,
// only the checksum vouches for the key.
func RecoverVault(recoveryKey, newPassphrase string, samples []ObjectSample) (vaultJSON []byte, checked bool, err error) {
	vk, err := DecodeRecoveryKey(recoveryKey)
	if err != nil {
		return nil, false, err
	}
	defer clear(vk[:])
	keys, err := DeriveVaultKeys(vk)
	if err != nil {
		return nil, false, err
	}
	defer keys.Wipe()
	if len(samples) > 0 && !unwrapsAny(samples, keys) {
		return nil, true, fmt.Errorf("%w: it unwraps none of the existing objects", ErrWrongRecoveryKey)
	}
	salt := make([]byte, SaltSize)
	nonce := make([]byte, NonceSize)
	randomBytes(salt)
	randomBytes(nonce)
	data, err := writeAndVerifyConfig(newPassphrase, &keys.VK, salt, nonce, &keys.InboxPub)
	return data, len(samples) > 0, err
}

func unwrapsAny(samples []ObjectSample, keys *VaultKeys) bool {
	for _, s := range samples {
		if fk, err := s.unwrapFK(keys); err == nil {
			clear(fk[:])
			return true
		}
	}
	return false
}

// UnlockWithRecoveryKey unlocks the vault from a recovery key (SPEC 4.3).
// samples (possibly empty) are only used to tell ErrVaultAltered from
// ErrWrongRecoveryKey when inbox_pub does not match.
func UnlockWithRecoveryKey(c *Config, recoveryKey string, samples []ObjectSample) (*VaultKeys, error) {
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
	derived, err := DeriveVaultKeys(vk)
	if err != nil {
		return nil, err
	}
	defer derived.Wipe()
	if unwrapsAny(samples, derived) {
		return nil, ErrVaultAltered
	}
	return nil, ErrWrongRecoveryKey
}
