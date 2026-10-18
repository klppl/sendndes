package core

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
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

// InboxSample is the start of an inbox file, used to check a recovery key:
// Prefix holds up to the first InboxSamplePrefixMax bytes (enough for the
// header and the first chunk), Size is the full file length and ID the
// file_id from its name.
type InboxSample struct {
	Prefix []byte
	Size   int64
	ID     FileID
}

// InboxSamplePrefixMax is how many bytes of an inbox file an InboxSample needs.
const InboxSamplePrefixMax = inboxFixedHeader + maxMetaLen + StoredChunkSize

// RecoverySamples is what a recovery key is checked against (SPEC 4.5).
type RecoverySamples struct {
	Objects []ObjectSample
	Inbox   []InboxSample
}

// Verification says how a recovery key was checked (SPEC 4.5).
type Verification int

const (
	VerifiedByObject Verification = iota + 1 // case 1
	VerifiedByInbox                          // case 3
	Unverifiable                             // case 4, accepted only with an explicit override
	ChecksumOnly                             // case 5
)

// CheckRecoveryKey checks a recovery key against the vault in the order of
// SPEC 4.5. It returns ErrWrongRecoveryKey when readable objects exist but
// none unwraps (case 2), and an error wrapping ErrKeyUnverifiable in case 4.
func CheckRecoveryKey(recoveryKey string, s RecoverySamples) (Verification, error) {
	vk, err := DecodeRecoveryKey(recoveryKey)
	if err != nil {
		return 0, err
	}
	defer clear(vk[:])
	keys, err := DeriveVaultKeys(vk)
	if err != nil {
		return 0, err
	}
	defer keys.Wipe()
	readable := false
	for _, o := range s.Objects {
		fk, err := o.unwrapFK(keys)
		if err == nil {
			clear(fk[:])
			return VerifiedByObject, nil
		}
		if errors.Is(err, ErrAuth) {
			readable = true // it passed every check before the unwrap
		}
	}
	if readable {
		return 0, fmt.Errorf("%w: readable objects exist but none unwraps with this key", ErrWrongRecoveryKey)
	}
	for _, in := range s.Inbox {
		if in.authenticates(keys) {
			return VerifiedByInbox, nil
		}
	}
	switch {
	case len(s.Objects) > 0:
		return Unverifiable, fmt.Errorf("%w: objects exist but none can be read, so the key cannot be verified", ErrKeyUnverifiable)
	case len(s.Inbox) > 0:
		return Unverifiable, fmt.Errorf("%w: inbox files exist but none authenticate, so the key cannot be verified", ErrKeyUnverifiable)
	}
	return ChecksumOnly, nil
}

// authenticates reports whether the sample's meta_blob and first chunk
// authenticate under keys. A failure proves nothing about the key.
func (s *InboxSample) authenticates(keys *VaultKeys) bool {
	hdr, err := readInboxHeader(bytes.NewReader(s.Prefix))
	if err != nil || hdr.fileID != s.ID {
		return false
	}
	ctTotal := s.Size - hdr.size()
	n, err := chunkCount(ctTotal)
	if err != nil {
		return false
	}
	dh, err := x25519(keys.InboxPriv[:], hdr.ephPub[:])
	if err != nil {
		return false
	}
	fk := inboxFK(dh, keys.InboxAuth[:], &hdr.ephPub, &keys.InboxPub)
	clear(dh)
	defer clear(fk[:])
	fkeys := deriveFileKeys(&fk)
	defer fkeys.wipe()
	if _, err := decryptMeta(hdr.metaBlob, &fkeys.meta, hdr.fileID); err != nil {
		return false
	}
	off, first := hdr.size(), min(StoredChunkSize, ctTotal)
	if int64(len(s.Prefix)) < off+first {
		return false
	}
	nonce := chunkNonce(0, n == 1)
	plain, err := open(&fkeys.content, nonce[:], s.Prefix[off:off+first], hdr.fileID[:])
	clear(plain)
	return err == nil
}

// RecoverVault rebuilds vault.json from the recovery key and a new passphrase
// (SPEC 4.5). It runs CheckRecoveryKey first and writes nothing on an error;
// case 4 is accepted only if allowUnverified is set. The interactive retype
// SPEC 4.5 asks for in cases 4 and 5 is the caller's job.
func RecoverVault(recoveryKey, newPassphrase string, s RecoverySamples, allowUnverified bool) ([]byte, Verification, error) {
	v, err := CheckRecoveryKey(recoveryKey, s)
	if errors.Is(err, ErrKeyUnverifiable) && allowUnverified {
		err = nil
	}
	if err != nil {
		return nil, v, err
	}
	vk, _ := DecodeRecoveryKey(recoveryKey)
	defer clear(vk[:])
	keys, err := DeriveVaultKeys(vk)
	if err != nil {
		return nil, v, err
	}
	defer keys.Wipe()
	salt := make([]byte, SaltSize)
	nonce := make([]byte, NonceSize)
	randomBytes(salt)
	randomBytes(nonce)
	data, err := writeAndVerifyConfig(newPassphrase, &keys.VK, salt, nonce, &keys.InboxPub)
	return data, v, err
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

func unwrapsAny(samples []ObjectSample, keys *VaultKeys) bool {
	for _, s := range samples {
		if fk, err := s.unwrapFK(keys); err == nil {
			clear(fk[:])
			return true
		}
	}
	return false
}
