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
//
// A caller with many inbox files should not keep every prefix in memory (a hostile
// host can plant tens of thousands): it sets Load instead of Prefix. Load fills buf
// (InboxSamplePrefixMax bytes) with the start of the file and returns the filled part,
// or nil if the file cannot be read; it is called while the key is checked, one file at
// a time, and the returned slice is not kept.
type InboxSample struct {
	Prefix []byte
	Size   int64
	ID     FileID
	Load   func(buf []byte) []byte
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
	VerifiedByInbox                          // case 2
	Unverifiable                             // case 3, accepted only with an explicit override
	ChecksumOnly                             // case 4
)

// RecoveryCheck is the result of checking a recovery key.
type RecoveryCheck struct {
	How       Verification
	Readable  int // readable objects (SPEC 4.5)
	Unwrapped int // readable objects that unwrap with the key
}

// CheckRecoveryKey checks a recovery key against the vault in the order of
// SPEC 4.5. Nothing the host can plant makes it reject a correct key: when
// no object unwraps and no inbox file authenticates it returns an error
// wrapping ErrKeyUnverifiable (case 3), which the user may override.
func CheckRecoveryKey(recoveryKey string, s RecoverySamples) (RecoveryCheck, error) {
	var rc RecoveryCheck
	vk, err := DecodeRecoveryKey(recoveryKey)
	if err != nil {
		return rc, err
	}
	defer clear(vk[:])
	keys, err := DeriveVaultKeys(vk)
	if err != nil {
		return rc, err
	}
	defer keys.Wipe()
	for _, o := range s.Objects {
		fk, err := o.unwrapFK(keys)
		switch {
		case err == nil:
			clear(fk[:])
			rc.Readable++
			rc.Unwrapped++
		case errors.Is(err, ErrAuth):
			rc.Readable++ // it passed every check before the unwrap
		}
	}
	if rc.Unwrapped > 0 {
		rc.How = VerifiedByObject
		return rc, nil
	}
	var scratch []byte
	for i := range s.Inbox {
		in := &s.Inbox[i]
		if in.Load != nil {
			if scratch == nil {
				scratch = make([]byte, InboxSamplePrefixMax)
			}
			in.Prefix = in.Load(scratch)
		}
		ok := in.authenticates(keys)
		if in.Load != nil {
			in.Prefix = nil
		}
		if ok {
			rc.How = VerifiedByInbox
			return rc, nil
		}
	}
	if len(s.Objects) > 0 || len(s.Inbox) > 0 {
		rc.How = Unverifiable
		return rc, fmt.Errorf("%w: 0 of %d readable objects unwrap with this key; the key may be wrong or the objects damaged",
			ErrKeyUnverifiable, rc.Readable)
	}
	rc.How = ChecksumOnly
	return rc, nil
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
// case 3 is accepted only if allowUnverified is set. The interactive retype
// SPEC 4.5 asks for in cases 3 and 4 is the caller's job.
func RecoverVault(recoveryKey, newPassphrase string, s RecoverySamples, allowUnverified bool) ([]byte, RecoveryCheck, error) {
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
