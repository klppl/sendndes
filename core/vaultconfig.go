package core

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Fixed KDF parameters (SPEC 4.2). v1 accepts nothing else.
const (
	kdfAlg  = "argon2id"
	kdfT    = 3
	kdfMKiB = 65536
	kdfP    = 1

	SaltSize       = 16
	wrappedVKSize  = NonceSize + KeySize + TagSize
	configAADLabel = "valv-config-v1"
)

var b64 = base64.StdEncoding.Strict()

// Config is a parsed vault.json. Only the variable fields are kept; v and the
// KDF parameters are fixed in v1.
type Config struct {
	Salt      [SaltSize]byte
	WrappedVK [wrappedVKSize]byte
	InboxPub  [KeySize]byte
}

// ParseConfig parses and checks vault.json (SPEC 4.2). It does not run the KDF.
func ParseConfig(data []byte) (*Config, error) {
	var raw struct {
		V   *int64 `json:"v"`
		KDF *struct {
			Alg  *string `json:"alg"`
			Salt *string `json:"salt"`
			T    *int64  `json:"t"`
			MKiB *int64  `json:"m_kib"`
			P    *int64  `json:"p"`
		} `json:"kdf"`
		WrappedVK *string `json:"wrapped_vk"`
		InboxPub  *string `json:"inbox_pub"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: vault.json: %v", ErrMalformed, err)
	}
	if raw.V == nil || raw.KDF == nil || raw.WrappedVK == nil || raw.InboxPub == nil ||
		raw.KDF.Alg == nil || raw.KDF.Salt == nil || raw.KDF.T == nil || raw.KDF.MKiB == nil || raw.KDF.P == nil {
		return nil, fmt.Errorf("%w: vault.json: missing field", ErrMalformed)
	}
	if *raw.V != FormatVersion {
		return nil, fmt.Errorf("%w: vault.json version %d", ErrUnsupported, *raw.V)
	}
	if *raw.KDF.Alg != kdfAlg || *raw.KDF.T != kdfT || *raw.KDF.MKiB != kdfMKiB || *raw.KDF.P != kdfP {
		return nil, fmt.Errorf("%w: KDF parameters", ErrUnsupported)
	}
	var c Config
	if err := decodeB64Exact(c.Salt[:], *raw.KDF.Salt); err != nil {
		return nil, fmt.Errorf("%w: vault.json salt", ErrMalformed)
	}
	if err := decodeB64Exact(c.WrappedVK[:], *raw.WrappedVK); err != nil {
		return nil, fmt.Errorf("%w: vault.json wrapped_vk", ErrMalformed)
	}
	if err := decodeB64Exact(c.InboxPub[:], *raw.InboxPub); err != nil {
		return nil, fmt.Errorf("%w: vault.json inbox_pub", ErrMalformed)
	}
	if !bytes.Equal(c.Marshal(), data) {
		return nil, fmt.Errorf("%w: vault.json is not in canonical form", ErrMalformed)
	}
	return &c, nil
}

func decodeB64Exact(dst []byte, s string) error {
	b, err := b64.DecodeString(s)
	if err != nil || len(b) != len(dst) {
		return ErrMalformed
	}
	copy(dst, b)
	return nil
}

// Marshal returns the canonical vault.json bytes (SPEC 4.2).
func (c *Config) Marshal() []byte {
	return fmt.Appendf(nil, "{\n"+
		"  \"v\": %d,\n"+
		"  \"kdf\": { \"alg\": \"%s\", \"salt\": \"%s\", \"t\": %d, \"m_kib\": %d, \"p\": %d },\n"+
		"  \"wrapped_vk\": \"%s\",\n"+
		"  \"inbox_pub\": \"%s\"\n"+
		"}\n",
		FormatVersion, kdfAlg, b64.EncodeToString(c.Salt[:]), kdfT, kdfMKiB, kdfP,
		b64.EncodeToString(c.WrappedVK[:]), b64.EncodeToString(c.InboxPub[:]))
}

// configAAD builds the AAD of wrapped_vk (SPEC 4.2).
func configAAD(salt *[SaltSize]byte, inboxPub *[KeySize]byte) []byte {
	b := make([]byte, 0, 83)
	b = append(b, configAADLabel...)
	b = append(b, byte(len(kdfAlg)))
	b = append(b, kdfAlg...)
	b = append(b, salt[:]...)
	b = binary.BigEndian.AppendUint32(b, kdfT)
	b = binary.BigEndian.AppendUint32(b, kdfMKiB)
	b = binary.BigEndian.AppendUint32(b, kdfP)
	b = append(b, inboxPub[:]...)
	return b
}

// normalizePassphrase checks UTF-8 and returns the NFC form's bytes (SPEC 3).
func normalizePassphrase(passphrase string) ([]byte, error) {
	if !utf8.ValidString(passphrase) {
		return nil, fmt.Errorf("%w: passphrase is not valid UTF-8", ErrMalformed)
	}
	return []byte(norm.NFC.String(passphrase)), nil
}

// deriveKEK runs Argon2id on an already normalized passphrase.
func deriveKEK(passphrase []byte, salt *[SaltSize]byte) [KeySize]byte {
	var kek [KeySize]byte
	k := argon2.IDKey(passphrase, salt[:], kdfT, kdfMKiB, kdfP, KeySize)
	copy(kek[:], k)
	clear(k)
	return kek
}

// newConfig wraps vk under a KEK from a normalized passphrase and salt,
// binding inboxPub.
func newConfig(passphrase []byte, vk *[KeySize]byte, salt, wrapNonce []byte, inboxPub *[KeySize]byte) *Config {
	c := &Config{InboxPub: *inboxPub}
	copy(c.Salt[:], salt)
	kek := deriveKEK(passphrase, &c.Salt)
	defer clear(kek[:])
	ct := seal(&kek, wrapNonce, vk[:], configAAD(&c.Salt, &c.InboxPub))
	copy(c.WrappedVK[:NonceSize], wrapNonce)
	copy(c.WrappedVK[NonceSize:], ct)
	return c
}

// Unlock opens wrapped_vk with the passphrase and checks inbox_pub (SPEC 4.3).
func Unlock(c *Config, passphrase string) (*VaultKeys, error) {
	pass, err := normalizePassphrase(passphrase)
	if err != nil {
		return nil, err
	}
	kek := deriveKEK(pass, &c.Salt)
	clear(pass)
	defer clear(kek[:])
	vkb, err := open(&kek, c.WrappedVK[:NonceSize], c.WrappedVK[NonceSize:], configAAD(&c.Salt, &c.InboxPub))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	var vk [KeySize]byte
	defer clear(vk[:])
	copy(vk[:], vkb)
	clear(vkb)
	return keysCheckingInboxPub(c, vk)
}

func keysCheckingInboxPub(c *Config, vk [KeySize]byte) (*VaultKeys, error) {
	defer clear(vk[:])
	keys, err := DeriveVaultKeys(vk)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(keys.InboxPub[:], c.InboxPub[:]) != 1 {
		keys.Wipe()
		return nil, ErrInboxKeyMismatch
	}
	return keys, nil
}

// CreateVault generates a new VK and returns the vault.json bytes, the
// unlocked keys and the recovery key. Before returning it unlocks the written
// bytes with the passphrase and checks they give the same VK (SPEC 4.3).
func CreateVault(passphrase string) (vaultJSON []byte, keys *VaultKeys, recoveryKey string, err error) {
	var vk [KeySize]byte
	randomBytes(vk[:])
	defer clear(vk[:])
	salt := make([]byte, SaltSize)
	nonce := make([]byte, NonceSize)
	randomBytes(salt)
	randomBytes(nonce)
	derived, err := DeriveVaultKeys(vk)
	if err != nil {
		return nil, nil, "", err
	}
	defer derived.Wipe()
	data, err := writeAndVerifyConfig(passphrase, &vk, salt, nonce, &derived.InboxPub)
	if err != nil {
		return nil, nil, "", err
	}
	keys, err = unlockBytes(data, passphrase)
	if err != nil {
		return nil, nil, "", err
	}
	return data, keys, EncodeRecoveryKey(vk), nil
}

// ChangePassphrase re-wraps VK under a new passphrase with a fresh salt and
// nonce (SPEC 4.4) and returns the new vault.json bytes.
func ChangePassphrase(keys *VaultKeys, newPassphrase string) ([]byte, error) {
	salt := make([]byte, SaltSize)
	nonce := make([]byte, NonceSize)
	randomBytes(salt)
	randomBytes(nonce)
	return writeAndVerifyConfig(newPassphrase, &keys.VK, salt, nonce, &keys.InboxPub)
}

// writeAndVerifyConfig builds vault.json and checks it unlocks to vk.
func writeAndVerifyConfig(passphrase string, vk *[KeySize]byte, salt, nonce []byte, inboxPub *[KeySize]byte) ([]byte, error) {
	pass, err := normalizePassphrase(passphrase)
	if err != nil {
		return nil, err
	}
	data := newConfig(pass, vk, salt, nonce, inboxPub).Marshal()
	clear(pass)
	check, err := unlockBytes(data, passphrase)
	if err != nil {
		return nil, fmt.Errorf("valv: written vault.json does not unlock: %w", err)
	}
	defer check.Wipe()
	if subtle.ConstantTimeCompare(check.VK[:], vk[:]) != 1 {
		return nil, fmt.Errorf("valv: written vault.json unlocks to a different key")
	}
	return data, nil
}

func unlockBytes(data []byte, passphrase string) (*VaultKeys, error) {
	c, err := ParseConfig(data)
	if err != nil {
		return nil, err
	}
	return Unlock(c, passphrase)
}
