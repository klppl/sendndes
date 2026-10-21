package core

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Sizes fixed by the format.
const (
	KeySize   = 32
	NonceSize = chacha20poly1305.NonceSize // 12
	TagSize   = chacha20poly1305.Overhead  // 16
)

// HKDF info labels (SPEC 3, 6.2).
const (
	infoWrap        = "ndes/v1/wrap"
	infoInboxX25519 = "ndes/v1/inbox-x25519"
	infoContent     = "ndes/v1/content"
	infoMeta        = "ndes/v1/meta"
	infoInboxFK     = "ndes/v1/inbox-fk"
	infoInboxAuth   = "ndes/v1/inbox-auth" // inbox epoch 0
)

// hkdf32 is HKDF-SHA256 with L=32. A nil salt is the empty salt.
func hkdf32(ikm, salt []byte, info string) [KeySize]byte {
	var out [KeySize]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte(info)), out[:]); err != nil {
		panic("ndes: hkdf: " + err.Error()) // cannot happen for L=32
	}
	return out
}

// VaultKeys holds VK and the keys derived from it. Call Wipe when done.
type VaultKeys struct {
	VK        [KeySize]byte
	Wrap      [KeySize]byte
	InboxPriv [KeySize]byte // clamped
	InboxPub  [KeySize]byte
	InboxAuth [KeySize]byte // K_auth, for the inbox server
}

// DeriveVaultKeys derives K_wrap and the inbox key pair from VK (SPEC 3).
func DeriveVaultKeys(vk [KeySize]byte) (*VaultKeys, error) {
	k := &VaultKeys{VK: vk}
	k.Wrap = hkdf32(vk[:], nil, infoWrap)
	k.InboxAuth = hkdf32(vk[:], nil, infoInboxAuth)
	k.InboxPriv = hkdf32(vk[:], nil, infoInboxX25519)
	clamp(&k.InboxPriv)
	pub, err := curve25519.X25519(k.InboxPriv[:], curve25519.Basepoint)
	if err != nil {
		k.Wipe()
		return nil, fmt.Errorf("ndes: derive inbox key: %w", err)
	}
	copy(k.InboxPub[:], pub)
	return k, nil
}

// Wipe zeroes the key material.
func (k *VaultKeys) Wipe() {
	clear(k.VK[:])
	clear(k.Wrap[:])
	clear(k.InboxPriv[:])
	clear(k.InboxAuth[:])
}

// clamp applies RFC 7748 clamping to an X25519 private key.
func clamp(b *[KeySize]byte) {
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
}

// fileKeys are the subkeys of one FK.
type fileKeys struct {
	content [KeySize]byte
	meta    [KeySize]byte
}

func deriveFileKeys(fk *[KeySize]byte) fileKeys {
	return fileKeys{
		content: hkdf32(fk[:], nil, infoContent),
		meta:    hkdf32(fk[:], nil, infoMeta),
	}
}

func (f *fileKeys) wipe() {
	clear(f.content[:])
	clear(f.meta[:])
}

// inboxFK derives an inbox file's FK from the X25519 shared secret and
// K_auth (SPEC 6.2). kAuth is only nil when building negative test vectors.
func inboxFK(dh, kAuth []byte, ephPub, inboxPub *[KeySize]byte) [KeySize]byte {
	salt := make([]byte, 0, 2*KeySize)
	salt = append(salt, ephPub[:]...)
	salt = append(salt, inboxPub[:]...)
	ikm := make([]byte, 0, len(dh)+len(kAuth))
	ikm = append(ikm, dh...)
	ikm = append(ikm, kAuth...)
	defer clear(ikm)
	return hkdf32(ikm, salt, infoInboxFK)
}

// x25519 computes a shared secret, rejecting an all-zero result.
func x25519(priv, pub []byte) ([]byte, error) {
	dh, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, fmt.Errorf("%w: X25519 with a low-order point", ErrMalformed)
	}
	return dh, nil
}

func seal(key *[KeySize]byte, nonce, plaintext, aad []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("ndes: chacha20poly1305: " + err.Error())
	}
	return aead.Seal(nil, nonce, plaintext, aad)
}

func open(key *[KeySize]byte, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("ndes: chacha20poly1305: " + err.Error())
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// randomBytes fills b from the OS CSPRNG.
func randomBytes(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("ndes: crypto/rand: " + err.Error())
	}
}
