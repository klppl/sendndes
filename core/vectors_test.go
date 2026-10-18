package core

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// These tests read the committed vectors and run without the build tag.

func vectorKeys(t *testing.T, v *vectorFile) *VaultKeys {
	t.Helper()
	c, err := ParseConfig(readVectorFile(t, v.Vault.File))
	if err != nil {
		t.Fatalf("parse vault.json: %v", err)
	}
	keys, err := Unlock(c, v.Vault.Passphrase)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	return keys
}

func TestVectorVault(t *testing.T) {
	v := loadVectors(t)
	vv := v.Vault
	data := readVectorFile(t, vv.File)
	if !bytes.Equal(data, vv.VaultJSONHex) {
		t.Fatal("vault.json differs from vault_json_hex")
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if vv.T != kdfT || vv.MKiB != kdfMKiB || vv.P != kdfP || !bytes.Equal(vv.PassphraseHex, []byte(vv.Passphrase)) {
		t.Fatal("vector parameters")
	}
	kek := deriveKEK(vv.PassphraseHex, &c.Salt)
	keys, err := Unlock(c, vv.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	pn := vv.PassphraseNormalization
	if bytes.Equal(pn.NFD, pn.NFC) {
		t.Error("normalization vector: NFD and NFC inputs are equal")
	}
	for _, in := range []hexBytes{pn.NFD, pn.NFC} {
		p, err := normalizePassphrase(string(in))
		if err != nil {
			t.Fatal(err)
		}
		if k := deriveKEK(p, &c.Salt); !bytes.Equal(k[:], pn.KEK) || !bytes.Equal(p, pn.NFC) {
			t.Errorf("passphrase %x: KEK %x, want %x", in, k, pn.KEK)
		}
	}
	unclamped := hkdf32(keys.VK[:], nil, infoInboxX25519)
	checks := []struct {
		name      string
		got, want []byte
	}{
		{"salt", c.Salt[:], vv.Salt},
		{"kek", kek[:], vv.KEK},
		{"vk", keys.VK[:], vv.VK},
		{"wrap_nonce", c.WrappedVK[:NonceSize], vv.WrapNonce},
		{"config_aad", configAAD(&c.Salt, &c.InboxPub), vv.ConfigAAD},
		{"wrapped_vk", c.WrappedVK[:], vv.WrappedVK},
		{"k_wrap", keys.Wrap[:], vv.KWrap},
		{"k_auth", keys.InboxAuth[:], vv.KAuth},
		{"recovery_checksum", recoveryChecksum(&keys.VK), vv.RecoveryChecksum},
		{"inbox_priv_unclamped", unclamped[:], vv.InboxPrivUnclamped},
		{"inbox_priv", keys.InboxPriv[:], vv.InboxPriv},
		{"inbox_pub", keys.InboxPub[:], vv.InboxPub},
	}
	for _, ch := range checks {
		if !bytes.Equal(ch.got, ch.want) {
			t.Errorf("%s: got %x, want %x", ch.name, ch.got, ch.want)
		}
	}
	if len(vv.ConfigAAD) != 83 {
		t.Errorf("config_aad is %d bytes", len(vv.ConfigAAD))
	}
	if got := EncodeRecoveryKey(keys.VK); got != vv.RecoveryKey {
		t.Errorf("recovery key: got %s, want %s", got, vv.RecoveryKey)
	}
	rebuilt := newConfig(vv.PassphraseHex, &keys.VK, vv.Salt, vv.WrapNonce, &keys.InboxPub).Marshal()
	if !bytes.Equal(rebuilt, data) {
		t.Error("re-encrypting vault.json gives different bytes")
	}
}

func checkEncryptedFile(t *testing.T, e *encryptedFile, file []byte, plain []byte) {
	t.Helper()
	if s := sha256.Sum256(file); !bytes.Equal(s[:], e.FileSHA256) {
		t.Error("file sha256")
	}
	if e.FileHex != nil && !bytes.Equal(e.FileHex, file) {
		t.Error("file_hex")
	}
	if s := sha256.Sum256(plain); !bytes.Equal(s[:], e.PlaintextSHA256) || int64(len(plain)) != e.PlaintextLen {
		t.Error("plaintext sha256 or length")
	}
	if e.PlaintextHex != nil && !bytes.Equal(e.PlaintextHex, plain) {
		t.Error("plaintext_hex")
	}
	if !bytes.HasPrefix(file, e.Header) || int64(len(file)-len(e.Header)) != e.CtTotal {
		t.Error("header or ct_total")
	}
	if !bytes.HasSuffix(e.Header, e.MetaBlob) || !bytes.Equal(e.MetaBlob[:NonceSize], e.MetaNonce) {
		t.Error("meta_blob placement or nonce")
	}
	var fk [KeySize]byte
	copy(fk[:], e.FK)
	fkeys := deriveFileKeys(&fk)
	if !bytes.Equal(fkeys.content[:], e.KContent) || !bytes.Equal(fkeys.meta[:], e.KMeta) {
		t.Error("k_content or k_meta")
	}
	var id FileID
	copy(id[:], e.FileID)
	if !bytes.Equal(metaAAD(id), e.MetaAAD) {
		t.Error("meta_aad")
	}
	metaPlain, err := open(&fkeys.meta, e.MetaNonce, e.MetaBlob[NonceSize:], e.MetaAAD)
	if err != nil || !bytes.Equal(metaPlain, e.MetaPlaintext) {
		t.Error("meta_plaintext")
	}
	if size, err := PlaintextSize(e.CtTotal); err != nil || size != e.PlaintextLen {
		t.Errorf("PlaintextSize(%d) = %d, %v", e.CtTotal, size, err)
	}
	if n, _ := chunkCount(e.CtTotal); int(n) != len(e.Chunks) {
		t.Errorf("chunk count %d, vectors list %d", n, len(e.Chunks))
	}
	for _, c := range e.Chunks {
		nonce := chunkNonce(uint64(c.Index), c.Final)
		stored := file[c.Offset : c.Offset+int64(c.StoredLen)]
		pt, err := open(&fkeys.content, nonce[:], stored, e.FileID)
		if !bytes.Equal(nonce[:], c.Nonce) || err != nil || len(pt) != c.PlaintextLen ||
			!bytes.Equal(stored[len(stored)-TagSize:], c.Tag) {
			t.Errorf("chunk %d", c.Index)
		}
	}
}

func TestVectorObjects(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)
	for _, o := range v.Objects {
		t.Run(o.File, func(t *testing.T) {
			file := readVectorFile(t, o.File)
			want := readVectorFile(t, o.PlaintextFile)
			checkEncryptedFile(t, &o.encryptedFile, file, want)

			id, err := ParseObjectPath(o.Path)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			meta, err := DecryptObject(bytes.NewReader(file), int64(len(file)), id, keys, &got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), want) || !bytes.Equal(id[:], o.FileID) {
				t.Fatal("plaintext or file_id differs")
			}
			wantMeta, _ := o.Meta.metadata()
			if meta != wantMeta {
				t.Fatalf("metadata %+v, want %+v", meta, wantMeta)
			}
			if meta.IsNFC() == o.WarnNonNFC {
				t.Fatalf("IsNFC = %v but warn_non_nfc = %v", meta.IsNFC(), o.WarnNonNFC)
			}
			if !bytes.Equal(wrapAAD(id), o.WrapAAD) || !bytes.Equal(file[34:82], o.WrappedFK) {
				t.Fatal("wrap_aad or wrapped_fk")
			}

			var fk [KeySize]byte
			copy(fk[:], o.FK)
			var re bytes.Buffer
			if err := encryptObject(&re, keys, o.MetaPlaintext, bytes.NewReader(want), id, &fk, o.WrapNonce, o.MetaNonce); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(re.Bytes(), file) {
				t.Fatal("re-encryption gives different bytes")
			}
		})
	}
}

func TestVectorInbox(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)
	for _, iv := range v.Inbox {
		t.Run(iv.File, func(t *testing.T) {
			file := readVectorFile(t, iv.File)
			plain := readVectorFile(t, iv.PlaintextFile)
			checkEncryptedFile(t, &iv.encryptedFile, file, plain)

			id, err := ParseInboxName(strings.TrimPrefix(iv.Path, InboxDir+"/"))
			if err != nil || !bytes.Equal(id[:], iv.FileID) {
				t.Fatalf("path %s: %v", iv.Path, err)
			}
			in, err := openInbox(bytes.NewReader(file), int64(len(file)), id, keys)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(in.fk[:], iv.FK) || !bytes.Equal(in.hdr.ephPub[:], iv.EphPub) || !bytes.Equal(iv.InboxPub, keys.InboxPub[:]) {
				t.Fatal("fk, eph_pub or inbox_pub")
			}
			dh, _ := x25519(keys.InboxPriv[:], iv.EphPub)
			if !bytes.Equal(dh, iv.DH) || !bytes.Equal(iv.HKDFSalt, append(append([]byte{}, iv.EphPub...), iv.InboxPub...)) {
				t.Fatal("dh or hkdf_salt")
			}
			if !bytes.Equal(iv.KAuth, keys.InboxAuth[:]) || !bytes.Equal(iv.HKDFIKM, append(append([]byte{}, dh...), iv.KAuth...)) {
				t.Fatal("k_auth or hkdf_ikm")
			}

			// Server side: re-seal with the same values.
			var ephPriv, inboxPub [KeySize]byte
			copy(ephPriv[:], iv.EphPriv)
			copy(inboxPub[:], iv.InboxPub)
			var re bytes.Buffer
			if err := sealInbox(&re, &inboxPub, iv.KAuth, iv.MetaPlaintext, bytes.NewReader(plain), id, &ephPriv, iv.MetaNonce); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(re.Bytes(), file) {
				t.Fatal("re-sealing gives different bytes")
			}

			// Ingest with the same wrap nonce.
			wantObj := readVectorFile(t, iv.Ingest.File)
			var obj bytes.Buffer
			if _, _, err := ingestInbox(bytes.NewReader(file), int64(len(file)), id, keys, &obj, iv.Ingest.WrapNonce); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(obj.Bytes(), wantObj) || !bytes.HasPrefix(wantObj, iv.Ingest.Header) ||
				!bytes.Equal(wantObj[34:82], iv.Ingest.WrappedFK) || !bytes.Equal(wrapAAD(id), iv.Ingest.WrapAAD) {
				t.Fatal("ingested object differs")
			}
			if s := sha256.Sum256(wantObj); !bytes.Equal(s[:], iv.Ingest.FileSHA256) {
				t.Fatal("ingested object sha256")
			}
			// Body is copied, not re-encrypted.
			if !bytes.Equal(wantObj[len(iv.Ingest.Header):], file[len(iv.Header):]) {
				t.Fatal("ingested chunks are not byte-identical")
			}
			var got bytes.Buffer
			meta, err := DecryptObject(bytes.NewReader(wantObj), int64(len(wantObj)), id, keys, &got)
			if err != nil || !bytes.Equal(got.Bytes(), plain) {
				t.Fatalf("decrypt ingested object: %v", err)
			}
			if wantMeta, _ := iv.Meta.metadata(); meta != wantMeta {
				t.Fatal("ingested metadata")
			}
		})
	}
}

func TestVectorMetadata(t *testing.T) {
	v := loadVectors(t)
	for _, mv := range v.Metadata {
		t.Run(mv.Description, func(t *testing.T) {
			in, err := mv.Input.metadata()
			if err != nil {
				t.Fatal(err)
			}
			padded, norm, err := EncodeMetadata(in)
			if mv.Error != "" {
				if got := errorClass(err); got != mv.Error {
					t.Fatalf("got %s, want %s", got, mv.Error)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(padded) != mv.PaddedLen || !bytes.Equal(bytes.TrimRight(padded, " "), mv.Canonical) {
				t.Fatalf("got %q (%d), want %q (%d)", bytes.TrimRight(padded, " "), len(padded), mv.Canonical, mv.PaddedLen)
			}
			back, err := DecodeMetadata(padded)
			if err != nil || back != norm {
				t.Fatalf("decode: %+v, %v", back, err)
			}
		})
	}
}

func TestVectorNegative(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)
	seen := map[string]bool{}
	for _, nv := range v.Negative {
		seen[nv.Name] = true
		t.Run(nv.Name, func(t *testing.T) {
			data := readVectorFile(t, nv.File)
			var err error
			switch nv.Kind {
			case "vault":
				var c *Config
				if c, err = ParseConfig(data); err == nil {
					var k *VaultKeys
					if k, err = Unlock(c, nv.Passphrase); err == nil {
						k.Wipe()
					}
				}
			case "object":
				var id FileID
				if id, err = ParseObjectPath(nv.Path); err == nil {
					_, err = DecryptObject(bytes.NewReader(data), int64(len(data)), id, keys, &bytes.Buffer{})
				}
			case "inbox":
				name, ok := strings.CutPrefix(nv.Path, InboxDir+"/")
				if !ok {
					t.Fatalf("bad inbox path %s", nv.Path)
				}
				var id FileID
				if id, err = ParseInboxName(name); err == nil {
					_, err = IngestInbox(bytes.NewReader(data), int64(len(data)), id, keys, &bytes.Buffer{})
				}
			default:
				t.Fatalf("unknown kind %q", nv.Kind)
			}
			if err == nil {
				t.Fatalf("accepted: %s", nv.Description)
			}
			if got := errorClass(err); got != nv.Expect {
				t.Fatalf("got %s (%v), want %s", got, err, nv.Expect)
			}
			if nv.MetaPlaintext != nil {
				if _, derr := DecodeMetadata(nv.MetaPlaintext); !errors.Is(derr, ErrMetadata) {
					t.Fatalf("DecodeMetadata on the raw plaintext: %v", derr)
				}
			}
		})
	}
	// Every case SPEC 11 asks for must be present.
	for _, name := range []string{
		"obj_flipped_chunk_bit", "obj_truncated_final_chunk", "obj_truncated_at_chunk_boundary",
		"obj_dropped_middle_chunk", "obj_swapped_chunks", "vault_wrong_passphrase", "obj_wrong_file_id",
		"obj_tampered_version", "obj_ct_less_than_16", "obj_ct_residue_5", "obj_empty_final_after_full",
		"meta_duplicate_key", "meta_invalid_utf8", "meta_wrong_key_order", "meta_extra_key",
		"meta_escaped_slash", "meta_float_mtime", "meta_leading_zero", "meta_non_space_padding",
		"inb_no_k_auth", "inb_wrong_k_auth",
		"meta_rev_zero", "path_renamed_object", "path_wrong_prefix", "path_uppercase_name",
	} {
		if !seen[name] {
			t.Errorf("missing negative vector %s", name)
		}
	}
}

func TestVectorMTimeAbove2To53(t *testing.T) {
	v := loadVectors(t)
	for _, o := range v.Objects {
		if m, _ := o.Meta.metadata(); m.MTime > 1<<53 {
			return
		}
	}
	t.Fatal("no object vector has an mtime above 2^53")
}

func TestVectorRecoveryKeys(t *testing.T) {
	v := loadVectors(t)
	if len(v.RecoveryKeys) == 0 {
		t.Fatal("no recovery key vectors")
	}
	for _, rv := range v.RecoveryKeys {
		t.Run(rv.Description, func(t *testing.T) {
			vk, err := DecodeRecoveryKey(rv.Input)
			if rv.Error != "" {
				if got := errorClass(err); got != rv.Error {
					t.Fatalf("got %s (%v), want %s", got, err, rv.Error)
				}
				return
			}
			if err != nil || !bytes.Equal(vk[:], rv.VK) {
				t.Fatalf("decode: %v", err)
			}
		})
	}
	if rk := v.Vault.RecoveryKey; len(rk) != 56+13 || strings.Count(rk, "-") != 13 {
		t.Fatalf("recovery key format: %s", rk)
	}
}
