//go:build valv_testvectors

// Test-vector generator. It uses fixed keys, ids and nonces, so it exists
// only in this test file behind the valv_testvectors build tag (SPEC 10.9).
// Regenerate with:
//
//	go test -tags valv_testvectors -run TestGenerateVectors ./core

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

const testPassphrase = "correct horse battery staple"

// fixed derives a deterministic test value from a label.
func fixed(label string, n int) []byte {
	sum := sha256.Sum256([]byte("valv-testvector/" + label))
	return sum[:n]
}

func fixed32(label string) *[KeySize]byte {
	var k [KeySize]byte
	copy(k[:], fixed(label, KeySize))
	return &k
}

func fixedID(label string) FileID {
	var id FileID
	copy(id[:], fixed(label, FileIDSize))
	return id
}

// pattern is the plaintext of the content vectors: byte i is (i+seed) mod 251.
func pattern(n int, seed int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i + seed) % 251)
	}
	return b
}

const mtimeNow = 1792310400123456789 // 2026-10-18, above 2^53

type generator struct {
	t    *testing.T
	keys *VaultKeys
	out  vectorFile
}

func (g *generator) write(name string, data []byte) {
	g.t.Helper()
	path := filepath.Join(vectorDir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		g.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		g.t.Fatal(err)
	}
}

func sha(b []byte) hexBytes { s := sha256.Sum256(b); return s[:] }

func smallHex(b []byte) hexBytes {
	if len(b) <= 4096 {
		return b
	}
	return nil
}

func TestGenerateVectors(t *testing.T) {
	for _, dir := range []string{"vault", "objects", "inbox", "negative"} {
		if err := os.RemoveAll(filepath.Join(vectorDir, dir)); err != nil {
			t.Fatal(err)
		}
	}
	g := &generator{t: t}
	g.out.Format = "valv-testvectors-v1"
	vaultJSON := g.genVault()
	g.genObjects()
	g.genInbox()
	g.genMetadata()
	g.genNegative(vaultJSON)

	data, err := json.MarshalIndent(&g.out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	g.write("vectors.json", append(data, '\n'))
}

func (g *generator) genVault() []byte {
	vk := fixed32("vk")
	salt := fixed("vault/salt", SaltSize)
	nonce := fixed("vault/wrap_nonce", NonceSize)
	keys, err := DeriveVaultKeys(*vk)
	if err != nil {
		g.t.Fatal(err)
	}
	g.keys = keys
	c := newConfig([]byte(testPassphrase), vk, salt, nonce, &keys.InboxPub)
	data := c.Marshal()
	kek := deriveKEK([]byte(testPassphrase), &c.Salt)
	unclamped := hkdf32(vk[:], nil, infoInboxX25519)
	g.out.Vault = vaultVector{
		File:               "vault/vault.json",
		Passphrase:         testPassphrase,
		PassphraseHex:      []byte(testPassphrase),
		Salt:               salt,
		T:                  kdfT,
		MKiB:               kdfMKiB,
		P:                  kdfP,
		KEK:                kek[:],
		VK:                 vk[:],
		WrapNonce:          nonce,
		ConfigAAD:          configAAD(&c.Salt, &c.InboxPub),
		WrappedVK:          c.WrappedVK[:],
		KWrap:              keys.Wrap[:],
		InboxPrivUnclamped: unclamped[:],
		InboxPriv:          keys.InboxPriv[:],
		InboxPub:           keys.InboxPub[:],
		RecoveryKey:        EncodeRecoveryKey(*vk),
		VaultJSONHex:       data,
	}
	g.write("vault/vault.json", data)
	return data
}

// fillEncrypted fills the fields shared by object and inbox vectors.
func fillEncrypted(e *encryptedFile, file []byte, headerLen int, plain []byte, id FileID, fk *[KeySize]byte, meta Metadata, readable string, metaPlain, metaNonce []byte) {
	fkeys := deriveFileKeys(fk)
	ct := file[headerLen:]
	n, _ := chunkCount(int64(len(ct)))
	var chunks []chunkVector
	for i := int64(0); i < n; i++ {
		off := i * StoredChunkSize
		end := min(off+StoredChunkSize, int64(len(ct)))
		nonce := chunkNonce(uint64(i), i == n-1)
		chunks = append(chunks, chunkVector{
			Index:        i,
			Final:        i == n-1,
			Offset:       int64(headerLen) + off,
			PlaintextLen: int(end-off) - TagSize,
			StoredLen:    int(end - off),
			Nonce:        nonce[:],
			Tag:          ct[end-TagSize : end],
		})
	}
	*e = encryptedFile{
		Description:     e.Description,
		File:            e.File,
		FileSHA256:      sha(file),
		FileHex:         smallHex(file),
		PlaintextFile:   e.PlaintextFile,
		PlaintextLen:    int64(len(plain)),
		PlaintextSHA256: sha(plain),
		PlaintextHex:    smallHex(plain),
		FileID:          id[:],
		FK:              fk[:],
		KContent:        fkeys.content[:],
		KMeta:           fkeys.meta[:],
		Meta:            newMetaFields(meta, readable),
		MetaPlaintext:   metaPlain,
		MetaNonce:       metaNonce,
		MetaAAD:         metaAAD(id),
		MetaBlob:        file[headerLen-len(metaPlain)-metaOverhead : headerLen],
		Header:          file[:headerLen],
		CtTotal:         int64(len(ct)),
		Chunks:          chunks,
	}
}

// makeObjectRaw encrypts plain with fixed values derived from label.
func (g *generator) makeObjectRaw(label string, metaPlain, plain []byte) []byte {
	var buf bytes.Buffer
	err := encryptObject(&buf, g.keys, metaPlain, bytes.NewReader(plain), fixedID(label+"/file_id"),
		fixed32(label+"/fk"), fixed(label+"/wrap_nonce", NonceSize), fixed(label+"/meta_nonce", NonceSize))
	if err != nil {
		g.t.Fatal(err)
	}
	return buf.Bytes()
}

func (g *generator) genObjects() {
	specs := []struct {
		label, desc, readable string
		meta                  Metadata
		plain                 []byte
	}{
		{"tiny", "Tiny object (13 bytes, one final chunk)", "hello.txt in the root",
			Metadata{Name: "hello.txt", Dir: "", MTime: mtimeNow, MIME: "text/plain", Rev: 1},
			[]byte("Hello, Valv!\n")},
		{"multi", "Multi-chunk object: 3 full chunks plus a 1234-byte partial chunk", "Räkning åäö.pdf in Dokument/Kvitton 2026",
			Metadata{Name: "Räkning åäö.pdf", Dir: "Dokument/Kvitton 2026", MTime: mtimeNow + 1, MIME: "application/pdf", Rev: 3},
			pattern(3*ChunkSize+1234, 0)},
		{"exact", "Exact multiple of the chunk size: 2 full chunks, the second is final", "café.bin in Photos/한국",
			Metadata{Name: "café.bin", Dir: "Photos/한국", MTime: mtimeNow + 2, MIME: "application/octet-stream", Rev: 1},
			pattern(2*ChunkSize, 7)},
		{"empty", "Empty file: one empty final chunk (16 bytes, just the tag)", "empty in a/b/c",
			Metadata{Name: "empty", Dir: "a/b/c", MTime: mtimeNow + 3, MIME: "", Rev: 1},
			nil},
	}
	for _, s := range specs {
		metaPlain, meta, err := EncodeMetadata(s.meta)
		if err != nil {
			g.t.Fatal(err)
		}
		file := g.makeObjectRaw(s.label, metaPlain, s.plain)
		v := objectVector{}
		v.Description = s.desc
		v.File = "objects/" + s.label + ".obj"
		v.PlaintextFile = "objects/" + s.label + ".plain"
		headerLen := objectFixedHeader + len(metaPlain) + metaOverhead
		fillEncrypted(&v.encryptedFile, file, headerLen, s.plain, fixedID(s.label+"/file_id"), fixed32(s.label+"/fk"),
			meta, s.readable, metaPlain, fixed(s.label+"/meta_nonce", NonceSize))
		v.WrapNonce = fixed(s.label+"/wrap_nonce", NonceSize)
		v.WrapAAD = wrapAAD(fixedID(s.label + "/file_id"))
		v.WrappedFK = file[34:82]
		g.write(v.File, file)
		g.write(v.PlaintextFile, s.plain)
		g.out.Objects = append(g.out.Objects, v)
	}
}

func (g *generator) genInbox() {
	const label = "inbox"
	plain := pattern(ChunkSize+5, 3)
	meta := Metadata{Name: "scan-0001.pdf", Dir: "Inbox", MTime: mtimeNow + 4, MIME: "application/pdf", Rev: 1}
	metaPlain, meta, err := EncodeMetadata(meta)
	if err != nil {
		g.t.Fatal(err)
	}
	id := fixedID(label + "/file_id")
	ephPriv := fixed32(label + "/eph_priv")
	metaNonce := fixed(label+"/meta_nonce", NonceSize)
	var buf bytes.Buffer
	if err := sealInbox(&buf, &g.keys.InboxPub, metaPlain, bytes.NewReader(plain), id, ephPriv, metaNonce); err != nil {
		g.t.Fatal(err)
	}
	file := buf.Bytes()
	ephPub, _ := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	dh, _ := curve25519.X25519(ephPriv[:], g.keys.InboxPub[:])
	var ep [KeySize]byte
	copy(ep[:], ephPub)
	fk := inboxFK(dh, &ep, &g.keys.InboxPub)

	v := inboxVector{}
	v.Description = "Inbox file sealed to inbox_pub: one full chunk plus a 5-byte final chunk"
	v.File = "inbox/inbox.inb"
	v.PlaintextFile = "inbox/inbox.plain"
	headerLen := inboxFixedHeader + len(metaPlain) + metaOverhead
	fillEncrypted(&v.encryptedFile, file, headerLen, plain, id, &fk, meta, "scan-0001.pdf in Inbox", metaPlain, metaNonce)
	v.InboxPub = g.keys.InboxPub[:]
	v.EphPriv = ephPriv[:]
	v.EphPub = ephPub
	v.DH = dh
	v.HKDFSalt = append(append([]byte{}, ephPub...), g.keys.InboxPub[:]...)

	wrapNonce := fixed(label+"/ingest_wrap_nonce", NonceSize)
	var obj bytes.Buffer
	if _, _, err := ingestInbox(bytes.NewReader(file), int64(len(file)), g.keys, &obj, wrapNonce); err != nil {
		g.t.Fatal(err)
	}
	objBytes := obj.Bytes()
	v.Ingest.File = "inbox/inbox_ingested.obj"
	v.Ingest.FileSHA256 = sha(objBytes)
	v.Ingest.WrapNonce = wrapNonce
	v.Ingest.WrapAAD = wrapAAD(id)
	v.Ingest.WrappedFK = objBytes[34:82]
	v.Ingest.Header = objBytes[:objectFixedHeader+len(metaPlain)+metaOverhead]

	g.write(v.File, file)
	g.write(v.PlaintextFile, plain)
	g.write(v.Ingest.File, objBytes)
	g.out.Inbox = append(g.out.Inbox, v)
}

func (g *generator) genMetadata() {
	ok := func(desc string, m Metadata, readable string) {
		padded, norm, err := EncodeMetadata(m)
		if err != nil {
			g.t.Fatalf("%s: %v", desc, err)
		}
		g.out.Metadata = append(g.out.Metadata, metadataVector{
			Description: desc,
			Input:       newMetaFields(m, readable),
			Canonical:   canonicalMetadataJSON(&norm),
			PaddedLen:   len(padded),
		})
	}
	bad := func(desc string, m Metadata) {
		if _, _, err := EncodeMetadata(m); err == nil {
			g.t.Fatalf("%s: writer accepted it", desc)
		}
		g.out.Metadata = append(g.out.Metadata, metadataVector{Description: desc, Input: newMetaFields(m, ""), Error: "metadata"})
	}
	m := func(name, dir string) Metadata {
		return Metadata{Name: name, Dir: dir, MTime: mtimeNow, MIME: "text/plain", Rev: 1}
	}

	ok("ASCII name in the root", m("notes.txt", ""), "notes.txt")
	ok("Swedish å ä ö (NFC input)", m("Räksmörgås.txt", "Hem/Kök"), "Räksmörgås.txt in Hem/Kök")
	ok("é (NFC input)", m("café.pdf", "Résumé"), "café.pdf in Résumé")
	ok("Hangul syllables (NFC input)", m("한글.txt", "문서"), "한글.txt in 문서")
	ok("NFD input must be written as NFC", m("Ra\u0308ksmo\u0308rga\u030as.txt", "Ko\u0308k/Cafe\u0301"),
		"Räksmörgås.txt in Kök/Café, given in NFD")
	ok("Escapes: quote, backslash, control characters; DEL and / are literal",
		Metadata{Name: "say \"hi\" \\ back\n\ttab\x1f\x7f", Dir: "a/b", MTime: mtimeNow, MIME: "text/x-weird/é", Rev: 1}, "")
	ok("Negative mtime and the largest rev", Metadata{Name: "old.txt", MTime: -1, Rev: 9223372036854775807}, "")
	empty := Metadata{Name: "", MTime: 0, Rev: 1}
	base := len(canonicalMetadataJSON(&empty))
	ok("Canonical JSON exactly 512 bytes: no padding added",
		Metadata{Name: strings.Repeat("a", metaBlock-base), MTime: 0, Rev: 1}, "")
	ok("Canonical JSON 513 bytes: padded to 1024",
		Metadata{Name: strings.Repeat("a", metaBlock-base+1), MTime: 0, Rev: 1}, "")

	bad("Empty name", m("", ""))
	bad("Name is .", m(".", ""))
	bad("Name is ..", m("..", ""))
	bad("Name contains /", m("a/b", ""))
	bad("Name contains NUL", m("a\x00b", ""))
	bad("Name is invalid UTF-8", m("a\xffb", ""))
	bad("Dir has an empty component", m("x", "a//b"))
	bad("Dir has a leading slash", m("x", "/a"))
	bad("Dir has a trailing slash", m("x", "a/"))
	bad("Dir has a .. component", m("x", "a/../b"))
	bad("Dir has a . component", m("x", "./a"))
	bad("Padded metadata larger than 65536 bytes", m(strings.Repeat("a", MaxMetaPadded), ""))
}

func (g *generator) negative(name, kind, desc, expect string, data []byte) *negativeVector {
	file := "negative/" + name + map[string]string{"vault": ".json", "object": ".obj", "inbox": ".inb"}[kind]
	g.write(file, data)
	g.out.Negative = append(g.out.Negative, negativeVector{Name: name, Description: desc, Kind: kind, File: file, Expect: expect})
	return &g.out.Negative[len(g.out.Negative)-1]
}

func flip(b []byte, at int) []byte {
	c := bytes.Clone(b)
	c[at] ^= 0x01
	return c
}

func (g *generator) objectBytes(i int) []byte {
	data, err := os.ReadFile(filepath.Join(vectorDir, g.out.Objects[i].File))
	if err != nil {
		g.t.Fatal(err)
	}
	return data
}

func (g *generator) genNegative(vaultJSON []byte) {
	// vault.json
	vault := func(name, desc, expect string, data []byte, pass string) {
		g.negative(name, "vault", desc, expect, data).Passphrase = pass
	}
	other := fixed32("negative/other_inbox_pub")
	replace := func(old, new string) []byte {
		if !bytes.Contains(vaultJSON, []byte(old)) {
			g.t.Fatalf("vault.json has no %q", old)
		}
		return bytes.Replace(vaultJSON, []byte(old), []byte(new), 1)
	}
	c, _ := ParseConfig(vaultJSON)
	vault("vault_wrong_passphrase", "Correct vault.json, wrong passphrase", "wrong_passphrase", vaultJSON, "wrong passphrase")
	vault("vault_tampered_inbox_pub", "inbox_pub replaced (it is in config_aad)", "wrong_passphrase",
		replace(b64.EncodeToString(c.InboxPub[:]), b64.EncodeToString(other[:])), testPassphrase)
	vault("vault_tampered_salt", "salt replaced", "wrong_passphrase",
		replace(b64.EncodeToString(c.Salt[:]), b64.EncodeToString(fixed("negative/other_salt", SaltSize))), testPassphrase)
	vault("vault_kdf_t", "t = 2: rejected before the KDF runs", "unsupported", replace(`"t": 3`, `"t": 2`), testPassphrase)
	vault("vault_kdf_m_kib", "m_kib = 32768: rejected before the KDF runs", "unsupported",
		replace(`"m_kib": 65536`, `"m_kib": 32768`), testPassphrase)
	vault("vault_version", "v = 2", "unsupported", replace(`"v": 1`, `"v": 2`), testPassphrase)
	vault("vault_noncanonical", "Extra whitespace: not the canonical writer format", "malformed",
		replace(`"v": 1,`, `"v":  1,`), testPassphrase)
	vault("vault_unknown_key", "Unknown key", "malformed", replace("{\n", "{\n  \"x\": 1,\n"), testPassphrase)
	mismatch := newConfig([]byte(testPassphrase), &g.keys.VK, c.Salt[:], fixed("negative/mismatch_nonce", NonceSize), other)
	vault("vault_inbox_pub_mismatch", "wrapped_vk opens (inbox_pub is in its AAD) but inbox_pub is not the one derived from VK",
		"inbox_key_mismatch", mismatch.Marshal(), testPassphrase)

	// Objects. multi = 3 full chunks + 1250-byte final chunk.
	tiny, multi, exact := g.objectBytes(0), g.objectBytes(1), g.objectBytes(2)
	h := len(g.out.Objects[1].Header)
	obj := func(name, desc, expect string, data []byte) { g.negative(name, "object", desc, expect, data) }
	obj("obj_flipped_chunk_bit", "One bit flipped in chunk 1", "auth", flip(multi, h+StoredChunkSize+100))
	obj("obj_flipped_meta_bit", "One bit flipped in meta_blob ciphertext", "auth", flip(multi, objectFixedHeader+20))
	obj("obj_flipped_wrapped_fk", "One bit flipped in wrapped_fk", "auth", flip(multi, 40))
	obj("obj_wrong_file_id", "file_id in the header changed (it is in wrap_aad)", "auth", flip(multi, 6))
	obj("obj_tampered_version", "Header version byte set to 2", "unsupported", setByte(multi, 4, 2))
	obj("obj_tampered_kind", "Header kind byte set to 2 (inbox)", "malformed", setByte(multi, 5, 2))
	obj("obj_tampered_magic", "Magic changed", "malformed", setByte(multi, 0, 'X'))
	obj("obj_bad_meta_len", "meta_len + 1: not 28 plus a multiple of 512", "malformed", addMetaLen(multi, 82, 1))
	obj("obj_meta_len_shifted", "meta_len + 512: passes the bounds check, meta_blob then fails", "auth", addMetaLen(multi, 82, 512))
	obj("obj_truncated_final_chunk", "Last 10 bytes removed (final chunk still >= 16 bytes)", "auth", multi[:len(multi)-10])
	obj("obj_truncated_at_chunk_boundary", "Final chunk removed: chunk 2 becomes last but has the final flag clear", "auth",
		multi[:h+3*StoredChunkSize])
	obj("obj_dropped_middle_chunk", "Chunk 1 removed", "auth",
		concat(multi[:h+StoredChunkSize], multi[h+2*StoredChunkSize:]))
	obj("obj_swapped_chunks", "Chunks 0 and 1 swapped", "auth",
		concat(multi[:h], multi[h+StoredChunkSize:h+2*StoredChunkSize], multi[h:h+StoredChunkSize], multi[h+2*StoredChunkSize:]))
	th := len(g.out.Objects[0].Header)
	obj("obj_ct_less_than_16", "Structural: ct_total = 10 (< 16)", "malformed", tiny[:th+10])
	obj("obj_ct_zero", "Structural: header only, ct_total = 0 (< 16)", "malformed", tiny[:th])
	obj("obj_ct_residue_5", "Structural: 2 full chunks + 5 bytes (ct_total mod 65552 = 5)", "malformed",
		concat(exact, fixed("negative/residue", 5)))
	obj("obj_empty_final_after_full", "Structural: one full chunk then a correctly encrypted empty final chunk (ct_total mod 65552 = 16)",
		"malformed", g.emptyFinalAfterFull())

	// Metadata, each in an otherwise valid object.
	j := `{"name":"a.txt","dir":"","mtime":1792310400000000000,"mime":"text/plain","rev":1}`
	meta := func(name, desc, plainJSON string, padTo int, padByte byte) {
		p := []byte(plainJSON)
		if padTo == 0 {
			padTo = (len(p) + metaBlock - 1) / metaBlock * metaBlock
		}
		p = append(p, bytes.Repeat([]byte{padByte}, padTo-len(p))...)
		data := g.makeObjectRaw("negative/"+name, p, []byte("x"))
		g.negative(name, "object", desc, "metadata", data).MetaPlaintext = p
	}
	sub := func(old, new string) string {
		if !strings.Contains(j, old) {
			g.t.Fatalf("no %q", old)
		}
		return strings.Replace(j, old, new, 1)
	}
	meta("meta_duplicate_key", "name appears twice", sub(`"dir"`, `"name":"b.txt","dir"`), 0, ' ')
	meta("meta_invalid_utf8", "Invalid UTF-8 byte in name", sub("a.txt", "a\xff.txt"), 0, ' ')
	meta("meta_wrong_key_order", "dir before name", `{"dir":"","name":"a.txt","mtime":1792310400000000000,"mime":"text/plain","rev":1}`, 0, ' ')
	meta("meta_extra_key", "Unknown key x", sub(`"rev":1}`, `"rev":1,"x":1}`), 0, ' ')
	meta("meta_missing_key", "No rev", sub(`,"rev":1}`, `}`), 0, ' ')
	meta("meta_escaped_slash", "dir written as a\\/b", sub(`"dir":""`, `"dir":"a\/b"`), 0, ' ')
	meta("meta_uppercase_escape", "\\u001F with uppercase hex", sub("a.txt", `a\u001Fb`), 0, ' ')
	meta("meta_needless_escape", "\\u0041 for A", sub("a.txt", "\\u0041.txt"), 0, ' ')
	meta("meta_float_mtime", "mtime with a fraction", sub("1792310400000000000", "1792310400000000000.0"), 0, ' ')
	meta("meta_exponent_mtime", "mtime with an exponent", sub("1792310400000000000", "1.7923104e18"), 0, ' ')
	meta("meta_leading_zero", "rev written as 01", sub(`"rev":1`, `"rev":01`), 0, ' ')
	meta("meta_negative_zero", "mtime written as -0", sub("1792310400000000000", "-0"), 0, ' ')
	meta("meta_int64_overflow", "mtime above int64 max", sub("1792310400000000000", "9223372036854775808"), 0, ' ')
	meta("meta_whitespace", "Space after a colon", sub(`"name":"a.txt"`, `"name": "a.txt"`), 0, ' ')
	meta("meta_non_space_padding", "Padded with 0x00 instead of spaces", j, 0, 0x00)
	meta("meta_non_minimal_padding", "Padded to 1024 bytes when 512 is enough", j, 1024, ' ')
	meta("meta_nfd_name", "name in NFD (a + combining diaeresis)", sub("a.txt", "a\u0308.txt"), 0, ' ')
	meta("meta_empty_name", "Empty name", sub(`"name":"a.txt"`, `"name":""`), 0, ' ')
	meta("meta_dotdot_dir", "dir component ..", sub(`"dir":""`, `"dir":"a/../b"`), 0, ' ')

	// Inbox. 1 full chunk + 5-byte final chunk.
	inb, err := os.ReadFile(filepath.Join(vectorDir, g.out.Inbox[0].File))
	if err != nil {
		g.t.Fatal(err)
	}
	ih := len(g.out.Inbox[0].Header)
	in := func(name, desc, expect string, data []byte) { g.negative(name, "inbox", desc, expect, data) }
	in("inb_flipped_chunk_bit", "One bit flipped in chunk 0", "auth", flip(inb, ih+10))
	in("inb_flipped_eph_pub", "One bit flipped in eph_pub: different FK, meta_blob fails", "auth", flip(inb, 30))
	in("inb_zero_eph_pub", "eph_pub all zeros: X25519 result is all zero", "malformed", zeroRange(inb, 22, 54))
	in("inb_tampered_kind", "Header kind byte set to 1 (object)", "malformed", setByte(inb, 5, 1))
	in("inb_ct_residue_11", "Structural: last 10 bytes removed, final chunk is 11 bytes", "malformed", inb[:len(inb)-10])
}

// emptyFinalAfterFull builds an object whose content is one full non-final
// chunk followed by a correctly encrypted empty final chunk.
func (g *generator) emptyFinalAfterFull() []byte {
	const label = "negative/obj_empty_final_after_full"
	metaPlain, _, _ := EncodeMetadata(Metadata{Name: "x", MTime: mtimeNow, Rev: 1})
	plain := pattern(ChunkSize, 1)
	full := g.makeObjectRaw(label, metaPlain, plain)
	h := objectFixedHeader + len(metaPlain) + metaOverhead
	fkeys := deriveFileKeys(fixed32(label + "/fk"))
	id := fixedID(label + "/file_id")
	n0 := chunkNonce(0, false)
	n1 := chunkNonce(1, true)
	c0 := seal(&fkeys.content, n0[:], plain, id[:])
	c1 := seal(&fkeys.content, n1[:], nil, id[:])
	return concat(full[:h], c0, c1)
}

func setByte(b []byte, at int, v byte) []byte {
	c := bytes.Clone(b)
	c[at] = v
	return c
}

func addMetaLen(b []byte, at int, d uint32) []byte {
	c := bytes.Clone(b)
	binary.BigEndian.PutUint32(c[at:], binary.BigEndian.Uint32(c[at:])+d)
	return c
}

func zeroRange(b []byte, from, to int) []byte {
	c := bytes.Clone(b)
	clear(c[from:to])
	return c
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
