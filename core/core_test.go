package core

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

var roundTripSizes = []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 1}

func testKeys(t *testing.T) *VaultKeys {
	t.Helper()
	var vk [KeySize]byte
	randomBytes(vk[:])
	keys, err := DeriveVaultKeys(vk)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func randomContent(n int) []byte {
	b := make([]byte, n)
	randomBytes(b)
	return b
}

var testMeta = Metadata{Name: "file.bin", Dir: "x/y", MTime: 1792310400123456789, MIME: "application/octet-stream", Rev: 1}

func TestObjectRoundTrip(t *testing.T) {
	keys := testKeys(t)
	for _, n := range roundTripSizes {
		plain := randomContent(n)
		var file bytes.Buffer
		// OneByteReader makes the lookahead work with short reads.
		id, err := EncryptObject(&file, keys, testMeta, iotest.OneByteReader(bytes.NewReader(plain)))
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		data := file.Bytes()
		headerLen := objectFixedHeader + metaBlock + metaOverhead
		chunks := max(1, (n+ChunkSize-1)/ChunkSize)
		if len(data) != headerLen+n+TagSize*chunks {
			t.Fatalf("%d: file is %d bytes, want %d", n, len(data), headerLen+n+TagSize*chunks)
		}
		if size, err := PlaintextSize(int64(len(data) - headerLen)); err != nil || size != int64(n) {
			t.Fatalf("%d: PlaintextSize = %d, %v", n, size, err)
		}
		var out bytes.Buffer
		meta, err := DecryptObject(bytes.NewReader(data), int64(len(data)), id, keys, &out)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if meta != testMeta || !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("%d: round trip differs", n)
		}
		info, err := ReadObjectInfo(bytes.NewReader(data), int64(len(data)), id, keys)
		if err != nil || info.ID != id || info.Meta != testMeta || info.PlaintextSize != int64(n) {
			t.Fatalf("%d: ReadObjectInfo: %v", n, err)
		}
		var other FileID
		randomBytes(other[:])
		if _, err := DecryptObject(bytes.NewReader(data), int64(len(data)), other, keys, &out); !errors.Is(err, ErrPathMismatch) {
			t.Fatalf("%d: wrong expected id: %v", n, err)
		}
	}
}

func TestInboxRoundTrip(t *testing.T) {
	keys := testKeys(t)
	for _, n := range roundTripSizes {
		plain := randomContent(n)
		meta := testMeta
		meta.Rev = 7 // SealInbox must force rev 1
		var inb bytes.Buffer
		id, err := SealInbox(&inb, keys.InboxPub, keys.InboxAuth, meta, bytes.NewReader(plain))
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if _, err := VerifyInbox(bytes.NewReader(inb.Bytes()), int64(inb.Len()), id, keys); err != nil {
			t.Fatalf("%d: verify: %v", n, err)
		}
		var obj bytes.Buffer
		gotMeta, err := IngestInbox(bytes.NewReader(inb.Bytes()), int64(inb.Len()), id, keys, &obj)
		if err != nil || gotMeta.Rev != 1 {
			t.Fatalf("%d: ingest: %v", n, err)
		}
		var out bytes.Buffer
		if _, err := DecryptObject(bytes.NewReader(obj.Bytes()), int64(obj.Len()), id, keys, &out); err != nil || !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("%d: decrypt ingested: %v", n, err)
		}
	}
}

func TestEncryptIsRandomized(t *testing.T) {
	keys := testKeys(t)
	var a, b bytes.Buffer
	idA, _ := EncryptObject(&a, keys, testMeta, strings.NewReader("same"))
	idB, _ := EncryptObject(&b, keys, testMeta, strings.NewReader("same"))
	if idA == idB || bytes.Equal(a.Bytes()[22:], b.Bytes()[22:]) {
		t.Fatal("two encryptions share file_id, FK or nonces")
	}
}

func TestStructuralCheck(t *testing.T) {
	cases := []struct {
		ct int64
		ok bool
	}{
		{0, false}, {15, false}, {16, true}, {17, true},
		{StoredChunkSize, true}, {StoredChunkSize + 1, false}, {StoredChunkSize + 15, false},
		{StoredChunkSize + 16, false}, {StoredChunkSize + 17, true}, {3 * StoredChunkSize, true},
		{3*StoredChunkSize + 16, false}, {-1, false},
	}
	for _, c := range cases {
		if _, err := chunkCount(c.ct); (err == nil) != c.ok {
			t.Errorf("ct_total %d: err = %v, want ok = %v", c.ct, err, c.ok)
		}
	}
}

func TestCreateUnlockChangePassphrase(t *testing.T) {
	data, keys, rk, err := CreateVault("first")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(c, "nope"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	k2, err := UnlockWithRecoveryKey(c, strings.ToLower(strings.ReplaceAll(rk, "-", " ")), nil)
	if err != nil || k2.VK != keys.VK {
		t.Fatalf("recovery key: %v", err)
	}

	newData, err := ChangePassphrase(keys, "second")
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := ParseConfig(newData)
	if c2.Salt == c.Salt || [NonceSize]byte(c2.WrappedVK[:NonceSize]) == [NonceSize]byte(c.WrappedVK[:NonceSize]) {
		t.Fatal("passphrase change reused salt or nonce")
	}
	if _, err := Unlock(c2, "first"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatal("old passphrase still works")
	}
	k3, err := Unlock(c2, "second")
	if err != nil || k3.VK != keys.VK {
		t.Fatalf("new passphrase: %v", err)
	}
}

func TestRecoveryKeyFormat(t *testing.T) {
	var vk [KeySize]byte
	randomBytes(vk[:])
	rk := EncodeRecoveryKey(vk)
	if len(rk) != 56+13 || strings.Count(rk, "-") != 13 || strings.ToUpper(rk) != rk {
		t.Fatalf("format: %s", rk)
	}
	for _, in := range []string{rk, strings.ToLower(rk), strings.ReplaceAll(rk, "-", ""), strings.ReplaceAll(rk, "-", " ")} {
		if got, err := DecodeRecoveryKey(in); err != nil || got != vk {
			t.Fatalf("decode %q: %v", in, err)
		}
	}
	flat := strings.ReplaceAll(rk, "-", "")
	// Every single-character change is caught by the checksum or the alphabet.
	for i := 0; i < len(flat); i++ {
		for _, c := range "A7Q2" {
			if byte(c) == flat[i] {
				continue
			}
			in := flat[:i] + string(c) + flat[i+1:]
			if _, err := DecodeRecoveryKey(in); !errors.Is(err, ErrRecoveryKeyTypo) {
				t.Fatalf("change at %d: got %v", i, err)
			}
		}
	}
	for _, in := range []string{flat[:52], flat + "A", flat[:55] + "1", "\u0131" + flat[1:]} {
		if _, err := DecodeRecoveryKey(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: got %v", in, err)
		}
	}
}

// TestRecoveryKeyASCIIUppercaseOnly is the regression test for review I1:
// strings.ToUpper turned the dotless i into I.
func TestRecoveryKeyASCIIUppercaseOnly(t *testing.T) {
	for {
		var vk [KeySize]byte
		randomBytes(vk[:])
		flat := strings.ReplaceAll(EncodeRecoveryKey(vk), "-", "")
		i := strings.IndexAny(flat, "IS")
		if i < 0 {
			continue
		}
		repl := map[byte]string{'I': "\u0131", 'S': "\u017f"}[flat[i]]
		if _, err := DecodeRecoveryKey(flat[:i] + repl + flat[i+1:]); err == nil {
			t.Fatalf("accepted a non-ASCII look-alike of %c", flat[i])
		}
		return
	}
}

func sampleOf(t *testing.T, file []byte, id FileID) ObjectSample {
	t.Helper()
	return ObjectSample{Prefix: file[:min(len(file), 86)], Size: int64(len(file)), ID: id}
}

func TestRecoveryUnlockDiagnosis(t *testing.T) {
	v := loadVectors(t)
	data := readVectorFile(t, v.Vault.File)
	c, _ := ParseConfig(data)
	id, _ := ParseObjectPath(v.Objects[0].Path)
	samples := []ObjectSample{sampleOf(t, readVectorFile(t, v.Objects[0].File), id)}

	// Right key, vault.json with another inbox_pub.
	altered := *c
	altered.InboxPub[0] ^= 1
	if _, err := UnlockWithRecoveryKey(&altered, v.Vault.RecoveryKey, samples); !errors.Is(err, ErrVaultAltered) {
		t.Fatalf("altered vault.json: %v", err)
	}
	if _, err := UnlockWithRecoveryKey(&altered, v.Vault.RecoveryKey, nil); !errors.Is(err, ErrWrongRecoveryKey) {
		t.Fatalf("altered vault.json, no objects: %v", err)
	}
	var other [KeySize]byte
	randomBytes(other[:])
	if _, err := UnlockWithRecoveryKey(c, EncodeRecoveryKey(other), samples); !errors.Is(err, ErrWrongRecoveryKey) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := UnlockWithRecoveryKey(c, v.Vault.RecoveryKey, samples); err != nil {
		t.Fatalf("right key: %v", err)
	}
}

func TestCheckAlreadyIngested(t *testing.T) {
	keys := testKeys(t)
	plain := randomContent(ChunkSize + 100)
	var inb bytes.Buffer
	id, err := SealInbox(&inb, keys.InboxPub, keys.InboxAuth, testMeta, bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	inbox := inb.Bytes()
	ingest := func() []byte {
		var obj bytes.Buffer
		if _, err := IngestInbox(bytes.NewReader(inbox), int64(len(inbox)), id, keys, &obj); err != nil {
			t.Fatal(err)
		}
		return obj.Bytes()
	}
	check := func(obj []byte) error {
		return CheckAlreadyIngested(bytes.NewReader(inbox), int64(len(inbox)), bytes.NewReader(obj), int64(len(obj)), id, keys)
	}

	obj := ingest()
	if err := check(obj); err != nil {
		t.Fatalf("own ingest result: %v", err)
	}

	// Renamed after ingest: new meta_blob under the same FK. Still ingested.
	o, err := openObject(bytes.NewReader(obj), int64(len(obj)), id, keys)
	if err != nil {
		t.Fatal(err)
	}
	renamed := testMeta
	renamed.Name, renamed.Rev = "renamed.bin", 2
	metaPlain, _, _ := EncodeMetadata(renamed)
	nonce := make([]byte, NonceSize)
	randomBytes(nonce)
	o.hdr.metaBlob = encryptMeta(metaPlain, &o.keys.meta, o.hdr.fileID, nonce)
	oldHeaderLen := objectFixedHeader + metaBlock + metaOverhead
	renamedObj := append(o.hdr.marshal(), obj[oldHeaderLen:]...)
	if err := check(renamedObj); err != nil {
		t.Fatalf("renamed object: %v", err)
	}

	// Same id, different FK: someone else's object. Conflict.
	var other bytes.Buffer
	var fk [KeySize]byte
	randomBytes(fk[:])
	plainMeta, _, _ := EncodeMetadata(testMeta)
	if err := encryptObject(&other, keys, plainMeta, bytes.NewReader(plain), o.hdr.fileID, &fk, nonce, nonce); err != nil {
		t.Fatal(err)
	}
	if err := check(other.Bytes()); !errors.Is(err, ErrConflict) {
		t.Fatalf("different FK: %v", err)
	}

	// Same FK, one chunk byte changed. Conflict.
	tampered := bytes.Clone(obj)
	tampered[len(tampered)-1] ^= 1
	if err := check(tampered); !errors.Is(err, ErrConflict) {
		t.Fatalf("different chunk bytes: %v", err)
	}

	// Truncated existing object. Conflict.
	if err := check(obj[:len(obj)-5]); !errors.Is(err, ErrConflict) {
		t.Fatalf("truncated object: %v", err)
	}
}

func TestIngestWritesNothingAfterBadChunk(t *testing.T) {
	keys := testKeys(t)
	var inb bytes.Buffer
	id, err := SealInbox(&inb, keys.InboxPub, keys.InboxAuth, testMeta, bytes.NewReader(randomContent(2*ChunkSize+10)))
	if err != nil {
		t.Fatal(err)
	}
	data := inb.Bytes()
	headerLen := inboxFixedHeader + metaBlock + metaOverhead
	data[headerLen+StoredChunkSize+5] ^= 1 // corrupt chunk 1
	var obj bytes.Buffer
	_, err = IngestInbox(bytes.NewReader(data), int64(len(data)), id, keys, &obj)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v", err)
	}
	// Header and chunk 0 only: chunk 1 was never written.
	if obj.Len() != objectFixedHeader+metaBlock+metaOverhead+StoredChunkSize {
		t.Fatalf("wrote %d bytes", obj.Len())
	}
}

func TestMetadataDecodeEdgeCases(t *testing.T) {
	good, _, _ := EncodeMetadata(testMeta)
	if _, err := DecodeMetadata(good); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string][]byte{
		"empty":          nil,
		"not multiple":   good[:511],
		"too large":      bytes.Repeat([]byte{' '}, MaxMetaPadded+metaBlock),
		"all spaces":     bytes.Repeat([]byte{' '}, metaBlock),
		"trailing tab":   append(bytes.Clone(good[:len(good)-1]), '\t'),
		"raw control":    []byte(strings.Replace(string(good), "file.bin", "fi\nle.bin", 1)),
		"truncated \\u":  padTo512(`{"name":"a\u00`),
		"escaped \\b":    padTo512(`{"name":"a\bb","dir":"","mtime":0,"mime":"","rev":1}`),
		"int overflow":   padTo512(`{"name":"a","dir":"","mtime":0,"mime":"","rev":99999999999999999999}`),
		"plus sign":      padTo512(`{"name":"a","dir":"","mtime":+1,"mime":"","rev":1}`),
		"trailing bytes": padTo512(`{"name":"a","dir":"","mtime":0,"mime":"","rev":1}}`),
	} {
		if _, err := DecodeMetadata(p); !errors.Is(err, ErrMetadata) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func padTo512(s string) []byte {
	p, err := padMetadata([]byte(s))
	if err != nil {
		panic(err)
	}
	return p
}

func TestPaths(t *testing.T) {
	var id FileID
	randomBytes(id[:])
	id[0] = 0xab
	p := ObjectPath(id)
	if got, err := ParseObjectPath(p); err != nil || got != id {
		t.Fatalf("ParseObjectPath(%s) = %v, %v", p, got, err)
	}
	if got, err := ParseInboxName(InboxName(id)); err != nil || got != id {
		t.Fatalf("ParseInboxName: %v", err)
	}
	s := id.String()
	for _, bad := range []string{
		"objects/AB/" + strings.ToUpper(s) + ".obj",
		"objects/ab/" + strings.ToUpper(s) + ".obj",
		"objects/00/" + s + ".obj",
		"objects/ab/" + s + ".OBJ",
		"objects/ab/" + s,
		"objects/ab/" + s[:31] + ".obj",
		"objects/ab/" + s + "0.obj",
		"objects/ab/" + s + ".obj.part",
		"objects/" + s + ".obj",
		"inbox/ab/" + s + ".obj",
		"objects/ab/x/" + s + ".obj",
	} {
		if _, err := ParseObjectPath(bad); !errors.Is(err, ErrPathMismatch) {
			t.Errorf("accepted %s", bad)
		}
	}
	for _, bad := range []string{strings.ToUpper(s) + ".inb", s + ".obj", s, s + ".inb.part"} {
		if _, err := ParseInboxName(bad); !errors.Is(err, ErrPathMismatch) {
			t.Errorf("accepted inbox name %s", bad)
		}
	}
}

func TestPassphraseNormalization(t *testing.T) {
	if _, err := Unlock(&Config{}, "bad\xff"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("invalid UTF-8 passphrase: %v", err)
	}
	if _, _, _, err := CreateVault("bad\xff"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("CreateVault with invalid UTF-8: %v", err)
	}
	// NFD at create, NFC at unlock. Spaces are kept, case matters.
	data, _, _, err := CreateVault(" Ko\u0308k ")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ParseConfig(data)
	if k, err := Unlock(c, " K\u00f6k "); err != nil {
		t.Fatalf("NFC form: %v", err)
	} else {
		k.Wipe()
	}
	for _, wrong := range []string{"K\u00f6k", " k\u00f6k "} {
		if _, err := Unlock(c, wrong); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%q unlocked", wrong)
		}
	}
}

func TestRecoverVault(t *testing.T) {
	_, keys, rk, err := CreateVault("old")
	if err != nil {
		t.Fatal(err)
	}
	var obj bytes.Buffer
	id, err := EncryptObject(&obj, keys, testMeta, strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	ours := sampleOf(t, obj.Bytes(), id)
	// A decoy: structurally valid, random wrapped_fk.
	decoyBytes := bytes.Clone(obj.Bytes())
	copy(decoyBytes[34:82], randomContent(wrappedFKSize))
	decoy := sampleOf(t, decoyBytes, id)
	// One bit flipped in wrapped_fk.
	flippedBytes := bytes.Clone(obj.Bytes())
	flippedBytes[40] ^= 1
	flipped := sampleOf(t, flippedBytes, id)
	damaged := ours
	damaged.Size = 10 // fails the structural check: not readable

	var inb bytes.Buffer
	inID, _ := SealInbox(&inb, keys.InboxPub, keys.InboxAuth, testMeta, bytes.NewReader(randomContent(ChunkSize+10)))
	genuine := InboxSample{Prefix: inb.Bytes(), Size: int64(inb.Len()), ID: inID}
	var forged bytes.Buffer
	forgedID, _ := SealInbox(&forged, keys.InboxPub, [KeySize]byte{1}, testMeta, strings.NewReader("planted"))
	planted := InboxSample{Prefix: forged.Bytes(), Size: int64(forged.Len()), ID: forgedID}
	var garbageID FileID
	randomBytes(garbageID[:])
	garbage := InboxSample{Prefix: randomContent(300), Size: 300, ID: garbageID}

	// A wrong but valid key: another vault's recovery key.
	_, _, otherRK, err := CreateVault("other")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name              string
		key               string
		s                 RecoverySamples
		want              Verification
		readable, unwraps int
		unverifiable      bool
	}{
		{"1: one object unwraps, a decoy does not", rk, RecoverySamples{Objects: []ObjectSample{decoy, ours}}, VerifiedByObject, 2, 1, false},
		{"1: a bit-flipped wrapped_fk next to a good object", rk, RecoverySamples{Objects: []ObjectSample{flipped, ours, damaged}}, VerifiedByObject, 2, 1, false},
		{"2: decoy only, genuine inbox file", rk, RecoverySamples{Objects: []ObjectSample{decoy}, Inbox: []InboxSample{planted, genuine}}, VerifiedByInbox, 1, 0, false},
		{"2: no objects, genuine inbox file", rk, RecoverySamples{Inbox: []InboxSample{genuine}}, VerifiedByInbox, 0, 0, false},
		{"3: right key, only a decoy", rk, RecoverySamples{Objects: []ObjectSample{decoy}}, Unverifiable, 1, 0, true},
		{"3: right key, only a bit-flipped wrapped_fk", rk, RecoverySamples{Objects: []ObjectSample{flipped}}, Unverifiable, 1, 0, true},
		{"3: wrong but valid key from another vault", otherRK, RecoverySamples{Objects: []ObjectSample{ours}, Inbox: []InboxSample{genuine}}, Unverifiable, 1, 0, true},
		{"3: only damaged objects", rk, RecoverySamples{Objects: []ObjectSample{damaged}}, Unverifiable, 0, 0, true},
		{"3: planted garbage inbox file", rk, RecoverySamples{Inbox: []InboxSample{garbage}}, Unverifiable, 0, 0, true},
		{"3: inbox file forged without K_auth", rk, RecoverySamples{Inbox: []InboxSample{planted}}, Unverifiable, 0, 0, true},
		{"4: nothing to check against", rk, RecoverySamples{}, ChecksumOnly, 0, 0, false},
	}
	for _, c := range cases {
		rc, err := CheckRecoveryKey(c.key, c.s)
		if rc.How != c.want || rc.Readable != c.readable || rc.Unwrapped != c.unwraps || errors.Is(err, ErrKeyUnverifiable) != c.unverifiable {
			t.Errorf("%s: got %+v, %v", c.name, rc, err)
		}
		if c.unverifiable && !strings.Contains(err.Error(), "readable objects unwrap with this key") {
			t.Errorf("%s: message %q", c.name, err)
		}
		if errors.Is(err, ErrWrongRecoveryKey) {
			t.Errorf("%s: a plantable file made the key \"wrong\"", c.name)
		}
		data, rc2, err := RecoverVault(c.key, "new", c.s, false)
		if c.unverifiable != (err != nil) || (err != nil && data != nil) {
			t.Errorf("%s: RecoverVault without override: %v", c.name, err)
		}
		// Every case can be written with the override.
		data, rc2, err = RecoverVault(c.key, "new", c.s, true)
		if err != nil || data == nil || rc2.How != c.want {
			t.Errorf("%s: RecoverVault with override: %+v, %v", c.name, rc2, err)
			continue
		}
		cfg, _ := ParseConfig(data)
		if _, err := Unlock(cfg, "new"); err != nil {
			t.Errorf("%s: recovered vault.json does not unlock: %v", c.name, err)
		}
	}

	// Review H4: a key with a typo is refused even on an empty vault.
	flat := strings.ReplaceAll(rk, "-", "")
	typo := flat[:5] + map[bool]string{true: "B", false: "A"}[flat[5] == 'A'] + flat[6:]
	if out, _, err := RecoverVault(typo, "new", RecoverySamples{}, true); !errors.Is(err, ErrRecoveryKeyTypo) || out != nil {
		t.Fatalf("typo on an empty vault: %v", err)
	}
}

// TestRecoverySampleOpensLikeAReader is the regression test for review L1:
// the key check must bind to the expected file_id and run the structural check.
func TestRecoverySampleOpensLikeAReader(t *testing.T) {
	keys := testKeys(t)
	var obj bytes.Buffer
	id, _ := EncryptObject(&obj, keys, testMeta, strings.NewReader("hello"))
	good := sampleOf(t, obj.Bytes(), id)
	if fk, err := good.unwrapFK(keys); err != nil {
		t.Fatal(err)
	} else {
		clear(fk[:])
	}
	var other FileID
	randomBytes(other[:])
	wrongID := good
	wrongID.ID = other
	if _, err := wrongID.unwrapFK(keys); !errors.Is(err, ErrPathMismatch) {
		t.Fatalf("wrong expected id: %v", err)
	}
	truncated := good
	truncated.Size = int64(objectFixedHeader + metaBlock + metaOverhead + 5)
	if _, err := truncated.unwrapFK(keys); !errors.Is(err, ErrMalformed) {
		t.Fatalf("structural check: %v", err)
	}
	short := good
	short.Prefix = short.Prefix[:82]
	if _, err := short.unwrapFK(keys); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short prefix: %v", err)
	}
}

// TestNewObjectEncryptOnce is the regression test for review M7: a second
// Encrypt would reuse the FK and nonces (ct1 XOR ct2 == pt1 XOR pt2).
func TestNewObjectEncryptOnce(t *testing.T) {
	keys := testKeys(t)
	o, err := PrepareObject(testMeta)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Wipe()
	var a, b bytes.Buffer
	if err := o.Encrypt(&a, keys, strings.NewReader("first")); err != nil {
		t.Fatal(err)
	}
	if err := o.Encrypt(&b, keys, strings.NewReader("other")); err == nil || b.Len() != 0 {
		t.Fatalf("second Encrypt: err %v, wrote %d bytes", err, b.Len())
	}
	// The same holds for streaming an opened object twice.
	data := a.Bytes()
	or, err := OpenObject(bytes.NewReader(data), int64(len(data)), o.ID(), keys)
	if err != nil {
		t.Fatal(err)
	}
	defer or.Close()
	if err := or.DecryptTo(io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := or.DecryptTo(io.Discard); err == nil {
		t.Fatal("second DecryptTo succeeded")
	}
}

// TestAlreadyIngestedNeedsIntactMetadata is the reviewer's H1 PoC: ingest,
// restore the inbox file, flip one bit in the object's meta_blob. The
// idempotency check must report a conflict, not "already ingested".
func TestAlreadyIngestedNeedsIntactMetadata(t *testing.T) {
	keys := testKeys(t)
	var inb bytes.Buffer
	id, err := SealInbox(&inb, keys.InboxPub, keys.InboxAuth, testMeta, bytes.NewReader(randomContent(1000)))
	if err != nil {
		t.Fatal(err)
	}
	var obj bytes.Buffer
	if _, err := IngestInbox(bytes.NewReader(inb.Bytes()), int64(inb.Len()), id, keys, &obj); err != nil {
		t.Fatal(err)
	}
	damaged := bytes.Clone(obj.Bytes())
	damaged[objectFixedHeader+NonceSize+3] ^= 1 // inside meta_blob ciphertext
	err = CheckAlreadyIngested(bytes.NewReader(inb.Bytes()), int64(inb.Len()), bytes.NewReader(damaged), int64(len(damaged)), id, keys)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("damaged meta_blob: got %v, want a conflict", err)
	}
}

// TestInboxNeedsKAuth is the reviewer's H2 PoC: someone holding only
// inbox_pub seals a file with a name of their choice. Ingest must reject it.
func TestInboxNeedsKAuth(t *testing.T) {
	keys := testKeys(t)
	plain, _, _ := EncodeMetadata(Metadata{Name: "vault.json", MTime: 1, Rev: 1})
	for name, kAuth := range map[string][]byte{"without K_auth": nil, "wrong K_auth": randomContent(KeySize)} {
		var forged bytes.Buffer
		var eph [KeySize]byte
		randomBytes(eph[:])
		id := newFileID()
		nonce := randomContent(NonceSize)
		if err := sealInbox(&forged, &keys.InboxPub, kAuth, plain, strings.NewReader("hi"), id, &eph, nonce); err != nil {
			t.Fatal(err)
		}
		data := forged.Bytes()
		if _, err := IngestInbox(bytes.NewReader(data), int64(len(data)), id, keys, io.Discard); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: got %v, want an authentication failure", name, err)
		}
		if _, err := VerifyInbox(bytes.NewReader(data), int64(len(data)), id, keys); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: VerifyInbox: %v", name, err)
		}
	}
}

// TestReadersAcceptNonNFC covers review S2: readers no longer reject NFD.
func TestReadersAcceptNonNFC(t *testing.T) {
	m := Metadata{Name: "Ra\u0308ksmo\u0308rga\u030as.txt", Dir: "Ko\u0308k", MTime: 1, Rev: 1}
	padded, err := padMetadata(canonicalMetadataJSON(&m))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeMetadata(padded)
	if err != nil || got != m || got.IsNFC() {
		t.Fatalf("decode NFD: %+v, %v", got, err)
	}
	// Writers still normalize.
	_, norm, err := EncodeMetadata(m)
	if err != nil || !norm.IsNFC() {
		t.Fatalf("writer did not normalize: %v", err)
	}
}
