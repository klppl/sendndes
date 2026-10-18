package core

import (
	"bytes"
	"errors"
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
		gotID, meta, err := DecryptObject(bytes.NewReader(data), int64(len(data)), keys, &out)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if gotID != id || meta != testMeta || !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("%d: round trip differs", n)
		}
		infoID, infoMeta, err := ReadObjectInfo(bytes.NewReader(data), int64(len(data)), keys)
		if err != nil || infoID != id || infoMeta != testMeta {
			t.Fatalf("%d: ReadObjectInfo: %v", n, err)
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
		id, err := SealInbox(&inb, keys.InboxPub, meta, bytes.NewReader(plain))
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		var obj bytes.Buffer
		gotID, gotMeta, err := IngestInbox(bytes.NewReader(inb.Bytes()), int64(inb.Len()), keys, &obj)
		if err != nil || gotID != id || gotMeta.Rev != 1 {
			t.Fatalf("%d: ingest: %v", n, err)
		}
		var out bytes.Buffer
		if _, _, err := DecryptObject(bytes.NewReader(obj.Bytes()), int64(obj.Len()), keys, &out); err != nil || !bytes.Equal(out.Bytes(), plain) {
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
	data, keys, rk, err := CreateVault([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(c, []byte("nope")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	k2, err := UnlockWithRecoveryKey(c, strings.ToLower(strings.ReplaceAll(rk, "-", " ")), nil)
	if err != nil || k2.VK != keys.VK {
		t.Fatalf("recovery key: %v", err)
	}

	newData, err := ChangePassphrase(keys, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := ParseConfig(newData)
	if c2.Salt == c.Salt || [NonceSize]byte(c2.WrappedVK[:NonceSize]) == [NonceSize]byte(c.WrappedVK[:NonceSize]) {
		t.Fatal("passphrase change reused salt or nonce")
	}
	if _, err := Unlock(c2, []byte("first")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatal("old passphrase still works")
	}
	k3, err := Unlock(c2, []byte("second"))
	if err != nil || k3.VK != keys.VK {
		t.Fatalf("new passphrase: %v", err)
	}
}

func TestRecoveryKeyFormat(t *testing.T) {
	var vk [KeySize]byte
	randomBytes(vk[:])
	rk := EncodeRecoveryKey(vk)
	if len(rk) != 52+12 || strings.Count(rk, "-") != 12 || strings.ToUpper(rk) != rk {
		t.Fatalf("format: %s", rk)
	}
	for _, in := range []string{rk, strings.ToLower(rk), strings.ReplaceAll(rk, "-", ""), strings.ReplaceAll(rk, "-", " ")} {
		if got, err := DecodeRecoveryKey(in); err != nil || got != vk {
			t.Fatalf("decode %q: %v", in, err)
		}
	}
	flat := strings.ReplaceAll(rk, "-", "")
	// The last character carries 1 data bit and 4 unused bits, so only A or Q
	// is canonical there. A+1 or Q+1 sets an unused bit.
	nonCanonical := flat[:51] + string(flat[51]+1)
	for _, in := range []string{flat[:51], flat + "A", flat[:51] + "1", nonCanonical} {
		if _, err := DecodeRecoveryKey(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestRecoveryUnlockDiagnosis(t *testing.T) {
	v := loadVectors(t)
	data := readVectorFile(t, v.Vault.File)
	c, _ := ParseConfig(data)
	sample := readVectorFile(t, v.Objects[0].File)[:82]

	// Right key, vault.json with another inbox_pub.
	altered := *c
	altered.InboxPub[0] ^= 1
	if _, err := UnlockWithRecoveryKey(&altered, v.Vault.RecoveryKey, sample); !errors.Is(err, ErrVaultAltered) {
		t.Fatalf("altered vault.json: %v", err)
	}
	if _, err := UnlockWithRecoveryKey(&altered, v.Vault.RecoveryKey, nil); !errors.Is(err, ErrWrongRecoveryKey) {
		t.Fatalf("altered vault.json, no objects: %v", err)
	}
	var other [KeySize]byte
	randomBytes(other[:])
	if _, err := UnlockWithRecoveryKey(c, EncodeRecoveryKey(other), sample); !errors.Is(err, ErrWrongRecoveryKey) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := UnlockWithRecoveryKey(c, v.Vault.RecoveryKey, sample); err != nil {
		t.Fatalf("right key: %v", err)
	}
}

func TestCheckAlreadyIngested(t *testing.T) {
	keys := testKeys(t)
	plain := randomContent(ChunkSize + 100)
	var inb bytes.Buffer
	if _, err := SealInbox(&inb, keys.InboxPub, testMeta, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	inbox := inb.Bytes()
	ingest := func() []byte {
		var obj bytes.Buffer
		if _, _, err := IngestInbox(bytes.NewReader(inbox), int64(len(inbox)), keys, &obj); err != nil {
			t.Fatal(err)
		}
		return obj.Bytes()
	}
	check := func(obj []byte) error {
		return CheckAlreadyIngested(bytes.NewReader(inbox), int64(len(inbox)), bytes.NewReader(obj), int64(len(obj)), keys)
	}

	obj := ingest()
	if err := check(obj); err != nil {
		t.Fatalf("own ingest result: %v", err)
	}

	// Renamed after ingest: new meta_blob under the same FK. Still ingested.
	o, err := openObject(bytes.NewReader(obj), int64(len(obj)), keys)
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
	if _, err := SealInbox(&inb, keys.InboxPub, testMeta, bytes.NewReader(randomContent(2*ChunkSize+10))); err != nil {
		t.Fatal(err)
	}
	data := inb.Bytes()
	headerLen := inboxFixedHeader + metaBlock + metaOverhead
	data[headerLen+StoredChunkSize+5] ^= 1 // corrupt chunk 1
	var obj bytes.Buffer
	_, _, err := IngestInbox(bytes.NewReader(data), int64(len(data)), keys, &obj)
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
