package core

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Header constants (SPEC 5.1, 6.1).
const (
	Magic         = "NDES"
	FormatVersion = 2 // object and inbox files (SPEC 5.1, 6.1)
	// VaultConfigVersion is the "v" of vault.json. It did not change with the
	// padded object format: nothing in vault.json depends on it.
	VaultConfigVersion = 1
	KindObject         = 0x01
	KindInbox          = 0x02
	FileIDSize         = 16

	objectFixedHeader = 86
	inboxFixedHeader  = 58
	wrappedFKSize     = KeySize + TagSize
)

// FileID is a random 16-byte file identifier.
type FileID [FileIDSize]byte

func (id FileID) String() string { return hex.EncodeToString(id[:]) }

func newFileID() FileID {
	var id FileID
	randomBytes(id[:])
	return id
}

// wrapAAD is bytes 0..22 of an object header.
func wrapAAD(id FileID) []byte {
	out := append(append(make([]byte, 0, 22), Magic...), FormatVersion, KindObject)
	return append(out, id[:]...)
}

// metaAAD is magic | version | file_id, without the kind.
func metaAAD(id FileID) []byte {
	out := append(append(make([]byte, 0, 21), Magic...), FormatVersion)
	return append(out, id[:]...)
}

// checkPrefix checks magic, version and kind, and returns the file_id.
func checkPrefix(b []byte, kind byte) (FileID, error) {
	var id FileID
	if string(b[:4]) != Magic {
		return id, fmt.Errorf("%w: bad magic", ErrMalformed)
	}
	if b[4] != FormatVersion {
		return id, fmt.Errorf("%w: version %d", ErrUnsupported, b[4])
	}
	if b[5] != kind {
		return id, fmt.Errorf("%w: kind %d, want %d", ErrMalformed, b[5], kind)
	}
	copy(id[:], b[6:22])
	return id, nil
}

// readMetaBlob reads a meta_len-prefixed meta_blob after checking meta_len.
func readMetaBlob(r io.Reader, lenField []byte) ([]byte, error) {
	n := binary.BigEndian.Uint32(lenField)
	if !validMetaLen(n) {
		return nil, fmt.Errorf("%w: meta_len %d", ErrMalformed, n)
	}
	blob := make([]byte, n)
	if _, err := io.ReadFull(r, blob); err != nil {
		return nil, shortRead(err)
	}
	return blob, nil
}

func shortRead(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: file ends early", ErrMalformed)
	}
	return err
}

type objectHeader struct {
	fileID    FileID
	wrapNonce [NonceSize]byte
	wrappedFK [wrappedFKSize]byte
	metaBlob  []byte
}

func (h *objectHeader) size() int64 { return objectFixedHeader + int64(len(h.metaBlob)) }

func (h *objectHeader) marshal() []byte {
	b := make([]byte, 0, h.size())
	b = append(b, wrapAAD(h.fileID)...)
	b = append(b, h.wrapNonce[:]...)
	b = append(b, h.wrappedFK[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(h.metaBlob)))
	return append(b, h.metaBlob...)
}

func readObjectHeader(r io.Reader) (*objectHeader, error) {
	var fixed [objectFixedHeader]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, shortRead(err)
	}
	h := &objectHeader{}
	var err error
	if h.fileID, err = checkPrefix(fixed[:], KindObject); err != nil {
		return nil, err
	}
	copy(h.wrapNonce[:], fixed[22:34])
	copy(h.wrappedFK[:], fixed[34:82])
	if h.metaBlob, err = readMetaBlob(r, fixed[82:86]); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *objectHeader) unwrapFK(keys *VaultKeys) ([KeySize]byte, error) {
	var fk [KeySize]byte
	b, err := open(&keys.Wrap, h.wrapNonce[:], h.wrappedFK[:], wrapAAD(h.fileID))
	if err != nil {
		return fk, fmt.Errorf("%w: wrapped_fk", ErrAuth)
	}
	copy(fk[:], b)
	clear(b)
	return fk, nil
}

// unwrapFK opens a sample like any reader: path check, meta_len and
// structural check first, then the FK unwrap (SPEC 4.5).
func (s *ObjectSample) unwrapFK(keys *VaultKeys) ([KeySize]byte, error) {
	if len(s.Prefix) < objectFixedHeader {
		return [KeySize]byte{}, fmt.Errorf("%w: object header too short", ErrMalformed)
	}
	h := &objectHeader{}
	var err error
	if h.fileID, err = checkPrefix(s.Prefix, KindObject); err != nil {
		return [KeySize]byte{}, err
	}
	if err := checkExpected(h.fileID, s.ID); err != nil {
		return [KeySize]byte{}, err
	}
	metaLen := binary.BigEndian.Uint32(s.Prefix[82:86])
	if !validMetaLen(metaLen) {
		return [KeySize]byte{}, fmt.Errorf("%w: meta_len %d", ErrMalformed, metaLen)
	}
	if _, err := chunkCount(s.Size - objectFixedHeader - int64(metaLen)); err != nil {
		return [KeySize]byte{}, err
	}
	copy(h.wrapNonce[:], s.Prefix[22:34])
	copy(h.wrappedFK[:], s.Prefix[34:82])
	return h.unwrapFK(keys)
}

// decryptMeta decrypts and checks a meta_blob.
func decryptMeta(blob []byte, key *[KeySize]byte, id FileID) (Metadata, error) {
	plain, err := open(key, blob[:NonceSize], blob[NonceSize:], metaAAD(id))
	if err != nil {
		return Metadata{}, fmt.Errorf("%w: meta_blob", ErrAuth)
	}
	defer clear(plain)
	return DecodeMetadata(plain)
}

func encryptMeta(plain []byte, key *[KeySize]byte, id FileID, nonce []byte) []byte {
	return append(append([]byte{}, nonce...), seal(key, nonce, plain, metaAAD(id))...)
}

// openedObject is an object whose header passed the structural check and
// authenticated. Call wipe when done.
type openedObject struct {
	hdr     *objectHeader
	fk      [KeySize]byte
	keys    fileKeys
	meta    Metadata
	ctTotal int64
}

func (o *openedObject) wipe() {
	clear(o.fk[:])
	o.keys.wipe()
}

// openObject reads an object header from r (positioned at the start of a
// file of length size), checks the file_id against the one expected from the
// path, runs the structural check, then unwraps FK and decrypts the metadata.
// r is left at the first chunk.
func openObject(r io.Reader, size int64, expected FileID, keys *VaultKeys) (*openedObject, error) {
	hdr, err := readObjectHeader(r)
	if err != nil {
		return nil, err
	}
	if err := checkExpected(hdr.fileID, expected); err != nil {
		return nil, err
	}
	o := &openedObject{hdr: hdr, ctTotal: size - hdr.size()}
	if _, err := chunkCount(o.ctTotal); err != nil {
		return nil, err
	}
	if o.fk, err = hdr.unwrapFK(keys); err != nil {
		return nil, err
	}
	o.keys = deriveFileKeys(&o.fk)
	if o.meta, err = decryptMeta(hdr.metaBlob, &o.keys.meta, hdr.fileID); err != nil {
		o.wipe()
		return nil, err
	}
	if err := checkSizeMatches(o.meta.Size, o.ctTotal); err != nil {
		o.wipe()
		return nil, err
	}
	return o, nil
}

// checkSizeMatches requires that the size in the metadata is the one whose
// padded length is what the file actually stores (SPEC 5.3).
func checkSizeMatches(size, ctTotal int64) error {
	stored, err := StoredPlaintextSize(ctTotal)
	if err != nil {
		return err
	}
	if PaddedSize(size) != stored {
		return fmt.Errorf("%w: metadata size %d does not match the stored length", ErrMalformed, size)
	}
	return nil
}

// ObjectInfo is what an object's header tells about it.
type ObjectInfo struct {
	ID            FileID
	Meta          Metadata
	PlaintextSize int64
}

// ObjectReader is an object whose header has been checked and authenticated,
// ready to stream its content. It reads from the reader it was opened on.
type ObjectReader struct {
	o    *openedObject
	r    io.Reader
	used bool
}

// OpenObject reads and authenticates an object's header from r, positioned at
// the start of a file of length size; expected is the file_id from its path
// (SPEC 4.1). Call Close when done.
func OpenObject(r io.Reader, size int64, expected FileID, keys *VaultKeys) (*ObjectReader, error) {
	o, err := openObject(r, size, expected, keys)
	if err != nil {
		return nil, err
	}
	return &ObjectReader{o: o, r: r}, nil
}

// Info returns the object's id, metadata and plaintext size.
func (or *ObjectReader) Info() ObjectInfo {
	return ObjectInfo{ID: or.o.hdr.fileID, Meta: or.o.meta, PlaintextSize: or.o.meta.Size}
}

// DecryptTo streams the plaintext to w. The output is valid only if the
// returned error is nil; otherwise the caller must discard everything written
// to w. It can be called once.
func (or *ObjectReader) DecryptTo(w io.Writer) error {
	if or.used {
		return errors.New("ndes: ObjectReader.DecryptTo called twice")
	}
	or.used = true
	return readPadded(or.r, or.o.ctTotal, or.o.meta.Size, &or.o.keys.content, or.o.hdr.fileID, w)
}

// Close wipes the object's keys.
func (or *ObjectReader) Close() { or.o.wipe() }

// ReadObjectInfo authenticates an object's header and returns its metadata
// and plaintext size without reading the content. size is the full file
// length and expected the file_id from its path (SPEC 4.1).
func ReadObjectInfo(r io.Reader, size int64, expected FileID, keys *VaultKeys) (ObjectInfo, error) {
	or, err := OpenObject(r, size, expected, keys)
	if err != nil {
		return ObjectInfo{}, err
	}
	defer or.Close()
	return or.Info(), nil
}

// DecryptObject decrypts an object file of length size from r and streams the
// plaintext to w. expected is the file_id from its path. The output is valid
// only if the returned error is nil; otherwise the caller must discard
// everything written to w.
func DecryptObject(r io.Reader, size int64, expected FileID, keys *VaultKeys, w io.Writer) (Metadata, error) {
	or, err := OpenObject(r, size, expected, keys)
	if err != nil {
		return Metadata{}, err
	}
	defer or.Close()
	if err := or.DecryptTo(w); err != nil {
		return Metadata{}, err
	}
	return or.o.meta, nil
}

// VerifyObject authenticates an object's metadata and every chunk without
// keeping any plaintext.
func VerifyObject(r io.Reader, size int64, expected FileID, keys *VaultKeys) (Metadata, error) {
	return DecryptObject(r, size, expected, keys, io.Discard)
}

// NewObject is an object about to be written: its random file_id, FK and
// nonces are chosen, so the caller can pick the path before writing.
type NewObject struct {
	id        FileID
	fk        [KeySize]byte
	wrapNonce [NonceSize]byte
	metaNonce [NonceSize]byte
	metaPlain []byte
	meta      Metadata
	used      bool
}

// PrepareObject checks and normalizes meta and draws a new file_id, FK and
// nonces. Call Wipe when done.
func PrepareObject(meta Metadata) (*NewObject, error) {
	plain, meta, err := EncodeMetadata(meta)
	if err != nil {
		return nil, err
	}
	o := &NewObject{id: newFileID(), metaPlain: plain, meta: meta}
	randomBytes(o.fk[:])
	randomBytes(o.wrapNonce[:])
	randomBytes(o.metaNonce[:])
	return o, nil
}

// ID is the new object's file_id.
func (o *NewObject) ID() FileID { return o.id }

// Meta is the normalized metadata that will be written.
func (o *NewObject) Meta() Metadata { return o.meta }

// Encrypt writes the object file for content to w. content must yield exactly
// the size declared in the metadata, else it fails with ErrContentSize. It can be called only
// once: a second call would reuse the FK and nonces.
func (o *NewObject) Encrypt(w io.Writer, keys *VaultKeys, content io.Reader) error {
	if o.used {
		return errors.New("ndes: NewObject.Encrypt called twice")
	}
	o.used = true
	return encryptObject(w, keys, o.metaPlain, content, o.meta.Size, o.id, &o.fk, o.wrapNonce[:], o.metaNonce[:])
}

// Wipe zeroes the FK.
func (o *NewObject) Wipe() { clear(o.fk[:]) }

// EncryptObject writes a new object file for content to w, with a new random
// file_id and FK. meta.Name and meta.Dir are NFC-normalized.
func EncryptObject(w io.Writer, keys *VaultKeys, meta Metadata, content io.Reader) (FileID, error) {
	o, err := PrepareObject(meta)
	if err != nil {
		return FileID{}, err
	}
	defer o.Wipe()
	return o.id, o.Encrypt(w, keys, content)
}

// encryptObject writes an object with the given id, FK and nonces. Release
// code reaches it only through EncryptObject, with random values.
func encryptObject(w io.Writer, keys *VaultKeys, metaPlain []byte, content io.Reader, size int64, id FileID, fk *[KeySize]byte, wrapNonce, metaNonce []byte) error {
	fkeys := deriveFileKeys(fk)
	defer fkeys.wipe()
	h := &objectHeader{fileID: id, metaBlob: encryptMeta(metaPlain, &fkeys.meta, id, metaNonce)}
	copy(h.wrapNonce[:], wrapNonce)
	copy(h.wrappedFK[:], seal(&keys.Wrap, wrapNonce, fk[:], wrapAAD(id)))
	if _, err := w.Write(h.marshal()); err != nil {
		return err
	}
	return encryptChunks(w, &fkeys.content, id, content, size)
}

// sameBytes reports whether r yields exactly want next.
func sameBytes(r io.Reader, want []byte, buf []byte) (bool, error) {
	got := buf[:len(want)]
	if _, err := io.ReadFull(r, got); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, err
	}
	return bytes.Equal(got, want), nil
}
