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
	Magic         = "VALV"
	FormatVersion = 1
	KindObject    = 0x01
	KindInbox     = 0x02
	FileIDSize    = 16

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
	return append([]byte{'V', 'A', 'L', 'V', FormatVersion, KindObject}, id[:]...)
}

// metaAAD is magic | version | file_id, without the kind.
func metaAAD(id FileID) []byte {
	return append([]byte{'V', 'A', 'L', 'V', FormatVersion}, id[:]...)
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

// unwrapFKFromPrefix unwraps FK from the first 82 bytes of an object file.
func unwrapFKFromPrefix(prefix []byte, keys *VaultKeys) ([KeySize]byte, error) {
	if len(prefix) < 82 {
		return [KeySize]byte{}, fmt.Errorf("%w: object header too short", ErrMalformed)
	}
	h := &objectHeader{}
	var err error
	if h.fileID, err = checkPrefix(prefix, KindObject); err != nil {
		return [KeySize]byte{}, err
	}
	copy(h.wrapNonce[:], prefix[22:34])
	copy(h.wrappedFK[:], prefix[34:82])
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
// file of length size), runs the structural check, then unwraps FK and
// decrypts the metadata. r is left at the first chunk.
func openObject(r io.Reader, size int64, keys *VaultKeys) (*openedObject, error) {
	hdr, err := readObjectHeader(r)
	if err != nil {
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
	return o, nil
}

// ReadObjectInfo authenticates an object's header and returns its file_id
// and metadata without reading the content. size is the full file length.
func ReadObjectInfo(r io.Reader, size int64, keys *VaultKeys) (FileID, Metadata, error) {
	o, err := openObject(r, size, keys)
	if err != nil {
		return FileID{}, Metadata{}, err
	}
	o.wipe()
	return o.hdr.fileID, o.meta, nil
}

// DecryptObject decrypts an object file of length size from r and streams the
// plaintext to w. The output is valid only if the returned error is nil;
// otherwise the caller must discard everything written to w.
func DecryptObject(r io.Reader, size int64, keys *VaultKeys, w io.Writer) (FileID, Metadata, error) {
	o, err := openObject(r, size, keys)
	if err != nil {
		return FileID{}, Metadata{}, err
	}
	defer o.wipe()
	err = readChunks(r, o.ctTotal, &o.keys.content, o.hdr.fileID, func(_, plain []byte) error {
		_, err := w.Write(plain)
		return err
	})
	if err != nil {
		return FileID{}, Metadata{}, err
	}
	return o.hdr.fileID, o.meta, nil
}

// EncryptObject writes a new object file for content to w, with a new random
// file_id and FK. meta.Name and meta.Dir are NFC-normalized.
func EncryptObject(w io.Writer, keys *VaultKeys, meta Metadata, content io.Reader) (FileID, error) {
	plain, _, err := EncodeMetadata(meta)
	if err != nil {
		return FileID{}, err
	}
	id := newFileID()
	var fk [KeySize]byte
	randomBytes(fk[:])
	defer clear(fk[:])
	var wrapNonce, metaNonce [NonceSize]byte
	randomBytes(wrapNonce[:])
	randomBytes(metaNonce[:])
	return id, encryptObject(w, keys, plain, content, id, &fk, wrapNonce[:], metaNonce[:])
}

// encryptObject writes an object with the given id, FK and nonces. Release
// code reaches it only through EncryptObject, with random values.
func encryptObject(w io.Writer, keys *VaultKeys, metaPlain []byte, content io.Reader, id FileID, fk *[KeySize]byte, wrapNonce, metaNonce []byte) error {
	fkeys := deriveFileKeys(fk)
	defer fkeys.wipe()
	h := &objectHeader{fileID: id, metaBlob: encryptMeta(metaPlain, &fkeys.meta, id, metaNonce)}
	copy(h.wrapNonce[:], wrapNonce)
	copy(h.wrappedFK[:], seal(&keys.Wrap, wrapNonce, fk[:], wrapAAD(id)))
	if _, err := w.Write(h.marshal()); err != nil {
		return err
	}
	return encryptChunks(w, &fkeys.content, id, content)
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
