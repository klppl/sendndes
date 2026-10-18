package core

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

type inboxHeader struct {
	fileID   FileID
	ephPub   [KeySize]byte
	metaBlob []byte
}

func (h *inboxHeader) size() int64 { return inboxFixedHeader + int64(len(h.metaBlob)) }

func (h *inboxHeader) marshal() []byte {
	b := make([]byte, 0, h.size())
	b = append(b, 'V', 'A', 'L', 'V', FormatVersion, KindInbox)
	b = append(b, h.fileID[:]...)
	b = append(b, h.ephPub[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(h.metaBlob)))
	return append(b, h.metaBlob...)
}

func readInboxHeader(r io.Reader) (*inboxHeader, error) {
	var fixed [inboxFixedHeader]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, shortRead(err)
	}
	h := &inboxHeader{}
	var err error
	if h.fileID, err = checkPrefix(fixed[:], KindInbox); err != nil {
		return nil, err
	}
	copy(h.ephPub[:], fixed[22:54])
	if h.metaBlob, err = readMetaBlob(r, fixed[54:58]); err != nil {
		return nil, err
	}
	return h, nil
}

// SealInbox writes an inbox file for content to w, sealed to inboxPub and
// authenticated with kAuth (SPEC 6.2). It is what the inbox server runs; it
// needs no vault keys. meta.Rev is set to 1.
func SealInbox(w io.Writer, inboxPub, kAuth [KeySize]byte, meta Metadata, content io.Reader) (FileID, error) {
	meta.Rev = 1
	plain, _, err := EncodeMetadata(meta)
	if err != nil {
		return FileID{}, err
	}
	id := newFileID()
	var ephPriv [KeySize]byte
	randomBytes(ephPriv[:])
	defer clear(ephPriv[:])
	var metaNonce [NonceSize]byte
	randomBytes(metaNonce[:])
	return id, sealInbox(w, &inboxPub, kAuth[:], plain, content, id, &ephPriv, metaNonce[:])
}

// sealInbox writes an inbox file with the given id, ephemeral key and nonce.
// Release code reaches it only through SealInbox, with random values.
func sealInbox(w io.Writer, inboxPub *[KeySize]byte, kAuth, metaPlain []byte, content io.Reader, id FileID, ephPriv *[KeySize]byte, metaNonce []byte) error {
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	dh, err := x25519(ephPriv[:], inboxPub[:])
	if err != nil {
		return err
	}
	defer clear(dh)
	h := &inboxHeader{fileID: id}
	copy(h.ephPub[:], ephPub)
	fk := inboxFK(dh, kAuth, &h.ephPub, inboxPub)
	defer clear(fk[:])
	fkeys := deriveFileKeys(&fk)
	defer fkeys.wipe()
	h.metaBlob = encryptMeta(metaPlain, &fkeys.meta, id, metaNonce)
	if _, err := w.Write(h.marshal()); err != nil {
		return err
	}
	return encryptChunks(w, &fkeys.content, id, content)
}

// openedInbox is an inbox file whose header passed the structural check and
// whose metadata authenticated. Call wipe when done.
type openedInbox struct {
	hdr     *inboxHeader
	fk      [KeySize]byte
	keys    fileKeys
	meta    Metadata
	ctTotal int64
}

func (o *openedInbox) wipe() {
	clear(o.fk[:])
	o.keys.wipe()
}

// openInbox does ingest steps 1 and 2 (SPEC 6.3). r is left at the first chunk.
func openInbox(r io.Reader, size int64, expected FileID, keys *VaultKeys) (*openedInbox, error) {
	hdr, err := readInboxHeader(r)
	if err != nil {
		return nil, err
	}
	if err := checkExpected(hdr.fileID, expected); err != nil {
		return nil, err
	}
	o := &openedInbox{hdr: hdr, ctTotal: size - hdr.size()}
	if _, err := chunkCount(o.ctTotal); err != nil {
		return nil, err
	}
	dh, err := x25519(keys.InboxPriv[:], hdr.ephPub[:])
	if err != nil {
		return nil, err
	}
	o.fk = inboxFK(dh, keys.InboxAuth[:], &hdr.ephPub, &keys.InboxPub)
	clear(dh)
	o.keys = deriveFileKeys(&o.fk)
	if o.meta, err = decryptMeta(hdr.metaBlob, &o.keys.meta, hdr.fileID); err != nil {
		o.wipe()
		return nil, err
	}
	return o, nil
}

// IngestInbox verifies an inbox file of length size and writes the equivalent
// object file to w (SPEC 6.3). expected is the file_id from its name. Each
// chunk is authenticated before it is written. On error the caller must
// discard what was written to w and keep the inbox file.
func IngestInbox(r io.Reader, size int64, expected FileID, keys *VaultKeys, w io.Writer) (Metadata, error) {
	var wrapNonce [NonceSize]byte
	randomBytes(wrapNonce[:])
	_, meta, err := ingestInbox(r, size, expected, keys, w, wrapNonce[:])
	return meta, err
}

// VerifyInbox authenticates every byte of an inbox file without writing anything.
func VerifyInbox(r io.Reader, size int64, expected FileID, keys *VaultKeys) (Metadata, error) {
	in, err := openInbox(r, size, expected, keys)
	if err != nil {
		return Metadata{}, err
	}
	defer in.wipe()
	err = readChunks(r, in.ctTotal, &in.keys.content, in.hdr.fileID, func(_, _ []byte) error { return nil })
	return in.meta, err
}

func ingestInbox(r io.Reader, size int64, expected FileID, keys *VaultKeys, w io.Writer, wrapNonce []byte) (FileID, Metadata, error) {
	in, err := openInbox(r, size, expected, keys)
	if err != nil {
		return FileID{}, Metadata{}, err
	}
	defer in.wipe()
	id := in.hdr.fileID
	h := &objectHeader{fileID: id, metaBlob: in.hdr.metaBlob}
	copy(h.wrapNonce[:], wrapNonce)
	copy(h.wrappedFK[:], seal(&keys.Wrap, wrapNonce, in.fk[:], wrapAAD(id)))
	if _, err := w.Write(h.marshal()); err != nil {
		return FileID{}, Metadata{}, err
	}
	err = readChunks(r, in.ctTotal, &in.keys.content, id, func(stored, _ []byte) error {
		_, err := w.Write(stored)
		return err
	})
	if err != nil {
		return FileID{}, Metadata{}, err
	}
	return id, in.meta, nil
}

// CheckAlreadyIngested decides whether an existing object with the inbox
// file's id is the result of ingesting it (SPEC 6.3): the object's FK must
// equal the inbox FK, its meta_blob must decrypt under that FK, and its chunks
// must be byte-identical; meta_blob may differ from the inbox file's. It returns nil if so, so the inbox file may be deleted, and an
// error wrapping ErrConflict if not. Any other error means the inbox file
// itself is bad. Nothing is deleted here.
func CheckAlreadyIngested(inbox io.Reader, inboxSize int64, object io.Reader, objectSize int64, expected FileID, keys *VaultKeys) error {
	in, err := openInbox(inbox, inboxSize, expected, keys)
	if err != nil {
		return err
	}
	defer in.wipe()
	conflict := func(why string) error { return fmt.Errorf("%w: %s", ErrConflict, why) }
	oh, err := readObjectHeader(object)
	if err != nil {
		return conflict("existing object unreadable: " + err.Error())
	}
	if oh.fileID != in.hdr.fileID {
		return conflict("file_id differs")
	}
	if objectSize-oh.size() != in.ctTotal {
		return conflict("content length differs")
	}
	objFK, err := oh.unwrapFK(keys)
	if err != nil {
		return conflict("existing object's FK does not unwrap")
	}
	same := subtle.ConstantTimeCompare(objFK[:], in.fk[:]) == 1
	clear(objFK[:])
	if !same {
		return conflict("FK differs")
	}
	if _, err := decryptMeta(oh.metaBlob, &in.keys.meta, oh.fileID); err != nil {
		return conflict("existing object's metadata does not decrypt: " + err.Error())
	}
	buf := make([]byte, StoredChunkSize)
	errDiffer := errors.New("chunks differ")
	err = readChunks(inbox, in.ctTotal, &in.keys.content, in.hdr.fileID, func(stored, _ []byte) error {
		ok, err := sameBytes(object, stored, buf)
		if err != nil {
			return err
		}
		if !ok {
			return errDiffer
		}
		return nil
	})
	if errors.Is(err, errDiffer) {
		return conflict("chunks differ")
	}
	return err
}
