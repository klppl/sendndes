package core

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Chunk sizes (SPEC 5.3).
const (
	ChunkSize       = 65536
	StoredChunkSize = ChunkSize + TagSize
)

// chunkCount runs the structural check on ct_total and returns the number of
// chunks (SPEC 5.3). It must run before any decryption.
func chunkCount(ctTotal int64) (int64, error) {
	r := ctTotal % StoredChunkSize
	switch {
	case ctTotal < TagSize:
		return 0, fmt.Errorf("%w: content shorter than one tag", ErrMalformed)
	case r >= 1 && r < TagSize:
		return 0, fmt.Errorf("%w: final chunk shorter than a tag", ErrMalformed)
	case r == TagSize && ctTotal != TagSize:
		return 0, fmt.Errorf("%w: empty final chunk after full chunks", ErrMalformed)
	}
	return (ctTotal + StoredChunkSize - 1) / StoredChunkSize, nil
}

// PlaintextSize returns the plaintext length for a given ct_total, or an
// error if ct_total fails the structural check.
func PlaintextSize(ctTotal int64) (int64, error) {
	n, err := chunkCount(ctTotal)
	if err != nil {
		return 0, err
	}
	return ctTotal - TagSize*n, nil
}

func chunkNonce(index uint64, final bool) [NonceSize]byte {
	var n [NonceSize]byte
	binary.BigEndian.PutUint64(n[:8], index)
	if final {
		n[11] = 1
	}
	return n
}

// encryptChunks stream-encrypts r with one chunk of lookahead.
func encryptChunks(w io.Writer, key *[KeySize]byte, id FileID, r io.Reader) error {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(r, ChunkSize)
	buf := make([]byte, ChunkSize)
	out := make([]byte, 0, StoredChunkSize)
	defer clear(buf)
	for index := uint64(0); ; index++ {
		n, err := io.ReadFull(br, buf)
		final := false
		switch {
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			final = true
		case err != nil:
			return err
		default:
			if _, perr := br.Peek(1); perr == io.EOF {
				final = true
			} else if perr != nil {
				return perr
			}
		}
		nonce := chunkNonce(index, final)
		out = aead.Seal(out[:0], nonce[:], buf[:n], id[:])
		if _, err := w.Write(out); err != nil {
			return err
		}
		if final {
			return nil
		}
	}
}

// readChunks reads ct_total bytes of chunks from r, authenticates each one
// and passes its stored bytes and plaintext to fn. The structural check runs
// first.
func readChunks(r io.Reader, ctTotal int64, key *[KeySize]byte, id FileID, fn func(stored, plain []byte) error) error {
	n, err := chunkCount(ctTotal)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return err
	}
	buf := make([]byte, StoredChunkSize)
	plain := make([]byte, 0, ChunkSize)
	defer clear(plain[:cap(plain)])
	remaining := ctTotal
	for i := int64(0); i < n; i++ {
		chunk := buf[:min(StoredChunkSize, remaining)]
		if _, err := io.ReadFull(r, chunk); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: content ends early", ErrMalformed)
			}
			return err
		}
		nonce := chunkNonce(uint64(i), i == n-1)
		plain, err = aead.Open(plain[:0], nonce[:], chunk, id[:])
		if err != nil {
			return fmt.Errorf("%w: chunk %d", ErrAuth, i)
		}
		if err := fn(chunk, plain); err != nil {
			return err
		}
		remaining -= int64(len(chunk))
	}
	return nil
}
