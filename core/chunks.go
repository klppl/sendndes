package core

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"

	"golang.org/x/crypto/chacha20poly1305"
)

// Chunk sizes (SPEC 5.3).
const (
	ChunkSize       = 65536
	StoredChunkSize = ChunkSize + TagSize
)

// Content padding (SPEC 5.3). The stored plaintext length of every object is
// PaddedSize(size): Padme (Reble and Pretsch, "Padmé") of max(size,
// MinPadded). MaxPlaintextSize keeps the arithmetic far from int64 overflow.
const (
	MinPadded        = 4096
	MaxPlaintextSize = int64(1) << 60
)

// padme rounds l (at least 2) up to a length with at most 12% overhead that
// reveals only O(log log l) bits of l.
func padme(l int64) int64 {
	e := bits.Len64(uint64(l)) - 1 // floor(log2 l)
	s := bits.Len64(uint64(e))     // floor(log2 e) + 1
	mask := int64(1)<<(e-s) - 1
	return (l + mask) &^ mask
}

// PaddedSize returns the stored plaintext length for a file of size bytes.
// It is only meaningful for 0 <= size <= MaxPlaintextSize.
func PaddedSize(size int64) int64 {
	return padme(max(size, MinPadded))
}

// chunkCount runs the structural check on ct_total and returns the number of
// chunks (SPEC 5.3). It must run before any decryption. The stored plaintext
// length it implies must be a valid padded size (at least MinPadded and a
// fixed point of Padme), so unpadded content is rejected here.
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
	n := (ctTotal + StoredChunkSize - 1) / StoredChunkSize
	if p := ctTotal - TagSize*n; p < MinPadded || p > 2*MaxPlaintextSize || padme(p) != p {
		return 0, fmt.Errorf("%w: stored length %d is not a padded size", ErrMalformed, p)
	}
	return n, nil
}

// StoredPlaintextSize runs the structural check on ct_total and returns the
// stored plaintext length (the real size plus padding).
func StoredPlaintextSize(ctTotal int64) (int64, error) {
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

// ErrContentSize: the content did not have the length declared in the
// metadata (shorter or longer), so nothing consistent can be written.
var ErrContentSize = errors.New("ndes: content length differs from the declared size")

// paddedReader yields exactly size bytes from r, then zeros up to padded. It
// fails with ErrContentSize if r is shorter or longer than size.
type paddedReader struct {
	r      io.Reader
	size   int64 // content bytes still to read
	zeros  int64 // padding bytes still to emit
	probed bool
}

func newPaddedReader(r io.Reader, size int64) *paddedReader {
	return &paddedReader{r: r, size: size, zeros: PaddedSize(size) - size}
}

func (p *paddedReader) Read(b []byte) (int, error) {
	if p.size > 0 {
		n, err := p.r.Read(b[:min(int64(len(b)), p.size)])
		p.size -= int64(n)
		if err == io.EOF {
			if p.size > 0 {
				return n, ErrContentSize
			}
			err = nil
		}
		return n, err
	}
	if !p.probed {
		p.probed = true
		var one [1]byte
		if n, _ := io.ReadFull(p.r, one[:]); n > 0 {
			return 0, ErrContentSize
		}
	}
	if p.zeros == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(b)), p.zeros)
	clear(b[:n])
	p.zeros -= n
	return int(n), nil
}

// encryptChunks stream-encrypts size bytes of r, padded to PaddedSize(size),
// with one chunk of lookahead.
func encryptChunks(w io.Writer, key *[KeySize]byte, id FileID, content io.Reader, size int64) error {
	r := newPaddedReader(content, size)
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

// padSplitter separates a padded plaintext stream into the real content (the
// first size bytes) and the padding, which must be all zero.
type padSplitter struct{ left int64 }

// split returns the content part of plain and checks that the rest is zero.
func (p *padSplitter) split(plain []byte) ([]byte, error) {
	k := min(p.left, int64(len(plain)))
	p.left -= k
	for _, c := range plain[k:] {
		if c != 0 {
			return nil, fmt.Errorf("%w: padding is not zero", ErrMalformed)
		}
	}
	return plain[:k], nil
}

// readPadded authenticates every chunk like readChunks and writes the first
// size plaintext bytes to w (w may be nil). The rest must be zero padding.
func readPadded(r io.Reader, ctTotal, size int64, key *[KeySize]byte, id FileID, w io.Writer) error {
	ps := padSplitter{left: size}
	return readChunks(r, ctTotal, key, id, func(_, plain []byte) error {
		data, err := ps.split(plain)
		if err != nil || w == nil {
			return err
		}
		_, err = w.Write(data)
		return err
	})
}
