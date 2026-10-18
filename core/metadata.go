package core

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Metadata sizes (SPEC 5.1, 5.2).
const (
	metaBlock     = 512
	MaxMetaPadded = 65536
	metaOverhead  = NonceSize + TagSize
	minMetaLen    = metaBlock + metaOverhead
	maxMetaLen    = MaxMetaPadded + metaOverhead
)

// Metadata is the encrypted per-file metadata (SPEC 5.2).
type Metadata struct {
	Name  string
	Dir   string
	MTime int64 // Unix nanoseconds
	MIME  string
	Rev   int64
}

func validMetaLen(n uint32) bool {
	return n >= minMetaLen && n <= maxMetaLen && (n-metaOverhead)%metaBlock == 0
}

func validName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

func validDir(s string) bool {
	if s == "" {
		return true
	}
	for _, c := range strings.Split(s, "/") {
		if !validName(c) {
			return false
		}
	}
	return true
}

// check applies the field rules to already-normalized values.
func (m *Metadata) check() error {
	if !utf8.ValidString(m.Name) || !utf8.ValidString(m.Dir) || !utf8.ValidString(m.MIME) {
		return fmt.Errorf("%w: invalid UTF-8", ErrMetadata)
	}
	if !validName(m.Name) {
		return fmt.Errorf("%w: invalid name", ErrMetadata)
	}
	if !validDir(m.Dir) {
		return fmt.Errorf("%w: invalid dir", ErrMetadata)
	}
	if m.Rev < 1 {
		return fmt.Errorf("%w: rev must be at least 1", ErrMetadata)
	}
	if !norm.NFC.IsNormalString(m.Name) || !norm.NFC.IsNormalString(m.Dir) {
		return fmt.Errorf("%w: name or dir is not NFC", ErrMetadata)
	}
	return nil
}

// EncodeMetadata normalizes name and dir to NFC, checks the field rules and
// returns the padded canonical plaintext (SPEC 5.2). The returned Metadata
// holds the normalized values.
func EncodeMetadata(m Metadata) ([]byte, Metadata, error) {
	if !utf8.ValidString(m.Name) || !utf8.ValidString(m.Dir) || !utf8.ValidString(m.MIME) {
		return nil, m, fmt.Errorf("%w: invalid UTF-8", ErrMetadata)
	}
	m.Name = norm.NFC.String(m.Name)
	m.Dir = norm.NFC.String(m.Dir)
	if err := m.check(); err != nil {
		return nil, m, err
	}
	padded, err := padMetadata(canonicalMetadataJSON(&m))
	return padded, m, err
}

func padMetadata(j []byte) ([]byte, error) {
	n := (len(j) + metaBlock - 1) / metaBlock * metaBlock
	if n > MaxMetaPadded {
		return nil, fmt.Errorf("%w: metadata larger than %d bytes", ErrMetadata, MaxMetaPadded)
	}
	return append(j, bytes.Repeat([]byte{' '}, n-len(j))...), nil
}

func canonicalMetadataJSON(m *Metadata) []byte {
	b := make([]byte, 0, 128+len(m.Name)+len(m.Dir)+len(m.MIME))
	b = append(b, `{"name":`...)
	b = appendJSONString(b, m.Name)
	b = append(b, `,"dir":`...)
	b = appendJSONString(b, m.Dir)
	b = append(b, `,"mtime":`...)
	b = strconv.AppendInt(b, m.MTime, 10)
	b = append(b, `,"mime":`...)
	b = appendJSONString(b, m.MIME)
	b = append(b, `,"rev":`...)
	b = strconv.AppendInt(b, m.Rev, 10)
	return append(b, '}')
}

const lowerHex = "0123456789abcdef"

func appendJSONString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', lowerHex[c>>4], lowerHex[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// DecodeMetadata parses a padded metadata plaintext, accepting only the
// canonical form (SPEC 5.2).
func DecodeMetadata(padded []byte) (Metadata, error) {
	var m Metadata
	if len(padded) == 0 || len(padded)%metaBlock != 0 || len(padded) > MaxMetaPadded {
		return m, fmt.Errorf("%w: padded length %d", ErrMetadata, len(padded))
	}
	j := bytes.TrimRight(padded, " ")
	if len(padded)-len(j) >= metaBlock {
		return m, fmt.Errorf("%w: padding is not minimal", ErrMetadata)
	}
	if !utf8.Valid(j) {
		return m, fmt.Errorf("%w: invalid UTF-8", ErrMetadata)
	}
	m, ok := parseMetadataStrict(j)
	if !ok {
		return Metadata{}, fmt.Errorf("%w: not canonical JSON", ErrMetadata)
	}
	if err := m.check(); err != nil {
		return Metadata{}, err
	}
	if !bytes.Equal(canonicalMetadataJSON(&m), j) {
		return Metadata{}, fmt.Errorf("%w: not canonical JSON", ErrMetadata)
	}
	return m, nil
}

// metaParser is a strict parser for exactly the canonical metadata schema.
type metaParser struct {
	b []byte
	i int
}

func parseMetadataStrict(b []byte) (Metadata, bool) {
	p := metaParser{b: b}
	var m Metadata
	ok := p.lit(`{"name":`) && p.str(&m.Name) &&
		p.lit(`,"dir":`) && p.str(&m.Dir) &&
		p.lit(`,"mtime":`) && p.int(&m.MTime) &&
		p.lit(`,"mime":`) && p.str(&m.MIME) &&
		p.lit(`,"rev":`) && p.int(&m.Rev) &&
		p.lit(`}`) && p.i == len(p.b)
	return m, ok
}

func (p *metaParser) lit(s string) bool {
	if !bytes.HasPrefix(p.b[p.i:], []byte(s)) {
		return false
	}
	p.i += len(s)
	return true
}

func (p *metaParser) str(out *string) bool {
	if !p.lit(`"`) {
		return false
	}
	var s []byte
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			*out = string(s)
			return true
		case c < 0x20:
			return false
		case c == '\\':
			if p.i+1 >= len(p.b) {
				return false
			}
			switch e := p.b[p.i+1]; e {
			case '"', '\\':
				s = append(s, e)
				p.i += 2
			case 'u':
				// Only \u0000 to \u001f, lowercase hex.
				if p.i+6 > len(p.b) || p.b[p.i+2] != '0' || p.b[p.i+3] != '0' {
					return false
				}
				hi := strings.IndexByte("01", p.b[p.i+4])
				lo := strings.IndexByte(lowerHex, p.b[p.i+5])
				if hi < 0 || lo < 0 {
					return false
				}
				s = append(s, byte(hi<<4|lo))
				p.i += 6
			default:
				return false
			}
		default:
			s = append(s, c)
			p.i++
		}
	}
	return false
}

func (p *metaParser) int(out *int64) bool {
	start := p.i
	if p.i < len(p.b) && p.b[p.i] == '-' {
		p.i++
	}
	digits := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	n := p.i - digits
	if n == 0 || (p.b[digits] == '0' && (n > 1 || digits > start)) {
		return false // no digits, leading zero, or "-0"
	}
	v, err := strconv.ParseInt(string(p.b[start:p.i]), 10, 64)
	if err != nil {
		return false // overflow
	}
	*out = v
	return true
}
