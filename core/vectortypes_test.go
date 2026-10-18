package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The committed test vectors live in ../testvectors. vectors.json describes
// every vector; binary files sit next to it. See testvectors/README.md.
const vectorDir = "../testvectors"

// hexBytes is a byte slice that is written to JSON as lowercase hex.
type hexBytes []byte

func (h hexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}

type vectorFile struct {
	Format   string           `json:"format"`
	Vault    vaultVector      `json:"vault"`
	Objects  []objectVector   `json:"objects"`
	Inbox    []inboxVector    `json:"inbox"`
	Metadata []metadataVector `json:"metadata"`
	Negative []negativeVector `json:"negative"`
}

type vaultVector struct {
	File               string   `json:"file"`
	Passphrase         string   `json:"passphrase"`
	PassphraseHex      hexBytes `json:"passphrase_hex"`
	Salt               hexBytes `json:"salt"`
	T                  int      `json:"t"`
	MKiB               int      `json:"m_kib"`
	P                  int      `json:"p"`
	KEK                hexBytes `json:"kek"`
	VK                 hexBytes `json:"vk"`
	WrapNonce          hexBytes `json:"wrap_nonce"`
	ConfigAAD          hexBytes `json:"config_aad"`
	WrappedVK          hexBytes `json:"wrapped_vk"`
	KWrap              hexBytes `json:"k_wrap"`
	InboxPrivUnclamped hexBytes `json:"inbox_priv_unclamped"`
	InboxPriv          hexBytes `json:"inbox_priv"`
	InboxPub           hexBytes `json:"inbox_pub"`
	RecoveryKey        string   `json:"recovery_key"`
	VaultJSONHex       hexBytes `json:"vault_json_hex"`
}

// metaFields gives metadata values: strings as UTF-8 hex, integers as
// decimal strings (so no JSON parser rounds them through a float).
type metaFields struct {
	Readable string   `json:"readable,omitempty"`
	Name     hexBytes `json:"name_hex"`
	Dir      hexBytes `json:"dir_hex"`
	MTime    string   `json:"mtime"`
	MIME     hexBytes `json:"mime_hex"`
	Rev      string   `json:"rev"`
}

func newMetaFields(m Metadata, readable string) metaFields {
	return metaFields{
		Readable: readable,
		Name:     hexBytes(m.Name),
		Dir:      hexBytes(m.Dir),
		MTime:    strconv.FormatInt(m.MTime, 10),
		MIME:     hexBytes(m.MIME),
		Rev:      strconv.FormatInt(m.Rev, 10),
	}
}

func (f metaFields) metadata() (Metadata, error) {
	mt, err := strconv.ParseInt(f.MTime, 10, 64)
	if err != nil {
		return Metadata{}, err
	}
	rev, err := strconv.ParseInt(f.Rev, 10, 64)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{Name: string(f.Name), Dir: string(f.Dir), MTime: mt, MIME: string(f.MIME), Rev: rev}, nil
}

type chunkVector struct {
	Index        int64    `json:"index"`
	Final        bool     `json:"final"`
	Offset       int64    `json:"offset"`
	PlaintextLen int      `json:"plaintext_len"`
	StoredLen    int      `json:"stored_len"`
	Nonce        hexBytes `json:"nonce"`
	Tag          hexBytes `json:"tag"`
}

// encryptedFile is shared by object and inbox vectors.
type encryptedFile struct {
	Description     string        `json:"description"`
	File            string        `json:"file"`
	FileSHA256      hexBytes      `json:"file_sha256"`
	FileHex         hexBytes      `json:"file_hex,omitempty"`
	PlaintextFile   string        `json:"plaintext_file"`
	PlaintextLen    int64         `json:"plaintext_len"`
	PlaintextSHA256 hexBytes      `json:"plaintext_sha256"`
	PlaintextHex    hexBytes      `json:"plaintext_hex,omitempty"`
	FileID          hexBytes      `json:"file_id"`
	FK              hexBytes      `json:"fk"`
	KContent        hexBytes      `json:"k_content"`
	KMeta           hexBytes      `json:"k_meta"`
	Meta            metaFields    `json:"meta"`
	MetaPlaintext   hexBytes      `json:"meta_plaintext"`
	MetaNonce       hexBytes      `json:"meta_nonce"`
	MetaAAD         hexBytes      `json:"meta_aad"`
	MetaBlob        hexBytes      `json:"meta_blob"`
	Header          hexBytes      `json:"header"`
	CtTotal         int64         `json:"ct_total"`
	Chunks          []chunkVector `json:"chunks"`
}

type objectVector struct {
	encryptedFile
	WrapNonce hexBytes `json:"wrap_nonce"`
	WrapAAD   hexBytes `json:"wrap_aad"`
	WrappedFK hexBytes `json:"wrapped_fk"`
}

type inboxVector struct {
	encryptedFile
	InboxPub hexBytes `json:"inbox_pub"`
	EphPriv  hexBytes `json:"eph_priv"`
	EphPub   hexBytes `json:"eph_pub"`
	DH       hexBytes `json:"dh"`
	HKDFSalt hexBytes `json:"hkdf_salt"`
	Ingest   struct {
		File       string   `json:"file"`
		FileSHA256 hexBytes `json:"file_sha256"`
		WrapNonce  hexBytes `json:"wrap_nonce"`
		WrapAAD    hexBytes `json:"wrap_aad"`
		WrappedFK  hexBytes `json:"wrapped_fk"`
		Header     hexBytes `json:"header"`
	} `json:"ingest"`
}

type metadataVector struct {
	Description string     `json:"description"`
	Input       metaFields `json:"input"`
	Canonical   hexBytes   `json:"canonical_json,omitempty"`
	PaddedLen   int        `json:"padded_len,omitempty"`
	Error       string     `json:"error,omitempty"`
}

type negativeVector struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Kind          string   `json:"kind"` // vault, object, inbox
	File          string   `json:"file"`
	Passphrase    string   `json:"passphrase,omitempty"`
	MetaPlaintext hexBytes `json:"meta_plaintext,omitempty"`
	Expect        string   `json:"expect"`
}

// errorClasses maps the "expect" and "error" strings in vectors.json to the
// package's error classes.
var errorClasses = map[string]error{
	"malformed":          ErrMalformed,
	"unsupported":        ErrUnsupported,
	"auth":               ErrAuth,
	"metadata":           ErrMetadata,
	"wrong_passphrase":   ErrWrongPassphrase,
	"inbox_key_mismatch": ErrInboxKeyMismatch,
}

func errorClass(err error) string {
	for name, class := range errorClasses {
		if errors.Is(err, class) {
			return name
		}
	}
	return fmt.Sprintf("unclassified(%v)", err)
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir, "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

func readVectorFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
