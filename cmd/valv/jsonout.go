package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"

	"github.com/klppl/valv/core"
)

// jsonLines writes machine-readable output for the Mac app (D-A8): one JSON
// object per line, "type" first. Names only ever appear in the "name" and
// "dir" fields of ls records. Nothing here changes an exit code or an
// accept/reject decision.
type jsonLines struct{ w io.Writer }

// rec writes one record. kv is alternating key, value pairs after "type".
func (j jsonLines) rec(typ string, kv ...any) {
	var b bytes.Buffer
	b.WriteString(`{"type":`)
	writeJSON(&b, typ)
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteByte(',')
		writeJSON(&b, kv[i].(string))
		b.WriteByte(':')
		writeJSON(&b, kv[i+1])
	}
	b.WriteString("}\n")
	_, _ = j.w.Write(b.Bytes()) // one Write per line
}

func writeJSON(b *bytes.Buffer, v any) {
	enc := json.NewEncoder(b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	b.Truncate(b.Len() - 1) // Encode appends a newline
}

// notVaultError keeps the existing message and lets callers tell "no
// vault.json" from other failures.
type notVaultError struct {
	msg string
	is  error // what Unwrap reports; errNotAVault when nil
}

func (e *notVaultError) Error() string { return e.msg }
func (e *notVaultError) Unwrap() error {
	if e.is != nil {
		return e.is
	}
	return errNotAVault
}

var errNotAVault = errors.New("not a vault")

// httpStatusError is a server answer other than the expected one. Its text is
// what the code printed before.
type httpStatusError struct {
	status int
	msg    string
}

func (e *httpStatusError) Error() string { return e.msg }

// jsonErrCode maps a failure to the fixed code of a final "error" record. The
// app never reads the error text.
func jsonErrCode(err error) string {
	var hs *httpStatusError
	var ue *url.Error
	switch {
	case errors.Is(err, core.ErrWrongPassphrase):
		return "wrong-passphrase"
	case errors.Is(err, errNotAVault), errors.Is(err, os.ErrNotExist):
		return "not-a-vault"
	case errors.Is(err, core.ErrMalformed), errors.Is(err, core.ErrUnsupported),
		errors.Is(err, core.ErrInboxKeyMismatch):
		return "vault-unreadable"
	case errors.As(err, &hs):
		switch hs.status {
		case 401, 403:
			return "unauthorized"
		case 429:
			return "rate-limited"
		}
		return "other"
	case errors.As(err, &ue):
		return "unreachable"
	}
	return "other"
}
