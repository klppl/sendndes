package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func hashHex(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func TestParseTokensFile(t *testing.T) {
	tokA, tokB := strings.Repeat("a", 43), strings.Repeat("b", 43)
	good := "# phones\nupload phone-1 " + hashHex(tokA) + "\r\n\npull mac " + hashHex(tokB) + "\n"
	set, err := parseTokensFile([]byte(good), false)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := set.lookup3(tokA); !ok || r != roleUpload || r.canPull() {
		t.Fatalf("upload token: %v %v", r, ok)
	}
	if r, ok := set.lookup3(tokB); !ok || r != rolePull || r.canUpload() {
		t.Fatalf("pull token: %v %v", r, ok)
	}
	if _, ok := set.lookup3(strings.Repeat("c", 43)); ok {
		t.Fatal("unknown token accepted")
	}
	if _, ok := set.lookup3(""); ok {
		t.Fatal("empty token accepted")
	}
	both, _ := parseTokensFile([]byte("both x "+hashHex(tokA)), false)
	if r, _ := both.lookup3(tokA); !r.canUpload() || !r.canPull() {
		t.Fatal("both role")
	}

	bad := map[string]string{
		"empty":           "",
		"comments only":   "# nothing\n",
		"two fields":      "upload " + hashHex(tokA),
		"four fields":     "upload a b " + hashHex(tokA),
		"unknown role":    "admin a " + hashHex(tokA),
		"upper role":      "UPLOAD a " + hashHex(tokA),
		"upper hex":       "upload a " + strings.ToUpper(hashHex(tokA)),
		"short hash":      "upload a abcd",
		"non hex":         "upload a " + strings.Repeat("z", 64),
		"long label":      "upload " + strings.Repeat("l", 33) + " " + hashHex(tokA),
		"non ascii label": "upload fön " + hashHex(tokA),
		"duplicate hash":  "upload a " + hashHex(tokA) + "\nupload b " + hashHex(tokA),
		"duplicate label": "upload a " + hashHex(tokA) + "\nupload a " + hashHex(tokB),
		"invalid utf8":    "upload a \xff" + hashHex(tokA),
		"plaintext token": tokA,
	}
	for name, in := range bad {
		if _, err := parseTokensFile([]byte(in), false); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), tokA) || strings.Contains(err.Error(), hashHex(tokA)) {
			t.Errorf("%s: error repeats a token or hash: %v", name, err)
		}
	}
	if _, err := parseTokensFile(make([]byte, maxTokensFileSize+1), false); err == nil {
		t.Error("oversized file accepted")
	}
}

func TestMergeTokenSets(t *testing.T) {
	a, _ := parseTokensFile([]byte("upload a "+hashHex("x")), false)
	if _, err := mergeTokenSets(a, legacyTokenSet([]byte("x"))); err == nil {
		t.Fatal("same token in both sets accepted")
	}
	m, err := mergeTokenSets(a, legacyTokenSet([]byte("y")))
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := m.lookup3("y"); !ok || r != roleBoth {
		t.Fatal("legacy token is role both")
	}
}

// lookup3 is lookup without the label, for the older assertions.
func (t *tokenSet) lookup3(token string) (tokenRole, bool) {
	r, _, ok := t.lookup(token)
	return r, ok
}
