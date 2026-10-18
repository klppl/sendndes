package core

import (
	"fmt"
	"strings"
)

// Vault layout (SPEC 4.1). Paths use "/" separators, relative to the vault root.
const (
	ConfigFile  = "vault.json"
	ObjectsDir  = "objects"
	InboxDir    = "inbox"
	ObjectExt   = ".obj"
	InboxExt    = ".inb"
	PartSuffix  = ".part"
	fileIDChars = 2 * FileIDSize
)

// ParseFileID parses exactly 32 lowercase hex characters.
func ParseFileID(s string) (FileID, error) {
	var id FileID
	if len(s) != fileIDChars {
		return id, fmt.Errorf("%w: file_id must be %d lowercase hex characters", ErrPathMismatch, fileIDChars)
	}
	for i := 0; i < len(s); i += 2 {
		hi := strings.IndexByte(lowerHex, s[i])
		lo := strings.IndexByte(lowerHex, s[i+1])
		if hi < 0 || lo < 0 {
			return id, fmt.Errorf("%w: file_id must be %d lowercase hex characters", ErrPathMismatch, fileIDChars)
		}
		id[i/2] = byte(hi<<4 | lo)
	}
	return id, nil
}

// ObjectPath returns "objects/<first 2 hex>/<file_id hex>.obj".
func ObjectPath(id FileID) string {
	s := id.String()
	return ObjectsDir + "/" + s[:2] + "/" + s + ObjectExt
}

// InboxName returns "<file_id hex>.inb".
func InboxName(id FileID) string { return id.String() + InboxExt }

// ParseObjectPath returns the file_id an object at rel must have. rel is
// relative to the vault root, with "/" separators.
func ParseObjectPath(rel string) (FileID, error) {
	parts := strings.Split(rel, "/")
	if len(parts) != 3 || parts[0] != ObjectsDir {
		return FileID{}, fmt.Errorf("%w: not an object path", ErrPathMismatch)
	}
	name, ok := strings.CutSuffix(parts[2], ObjectExt)
	if !ok {
		return FileID{}, fmt.Errorf("%w: object name must end in %s", ErrPathMismatch, ObjectExt)
	}
	id, err := ParseFileID(name)
	if err != nil {
		return FileID{}, err
	}
	if parts[1] != name[:2] {
		return FileID{}, fmt.Errorf("%w: prefix directory does not match file_id", ErrPathMismatch)
	}
	return id, nil
}

// ParseInboxName returns the file_id an inbox file named name must have.
func ParseInboxName(name string) (FileID, error) {
	stem, ok := strings.CutSuffix(name, InboxExt)
	if !ok {
		return FileID{}, fmt.Errorf("%w: inbox name must end in %s", ErrPathMismatch, InboxExt)
	}
	return ParseFileID(stem)
}

func checkExpected(got, expected FileID) error {
	if got != expected {
		return fmt.Errorf("%w: header file_id differs from the name", ErrPathMismatch)
	}
	return nil
}
