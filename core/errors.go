// Package core implements the Ndes v1 file format (see SPEC.md).
package core

import "errors"

// Error classes. Every error returned by this package wraps one of these, so
// callers can use errors.Is.
var (
	// ErrMalformed: the file does not have a valid structure (bad magic or
	// kind, bad lengths, failed structural check, truncated read).
	ErrMalformed = errors.New("ndes: malformed or incomplete file")
	// ErrUnsupported: a version or KDF parameter v1 does not accept.
	ErrUnsupported = errors.New("ndes: unsupported version or parameters")
	// ErrAuth: an AEAD authentication check failed.
	ErrAuth = errors.New("ndes: authentication failed")
	// ErrMetadata: metadata is not in canonical form or breaks a field rule.
	ErrMetadata = errors.New("ndes: invalid metadata")
	// ErrWrongPassphrase: wrapped_vk did not open (SPEC 4.3).
	ErrWrongPassphrase = errors.New("ndes: wrong passphrase or altered vault.json")
	// ErrInboxKeyMismatch: inbox_pub in vault.json is not the one derived from VK.
	ErrInboxKeyMismatch = errors.New("ndes: inbox_pub in vault.json does not match the vault key")
	// ErrVaultAltered: recovery key is right but vault.json was changed (SPEC 4.3).
	ErrVaultAltered = errors.New("ndes: vault.json has been altered")
	// ErrWrongRecoveryKey: recovery-key unlock against an existing vault.json
	// failed and the cause can't be told apart (SPEC 4.3).
	ErrWrongRecoveryKey = errors.New("ndes: wrong recovery key or altered vault.json")
	// ErrPathMismatch: a file's path is not a valid name for it, or does not
	// match the file_id in its header (SPEC 4.1).
	ErrPathMismatch = errors.New("ndes: file path does not match its file_id")
	// ErrKeyUnverifiable: nothing in the vault confirms the recovery key (SPEC 4.5 case 3).
	ErrKeyUnverifiable = errors.New("ndes: cannot be verified")
	// ErrRecoveryKeyTypo: the recovery key's checksum does not match.
	ErrRecoveryKeyTypo = errors.New("ndes: recovery key has a typo (checksum does not match)")
	// ErrConflict: an object with the inbox file's id exists but is not its ingest result.
	ErrConflict = errors.New("ndes: conflicting object with the same file_id")
)
