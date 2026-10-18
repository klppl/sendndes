// Package core implements the Valv v1 file format (see SPEC.md).
package core

import "errors"

// Error classes. Every error returned by this package wraps one of these, so
// callers can use errors.Is.
var (
	// ErrMalformed: the file does not have a valid structure (bad magic or
	// kind, bad lengths, failed structural check, truncated read).
	ErrMalformed = errors.New("valv: malformed or incomplete file")
	// ErrUnsupported: a version or KDF parameter v1 does not accept.
	ErrUnsupported = errors.New("valv: unsupported version or parameters")
	// ErrAuth: an AEAD authentication check failed.
	ErrAuth = errors.New("valv: authentication failed")
	// ErrMetadata: metadata is not in canonical form or breaks a field rule.
	ErrMetadata = errors.New("valv: invalid metadata")
	// ErrWrongPassphrase: wrapped_vk did not open (SPEC 4.3).
	ErrWrongPassphrase = errors.New("valv: wrong passphrase or altered vault.json")
	// ErrInboxKeyMismatch: inbox_pub in vault.json is not the one derived from VK.
	ErrInboxKeyMismatch = errors.New("valv: inbox_pub in vault.json does not match the vault key")
	// ErrVaultAltered: recovery key is right but vault.json was changed (SPEC 4.3).
	ErrVaultAltered = errors.New("valv: vault.json has been altered")
	// ErrWrongRecoveryKey: recovery key unlock failed and the cause can't be told apart.
	ErrWrongRecoveryKey = errors.New("valv: wrong recovery key or altered vault.json")
	// ErrPathMismatch: a file's path is not a valid name for it, or does not
	// match the file_id in its header (SPEC 4.1).
	ErrPathMismatch = errors.New("valv: file path does not match its file_id")
	// ErrKeyUnverifiable: nothing in the vault can confirm the recovery key (SPEC 4.5 case 4).
	ErrKeyUnverifiable = errors.New("valv: the recovery key cannot be verified")
	// ErrRecoveryKeyTypo: the recovery key's checksum does not match.
	ErrRecoveryKeyTypo = errors.New("valv: recovery key has a typo (checksum does not match)")
	// ErrConflict: an object with the inbox file's id exists but is not its ingest result.
	ErrConflict = errors.New("valv: conflicting object with the same file_id")
)
