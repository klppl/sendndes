# Questions from the Swift port (step 3)

Every positive and negative vector passes. No vector failed, so the Python
decryptor in ~/valv-review/round2/ was not consulted.

The points below are places where SPEC.md (at format-v1-frozen) does not pin
down behaviour. None of them changes a byte the format writes, and none is
exercised by a vector. Each one has a **provisional** behaviour in the Swift
code, marked here so the owner can confirm or overrule it. If an answer
differs, the change is local and small.

## Q1. Error class for a bad `salt`, `wrapped_vk` or `inbox_pub` in vault.json

SPEC 4.2 says `salt` must decode to exactly 16 bytes ("rejected before the KDF
runs"), and `wrapped_vk`/`inbox_pub` must decode to 60/32 bytes with canonical
Base64. The README classes are `unsupported` ("KDF parameters v1 does not
accept") and `malformed` ("non-canonical vault.json"). A salt of the wrong
length could be either.

Provisional: `malformed` for any Base64 or length problem in these three
fields; `unsupported` only for `v`, `alg`, `t`, `m_kib` and `p`.

## Q2. Error class for a passphrase that is not valid UTF-8

SPEC 3 says to reject it but names no class. Provisional: `malformed`.
(Only reachable from the bytes-based unlock; a Swift `String` is always valid
Unicode.)

## Q3. SPEC 4.5: objects present but none readable, no inbox files

Case 4 is "Nothing to check against (no objects, no inbox files)". If
`objects/` holds files but none is *readable* (all fail the path, header or
structural check) and there are no inbox files, is that case 3 ("cannot be
verified: 0 of 0 readable objects") or case 4?

Provisional: case 3, because there are objects; only an empty `objects/` and
an empty `inbox/` give case 4. Case 3 is the stricter outcome (it refuses
without `--unverified-key`).

## Q4. SPEC 6.3 idempotency: must the inbox file's own `meta_blob` authenticate?

The rule requires the *existing object's* `meta_blob` to decrypt and pass 5.2,
equal FKs, and identical authenticated chunks. It says nothing about the inbox
file's `meta_blob`.

Provisional: not checked, following the text literally. The inbox file's
header, path and structure are checked and its FK is derived from it.

## Q5. Object path check: is the `objects/` component itself part of it?

SPEC 4.1 checks the file name and that "an object's directory under
`objects/`" equals the first two hex characters.

Provisional: `FileID(objectPath:)` checks the last two path components (prefix
directory and name). That the prefix directory sits under the vault's
`objects/` is the job of the caller that walks the vault (directory plumbing is
out of scope for this library). Inbox files: only the name is checked.

## Q6. Order of checks when a file has several faults

The vectors each have one fault. For files with several, the Swift reader
reports the first of: magic (`malformed`), version (`unsupported`), kind
(`malformed`), truncated fixed header (`malformed`), `meta_len` bounds
(`malformed`), header file_id vs. name (`path`), structural check
(`malformed`), then `wrapped_fk` / DH (`auth` / `malformed`), `meta_blob`
(`auth`), metadata (`metadata`), chunks (`auth`). The name itself is checked
before the file is opened (`path`). Is any other order intended?
