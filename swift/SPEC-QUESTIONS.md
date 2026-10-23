# Questions from the Swift port (step 3)

Every positive and negative vector passes. No vector failed, so the Python
decryptor in ~/valv-review/round2/ was not consulted.

The points below are places where SPEC.md (as frozen for v1, commit f5fb8e6) does not pin
down behaviour. None of them changes a byte the format writes, and none is
exercised by a vector. All six are **resolved by owner**; the Swift code
already behaves as ruled. SPEC.md is not edited (format frozen; see its
section 15 for how clarifications are added).

## Q1. Error class for a bad `salt`, `wrapped_vk` or `inbox_pub` in vault.json — resolved by owner

SPEC 4.2 says `salt` must decode to exactly 16 bytes ("rejected before the KDF
runs"), and `wrapped_vk`/`inbox_pub` must decode to 60/32 bytes with canonical
Base64. The README classes are `unsupported` ("KDF parameters v1 does not
accept") and `malformed` ("non-canonical vault.json"). A salt of the wrong
length could be either.

**Ruling: `malformed`.** Any Base64 or length problem in these three fields is
`malformed`; `unsupported` is only for `v`, `alg`, `t`, `m_kib` and `p`.

## Q2. Error class for a passphrase that is not valid UTF-8 — resolved by owner

SPEC 3 says to reject it but names no class.

**Ruling: `malformed`.** (Only reachable from the bytes-based unlock; a Swift
`String` is always valid Unicode.)

## Q3. SPEC 4.5: objects present but none readable, no inbox files — resolved by owner

Case 4 is "Nothing to check against (no objects, no inbox files)". If
`objects/` holds files but none is *readable* (all fail the path, header or
structural check) and there are no inbox files, is that case 3 or case 4?

**Ruling: the stricter reading.** It is case 3 ("cannot be verified: 0 of 0
readable objects"), which refuses without `--unverified-key`. Only an empty
`objects/` and an empty `inbox/` give case 4.

## Q4. SPEC 6.3 idempotency: must the inbox file's own `meta_blob` and chunks authenticate? — resolved by owner

The rule requires the *existing object's* `meta_blob` to decrypt and pass 5.2,
equal FKs, and identical authenticated chunks. Does the inbox file itself also
have to authenticate before the already-ingested decision is made?

**Ruling: authenticate the inbox file first (earlier ruling withdrawn).** The
already-ingested decision is made only after the inbox file itself is
authenticated (its `meta_blob` and chunks); if authenticating the inbox file
fails, report the error and keep the inbox file even if a matching object
exists. Then the existing idempotency rule applies.

## Q5. Object and inbox path check: are the `objects/` and `inbox/` components part of it? — resolved by owner

SPEC 4.1 checks the file name and that "an object's directory under
`objects/`" equals the first two hex characters.

**Ruling: the check covers all components.** An object path is
`objects/<xx>/<file_id>.obj` and an inbox path is `inbox/<file_id>.inb`.
`FileID(objectPath:)` checks that the path has exactly three components
(`objects`, `<xx>` equal to the first two hex characters, and
`<32 lowercase hex>.obj`), and `FileID(inboxPath:)` checks that the path has
exactly two components (`inbox` and `<32 lowercase hex>.inb`).

## Q6. Order of checks when a file has several faults — resolved by owner

**Ruling: multi-fault error precedence is not normative.** For every input,
accept/reject is normative and must be identical in all implementations; the
error class is normative only for single-fault inputs; the error precedence for
multi-fault inputs is not normative.

For reference, the order used in `ValvCore` is:

1. Path, before the file is opened: `objects/<xx>/<32 lowercase hex>.obj` (where
   `<xx>` equals the first two hex characters) or
   `inbox/<32 lowercase hex>.inb` → `path`.
2. Magic is `VALV` → else `malformed`.
3. Version is 0x01 → else `unsupported`.
4. Kind is 0x01 for an object reader, 0x02 for an inbox reader → else
   `malformed`.
5. The fixed header is complete (86 bytes for objects, 58 for inbox files) →
   else `malformed`.
6. `meta_len` satisfies `540 <= meta_len <= 65564` and
   `(meta_len - 28) mod 512 == 0` → else `malformed`.
7. The header file_id equals the file_id from the name → else `path`.
8. Structural check on `ct_total` (SPEC 5.3) → else `malformed`.
9. `meta_blob` is read in full → else `malformed`.
10. Object: unwrap `wrapped_fk` with K_wrap → else `auth`.
    Inbox: X25519 with `eph_pub` → `malformed` if the result is all zero; then
    derive FK.
11. Decrypt `meta_blob` → else `auth` (inbox: "inbox file is not authentic").
12. Parse and check the metadata (SPEC 5.2) → else `metadata`.
13. Each chunk in order, authenticated as it is read → else `auth`; a file that
    ends early → `malformed`; after the last chunk the file must be at its end
    → else `malformed`.

For vault.json:

1. Size at most 4096 bytes → else `malformed`.
2. JSON syntax (objects, strings without escapes, integers only) → else
   `malformed`.
3. Top-level keys are exactly `v`, `kdf`, `wrapped_vk`, `inbox_pub` in that
   order → else `malformed`.
4. `v` is an integer → else `malformed`; `v == 1` → else `unsupported`.
5. `kdf` is an object with exactly `alg`, `salt`, `t`, `m_kib`, `p` in that
   order → else `malformed`; `alg` and `salt` are strings and `t`, `m_kib`,
   `p` integers → else `malformed`.
6. `alg == "argon2id"` → else `unsupported`; `t == 3`, `m_kib == 65536`,
   `p == 1` → else `unsupported`.
7. `wrapped_vk` and `inbox_pub` are strings → else `malformed`.
8. `salt`, `wrapped_vk`, `inbox_pub` are canonical Base64 of 16, 60 and 32
   bytes → else `malformed`.
9. Re-serialization is byte-identical → else `malformed`.
10. Argon2id and opening `wrapped_vk` with `config_aad` → else
    `wrong_passphrase`.
11. The derived `inbox_pub` equals the stored one → else `inbox_key_mismatch`.
