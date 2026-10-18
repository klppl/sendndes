# Valv: Format and Architecture Spec, v1 (DRAFT)

Personal, single-user, open-source encrypted vault. Own format, not compatible with anything else.
Status: experimental. The format may change freely until real data depends on it. Always keep a plaintext backup until the tool has proven itself.

You (the AI implementing this) are building a tool for exactly one user. Prefer simple and correct over flexible. Anything not specified here is a question for the human, not a decision for you.

Each rule is stated once, in the section listed for it in section 13. Section 14 lists what changed from the original draft.

## 1. Goals and non-goals

Goals
- File contents, filenames, and folder structure are unreadable to whoever hosts or syncs the vault (Google Drive, a NAS, a server).
- Works with dumb file sync: no central mutable index, no locking.
- A write-only server can add files to the vault without ever being able to read it (the "inbox").
- One spec, two implementations (Go for reference and server, Swift for Mac/iOS) that must agree byte for byte.
- The vault does not care where it is stored. Any storage that can put/get/list/delete files works (section 8).

Non-goals
- Multi-user, sharing, compatibility with other tools, hiding file count or approximate sizes, protecting against malware on an unlocked device, freshness/rollback protection (v1).

## 2. Primitives (fixed, no negotiation)

| Purpose | Choice |
|---|---|
| Password KDF | Argon2id, m=64 MiB, t=3, p=1 |
| AEAD | ChaCha20-Poly1305 (RFC 8439): 32-byte key, 12-byte nonce, 16-byte tag |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| Inbox key agreement | X25519 (RFC 7748) |
| Randomness | OS CSPRNG only |

- Go: golang.org/x/crypto (argon2, chacha20poly1305, hkdf, curve25519).
- Swift: CryptoKit (ChaChaPoly, HKDF, Curve25519.KeyAgreement). CryptoKit has no Argon2, so use a vetted package (e.g. a libsodium wrapper; libsodium's Argon2id supports p=1, which is all v1 needs). Do not hand-roll Argon2.
- No other algorithms. No algorithm fields that let a file choose its cipher.
- Non-crypto dependency: Unicode NFC normalization (section 5.2). Go: golang.org/x/text/unicode/norm. Swift: `String.precomposedStringWithCanonicalMapping`.

## 3. Keys

- **VK**: 32 random bytes, the vault master key. Generated once at `init`.
- **KEK** = Argon2id(passphrase, salt, t=3, m=65536 KiB, p=1) -> 32 bytes. Its only job is to wrap VK (section 4.2).
- **HKDF salt.** Every HKDF derivation from VK or FK uses an empty salt. Per RFC 5869 an empty salt is the same as 32 zero bytes; both implementations must match the test vectors on this. The only HKDF call with a non-empty salt is the inbox FK derivation (section 6.2). Every derivation outputs L=32 bytes.
- **Subkeys from VK**: `HKDF-SHA256(ikm=VK, salt=empty, info=LABEL, L=32)`
  - `"valv/v1/wrap"` -> K_wrap (wraps per-file keys)
  - `"valv/v1/inbox-x25519"` -> inbox X25519 private key. Clamp per RFC 7748 (`b[0] &= 248; b[31] &= 127; b[31] |= 64`) and use the clamped bytes as the private key.
- **inbox_pub** = X25519(inbox private key, base point 9). It is stored in vault.json and bound into the AAD of `wrapped_vk` (section 4.2). The inbox server holds the public key only, and gets it from its own configuration (supplied by the user), never by reading vault.json.
- **FK**: per-file random 32-byte key. Subkeys: `HKDF(ikm=FK, salt=empty, info="valv/v1/content")` -> K_content, `HKDF(ikm=FK, salt=empty, info="valv/v1/meta")` -> K_meta.
- **Recovery key**: VK encoded as RFC 4648 base32 (alphabet `A-Z2-7`), uppercase, no padding: 52 characters, written as 13 groups of 4 separated by `-`. Shown once at init, to be stored offline. On input, case, spaces and hyphens are ignored; what remains must be exactly 52 base32 characters that decode to 32 bytes and re-encode to the same 52 characters (the 4 unused trailing bits are zero). There is no separate checksum; section 4.3 says how it is verified. If the passphrase is lost and there is no recovery key, the data is gone.
- Changing the passphrase only re-wraps VK (section 4.4).

## 4. Vault layout

### 4.1 Files

```
vault/
  vault.json
  objects/<first 2 hex of file_id>/<file_id hex>.obj
  inbox/<file_id hex>.inb
```

- `file_id`: 16 random bytes, written as 32 lowercase hex chars. File names reveal nothing about content.
- No directory objects. Folder structure lives in each file's encrypted metadata (`dir`).
- Writers upload under a temporary name (`<name>.part`) and then rename (see section 8). Readers ignore `*.part`.
- Local-only scratch/cache (never in the synced vault): temp files, a SQLite listing cache. The cache is derived data and is rebuildable by scanning object headers.

### 4.2 vault.json (plaintext, public)

Writers produce exactly these bytes: LF line endings, two-space indent, the `kdf` object on one line with the spacing shown, and one trailing LF.

```json
{
  "v": 1,
  "kdf": { "alg": "argon2id", "salt": "<b64, 16 bytes>", "t": 3, "m_kib": 65536, "p": 1 },
  "wrapped_vk": "<b64: nonce(12) | ct(32) | tag(16)>",
  "inbox_pub": "<b64, 32 bytes>"
}
```

- `v` must be 1.
- `kdf` must be exactly `alg` = `"argon2id"`, `t` = 3, `m_kib` = 65536, `p` = 1, and `salt` must decode to exactly 16 bytes. Anything else is rejected before the KDF runs. Changing the parameters requires a new format version.
- `wrapped_vk` decodes to exactly 60 bytes, `inbox_pub` to exactly 32.
- Base64 is RFC 4648 standard alphabet with padding, canonical (unused trailing bits zero).
- Readers parse the file, check the rules above, re-serialize the parsed values in the writer format, and reject the file unless the result is byte-identical. Unknown keys are therefore rejected.

`wrapped_vk` = ChaCha20-Poly1305 under KEK with a random nonce, plaintext VK, AAD = `config_aad`:

```
"valv-config-v1"   14 ASCII bytes
u8 len(alg)         = 8
alg                 "argon2id"
salt                16 raw bytes
u32 t               big-endian
u32 m_kib           big-endian
u32 p               big-endian
inbox_pub           32 raw bytes
```

That is 83 bytes. Binding the parameters and `inbox_pub` into the AAD means any change to them makes the unwrap fail.

### 4.3 Unlocking

Passphrase unlock:
1. Parse and check vault.json (section 4.2), including `v` and the KDF parameters, before running the KDF.
2. Compute KEK and open `wrapped_vk` with `config_aad`. On failure report "wrong passphrase or altered vault.json".
3. Derive the inbox key pair from VK and compare the derived public key with `inbox_pub` in constant time. On mismatch, refuse to continue.

`init` generates VK, salt and nonce, writes vault.json, then runs passphrase unlock on what it wrote. If that fails, `init` fails.

Recovery-key unlock (no `wrapped_vk` involved):
1. Parse and check vault.json (section 4.2).
2. Decode the recovery key to VK (section 3).
3. Derive `inbox_pub` from VK. If it equals the one in vault.json, unlock succeeds.
4. Otherwise unlock fails. If the vault has at least one object, try to unwrap one object's `wrapped_fk` with K_wrap from this VK. If that works, report "vault.json has been altered". If it fails, or there are no objects, report "wrong recovery key or altered vault.json". Never guess beyond that.

### 4.4 Changing the passphrase

Every passphrase change generates a fresh random 16-byte salt and a fresh random wrap nonce. The KDF parameters stay as section 4.2 requires. `config_aad` is recomputed (it includes the new salt). VK and all objects are unchanged. vault.json is replaced via temp + rename.

## 5. Object file (kind 0x01)

All integers big-endian.

### 5.1 Header

```
offset  size       field
0       4          magic    "VALV"
4       1          version  0x01
5       1          kind     0x01
6       16         file_id
22      12         wrap_nonce
34      48         wrapped_fk   (ct 32 + tag 16)
82      4          meta_len
86      meta_len   meta_blob    (nonce 12 | ct | tag 16)
86+meta_len  ...   chunks
```

- A reader rejects a wrong magic or kind as malformed and any version other than 0x01 as unsupported.
- `meta_len` must satisfy `540 <= meta_len <= 65564` and `(meta_len - 28) mod 512 == 0` (the padded metadata is 512 to 65536 bytes, plus 28 bytes of nonce and tag). Check this before allocating.

Two AADs, deliberately different:
- `wrap_aad` = bytes[0..22] (magic, version, kind, file_id).
- `meta_aad` = magic | version | file_id (21 bytes, kind is NOT included). This lets an inbox file's `meta_blob` be copied unchanged into an object file during ingest.

Encryption:
- wrapped_fk = ChaCha20-Poly1305(K_wrap, wrap_nonce random, wrap_aad) of FK.
- meta_blob = ChaCha20-Poly1305(K_meta, random 12-byte nonce, meta_aad) of the padded metadata (section 5.2). Use a fresh random nonce every time the metadata is rewritten.

### 5.2 Metadata

Fields:

| Field | Type | Rule |
|---|---|---|
| `name` | string | Non-empty. Must not contain `/` or U+0000. Must not be `.` or `..`. |
| `dir` | string | `""` for the root, otherwise components joined by `/` with no leading or trailing `/`. Each component follows the `name` rules. |
| `mtime` | int64 | Unix time in nanoseconds. |
| `mime` | string | `""` if unknown. |
| `rev` | int64 | 1 when a file is created (also by the inbox server), incremented on every rewrite. Helps spot conflicts. |

Plaintext size is not stored (it is derived, see section 5.3).

Writers check that the input strings are valid UTF-8, normalize `name` and `dir` to NFC, then check the rules above.

Canonical serialization (byte-exact, produced by a hand-written serializer, never by JSONEncoder or encoding/json):
- `{"name":S,"dir":S,"mtime":I,"mime":S,"rev":I}`: keys in this order, no whitespace, UTF-8.
- S is a string: `"`, the content, `"`. Escape only `"` as `\"`, `\` as `\\`, and U+0000 to U+001F as `\u00xx` with lowercase hex. Everything else, including `/` and non-ASCII characters, is written as literal UTF-8.
- I is an integer: plain decimal, `-` for negative values, no leading zeros, no `+`, no fraction, no exponent.
- Then append spaces (0x20) until the length is a multiple of 512 (nothing if it already is). The padded plaintext is at most 65536 bytes; a writer fails if it would be larger.

Readers accept only the canonical form:
1. Check `meta_len` (section 5.1) and decrypt.
2. Remove trailing spaces. Fewer than 512 may have been removed (padding is minimal), and the padded length must be a multiple of 512.
3. Reject invalid UTF-8.
4. Parse with a small hand-written strict parser for exactly this schema. Reject duplicate keys, unknown keys, missing keys, wrong key order, any escape the writer does not emit, any whitespace outside the trailing padding, floats, leading zeros, and int64 overflow. `mtime` and `rev` are parsed as int64, never as float.
5. Check the field rules above, including that `name` and `dir` are already NFC. Readers do not re-normalize.
6. Re-serialize the parsed values; the result must equal the stripped plaintext byte for byte.

Adding a field requires a format version bump.

### 5.3 Content chunks

- Plaintext chunk size is 65536 bytes. Each chunk is stored as `ct | tag(16)`, so a stored chunk is at most 65552 bytes.
- All chunks are full size except the last, which is 1..65536 bytes. An empty file is exactly one empty final chunk (16 bytes: just the tag). A file whose length is an exact multiple of 65536 ends in a full final chunk, with no extra empty chunk.
- **Structural check**, run before any decryption (including unwrapping FK). `ct_total` = file length minus header length (86 + meta_len). Reject the file if any of these hold:
  - `ct_total < 16`
  - `ct_total mod 65552` is in [1, 15]
  - `ct_total mod 65552 == 16` and `ct_total != 16`

  `ct_total mod 65552 == 0` with `ct_total > 0` is valid (the final chunk is full). After the check, the number of chunks is `ceil(ct_total / 65552)`; every chunk but the last is 65552 bytes by construction.
- **Nonce (12 bytes)** = `u64 chunk_index (BE) | 0x00 0x00 0x00 | final_flag`, with final_flag 0x01 only on the last chunk. Safe because K_content is unique per file.
- **AAD** = file_id (16 bytes).
- Reader decides which chunk is last by the file length. A truncated file fails the structural check or authentication: a new "last" chunk was encrypted with the final flag clear. Reordering fails via the index in the nonce.
- Plaintext size = `ct_total - 16 * ceil(ct_total / 65552)`, for a `ct_total` that passed the structural check.
- When a file's content changes, generate a new FK. Never reuse an FK for different content.
- Streaming encryption needs a one-chunk lookahead, because the writer must know whether a chunk is the last one before encrypting it. Never buffer a whole file in memory.
- Streaming decryption hands out plaintext before later chunks are checked. The output is valid only if the whole file authenticates; write it to a temp file and discard it on failure.

## 6. Inbox file (kind 0x02), sealed to the vault

### 6.1 Format

Written by the server, which only knows `inbox_pub`.

```
offset  size       field
0       4          magic    "VALV"
4       1          version  0x01
5       1          kind     0x02
6       16         file_id  (server picks random)
22      32         eph_pub
54      4          meta_len
58      meta_len   meta_blob   (encrypted under K_meta from FK below, meta_aad)
...     ...        chunks      (identical format to objects)
```

Magic, version, `meta_len`, metadata and chunks follow sections 5.1 to 5.3, with header length 58 + meta_len in the structural check.

### 6.2 Server procedure per upload

1. Generate an ephemeral X25519 keypair. `DH = X25519(eph_priv, inbox_pub)`, with `inbox_pub` from the server's own configuration. Reject an all-zero result.
2. `FK = HKDF-SHA256(ikm=DH, salt=eph_pub | inbox_pub, info="valv/v1/inbox-fk", L=32)`.
3. Derive K_content and K_meta from FK as in section 3. Build the metadata as any writer does (section 5.2, `rev` = 1), encrypt it, and stream-encrypt the chunks as in section 5, with the inbox file_id.
4. Discard eph_priv and FK. After the upload completes the server can no longer decrypt the file.

### 6.3 Client ingest (holds VK)

1. Run the structural check. Derive the inbox private key from VK, compute DH with eph_pub (reject an all-zero result), derive FK.
2. Decrypt meta_blob and check it (section 5.2).
3. Write an object file under a `.part` name: same file_id, FK wrapped under K_wrap with a fresh random wrap_nonce, meta_blob copied verbatim, chunks copied byte for byte. The body is not re-encrypted. Every chunk is authenticated while streaming, before it is copied.
4. Only after every chunk has authenticated, finish the object in `objects/` (rename or final put), then delete the inbox file.

On any ingest failure, discard our own `.part` file, keep the inbox file, and report the error. Nothing in `inbox/` is ever deleted except after a fully verified successful ingest, or by the idempotency rule below.

Idempotency: if `objects/.../<file_id>.obj` already exists, treat the inbox file as already ingested only if (1) the existing object's unwrapped FK equals the FK derived from the inbox file (constant-time compare) AND (2) its chunk bytes are byte-identical to the inbox file's, which are authenticated during the comparison. `meta_blob` may differ (renames). If so, delete the inbox file. Otherwise report a conflict and delete nothing.

The inbox is anonymous. Anyone holding `inbox_pub` can drop files in, so authentication belongs to the transport (Tailscale-only, bearer token, or mTLS), not the file format.

## 7. Threat model

Protects against: a cloud provider, sync service, or compromised server reading file contents, names, or folder structure. A compromised server cannot read previously uploaded files. Any modification of a file is detected.

Leaks: object count, approximate sizes (granularity of one chunk), and modification times and access patterns visible to the host.

Does not protect against: malware on an unlocked device, a weak passphrase, losing the passphrase without the recovery key, or a host deleting or rolling back whole files (an old valid version can be restored, there is no freshness guarantee in v1).

## 8. Storage backends and deployment

The vault needs only four operations from its storage: `put(path, bytes)`, `get(path)`, `list(prefix)`, `delete(path)`. A rename is a bonus, not a requirement. Do not assume rename is atomic (Google Drive's is not). Do not assume file names are unique (Drive allows duplicates).

Rules that make this safe on dumb storage:
- Writers upload under `<name>.part` and finish with a rename (or a final put). Readers skip `*.part`.
- Readers treat any file that fails to parse or authenticate as "incomplete or corrupt": skip it, report it, retry later. Never delete it automatically.
- An unrecognized file in `objects/` or `inbox/` (e.g. "conflicted copy") must be surfaced to the user, not ignored or deleted.
- If duplicates of the same file_id appear, they are the same logical file. Delete a duplicate only if it is byte-identical to the one kept.

Deployment (v1, "mode B", chosen first):
- The server keeps the inbox on its own disk and holds no storage credentials.
- Your devices pull from it (over Tailscale or HTTPS), ingest, and write the objects into the real vault (e.g. a Google Drive folder).
- Minimal server API (all authenticated):
  - `PUT /inbox`: streaming upload. Metadata arrives in headers (name, dir, mtime, mime). Returns the file_id.
  - `GET /inbox`: list ids.
  - `GET /inbox/{id}`: download the sealed file.
  - `DELETE /inbox/{id}`: called by the client after a successful ingest.
- Later ("mode A", optional): the server writes `.inb` files directly into `vault/inbox/` on the real storage. No format change is needed. If you do this, give the server only a limited credential (e.g. Drive `drive.file` scope or a separate account with access to the inbox folder), because a compromised server could delete or overwrite files even though it can't read them.

## 9. Platform notes

- **iOS File Provider extensions have a tight memory limit.** Never run Argon2 inside the extension. Unlock in the main app, store VK in the Keychain via a shared access group, and let the extension read it from there.
- Mac: no virtual drive in v1. Start with a CLI, then a simple app (unlock, browse, add, open). Consider loopback WebDAV or a File Provider later.
- Keep the core as a library with no UI dependencies, so the CLI, the server, and the apps all reuse it.

## 10. Implementation rules (for the AI writing the code)

1. Use only the primitives in section 2. Do not add, swap, or "improve" any of them.
2. Do not invent nonce logic beyond section 5. Never reuse an FK. Never use random nonces for chunks.
3. Every AEAD call uses exactly the AAD defined above. Never skip the AAD.
4. Compare secrets in constant time, wipe key material where feasible, never log keys, passphrases, FKs, or plaintext.
5. Parse defensively: bounds-check meta_len (section 5.1), offsets, and chunk counts before allocating.
6. File names on storage never derive from plaintext names. file_id is always random.
7. Do not edit files in place. Write temp, then rename or replace.
8. When the spec is ambiguous, stop and ask. Do not guess.
9. Fixed keys, nonces and ids exist only in test code behind the `valv_testvectors` build tag. Release builds contain no way to inject a random source or fixed values, and a test checks this.

## 11. Build order

1. **Spec + test vectors.** A reference generator (Go), in test-only code behind the `valv_testvectors` build tag, with fixed seeds (fixed VK, file_ids, FKs, nonces). Regenerating needs `-tags valv_testvectors`; the verification and negative tests read the committed vector files and run without the tag. Vector files give every field in hex; vault.json is also committed as-is (base64 as the format requires) with a hex breakdown next to it.
   - Positive vectors: vault.json, recovery key, a tiny object, a multi-chunk object (3 full chunks plus a partial), an exact-multiple-of-chunk-size object, an empty file, an inbox file and the object produced by ingesting it, and metadata encodings using å, ä, ö, é, a Hangul syllable, and one NFD input that must come out as NFC. At least one mtime is above 2^53.
   - Negative vectors: flipped bit, truncated final chunk, truncated at a chunk boundary, dropped middle chunk, swapped chunks, wrong passphrase, wrong file_id, tampered header; each of the three structural-check rejections (section 5.3); metadata with a duplicate key, invalid UTF-8, wrong key order, an extra key, an escaped `/`, a float mtime, a leading zero, non-space padding, an NFD name.
   - Round trips for 0, 1, 65535, 65536, 65537 bytes and 3 full chunks + 1 byte.
2. **Go core library + CLI**: `init`, `add`, `ls`, `get`, `ingest`, `rekey-passphrase`.
3. **Swift core library**: must decrypt every Go vector and re-encrypt to identical bytes.
4. **Inbox server (Go)**: streaming upload, seal, store. API from section 8.
5. **Mac app.**
6. **iPhone app + File Provider extension.**

Do not start step N+1 until step N passes its tests. Not trustworthy with only-copy data until someone credible has reviewed the crypto.

## 12. Open questions

- Deletion semantics: tombstones vs plain delete, and what happens when sync resurrects a deleted file.
- Optional padding to hide exact file sizes.
- Whether the Mac app uses loopback WebDAV or a File Provider (iOS needs a File Provider regardless).
- Conflict policy when two devices rewrite the same file_id (use `rev`; probably keep both, surface to the user).

## 13. Resolved decisions

A log of what was decided after the first draft and where each rule now lives. The rule itself is only in the section named.

| # | Decision | Section |
|---|---|---|
| 1 | Binary encoding of the KDF parameters in `config_aad` | 4.2 |
| 2 | Canonical metadata serialization, hand-written serializer | 5.2 |
| 3 | Metadata field types and rules, NFC on write | 5.2 |
| 4 | 64 KiB metadata cap applies after padding; `meta_len` bounds | 5.1, 5.2 |
| 5 | Base64: standard alphabet, padded | 4.2 |
| 6 | Empty HKDF salt for all derivations from VK and FK | 3 |
| 7 | Recovery key: RFC 4648 base32 only, grouped, lenient input | 3 |
| 8 | Ingest idempotency (refined by F) | 6.3 |
| 9 | Ingest authenticates every chunk; discard `.part` on failure | 6.3 |
| 10 | Reader length rules (refined by D) | 5.3 |
| 11 | Unlock checks `inbox_pub`; server gets it from its own config | 3, 4.3 |
| 12 | Strict KDF parameters and `v == 1` | 4.2 |
| A | Old "exists and verifies" ingest rule removed | 6.3 |
| B | Inbox files are kept on any ingest failure | 6.3 |
| C | Word-list recovery key option removed | 3 |
| D | Structural length check on `ct_total` before decryption | 5.3 |
| E | NFC library as the one non-crypto dependency | 2 |
| F | Already-ingested means equal FK and identical chunks | 6.3 |
| G | `inbox_pub` bound into `config_aad`; recovery-key unlock procedure | 4.2, 4.3 |
| H | Unlock and `init` verify `inbox_pub` | 4.3 |
| I, K | Canonical-form-only metadata readers; new fields need a version bump | 5.2 |
| J | Non-empty names; same rules for `dir` components | 5.2 |
| L | Deterministic values only behind the `valv_testvectors` build tag | 10, 11 |
| M | Fresh salt and wrap nonce on every passphrase change | 4.4 |
| N | Vector file format; an mtime above 2^53 | 11 |

## 14. Changelog from the original draft

- Section 2: added the NFC normalization dependency; noted libsodium's p=1 support.
- Section 3: HKDF salt rule for all derivations; clamping spelled out; `inbox_pub` binding and server configuration; recovery key fixed to base32 (word list removed) with exact format and input rules.
- Section 4: split into 4.1 to 4.4. vault.json gained a byte-exact writer format, strict parameter and length rules, canonical-only readers, and `inbox_pub` in `config_aad` with an exact byte layout. New unlock, init, recovery-key and passphrase-change procedures.
- Section 5: `meta_len` bounds and version/kind handling (5.1). Metadata rewritten as 5.2: field rules, NFC, canonical serialization, minimal padding, canonical-only strict readers (replaces "pad to 512, max 64 KiB" and the implied "ignore unknown keys"). Chunks (5.3): structural check before decryption, "truncated file fails the structural check or authentication", note on streaming decryption output.
- Section 6: split into 6.1 to 6.3. Ingest now authenticates every chunk (was "at least the first and last"), keeps the inbox file on failure, and uses the FK-and-chunks idempotency rule (replaces "exists and verifies, just delete the inbox file"). Server takes `inbox_pub` from its config and writes `rev` = 1.
- Section 10: rule 5 points to the exact `meta_len` bounds; new rule 9 on test-only deterministic values.
- Section 11: step 1 lists the full positive and negative vector set, the vector file format, and the build tag.
- Sections 13 and 14 added.
