# NdesCore (Swift)

The Swift core library for ndes, SPEC.md section 11 step 3. It is an
independent implementation written from SPEC.md and `testvectors/` only, and
it must agree with the Go implementation byte for byte.

Library only: no UI, File Provider, Keychain, server, directory walking, junk
lists or no-replace moves.

## Build and test

```sh
swift build
./scripts/test.sh                    # swift test --traits NDES_TESTVECTORS (+ CLT paths)
./scripts/check-release-symbols.sh   # release build has no test hook
```

`scripts/test.sh` adds the Swift Testing framework paths when only the Command
Line Tools are installed. With Xcode, `swift test --traits NDES_TESTVECTORS`
works directly. Without the trait the suite still runs; the four tests that
re-encrypt vectors from fixed values are compiled out.

## Dependencies

- CryptoKit: ChaChaPoly, HKDF<SHA256>, SHA256, Curve25519.KeyAgreement.
- Foundation: NFC (`precomposedStringWithCanonicalMapping`), FileHandle.
- Security: `SecRandomCopyBytes`, the only randomness source.
- [swift-sodium](https://github.com/jedisct1/swift-sodium), product
  `Clibsodium` only, pinned to revision
  `cfd195c76882aa9b997560ca7cb95d72fbf5db00` (bundles libsodium 1.0.22 as a
  prebuilt xcframework with macOS and iOS slices). Used **only** for
  `crypto_pwhash` with `crypto_pwhash_alg_argon2id13()`, opslimit 3, memlimit
  67108864 bytes, 16-byte salt, 32-byte output; libsodium's Argon2id always
  uses one lane (p = 1). The Swift `Sodium` wrapper is not used, so the
  passphrase is passed to C without extra copies.

## API outline

- `VaultConfig.parse(_:)`, `serialized()`: strict vault.json.
- `Vault.unlock(vaultJSON:passphrase:)` / `(vaultJSON:passphraseUTF8:)`: runs
  Argon2id. `Vault.create(passphrase:)` and `makeVaultJSON(passphrase:)`
  (passwd, recover) also run it. Nothing else does.
- `Vault(vk:vaultJSON:)`: raw VK, no Argon2 (File Provider via Keychain,
  SPEC 9). `exportVK()` returns the bytes to store.
- `Vault(recoveryKey:)`, `vault.recoveryKey`,
  `Vault.unlock(vaultJSON:recoveryKey:sampleObject:)` (SPEC 4.3),
  `vault.verifyRecoveredKey(objects:inboxFiles:)` (SPEC 4.5 cases 1 to 4).
- `Metadata`: writer init (UTF-8 check, NFC, rules), `canonicalJSON()`,
  `paddedPlaintext()`, `Metadata.parse(padded:)` (strict, hand-written).
- `FileID(objectPath:)`, `FileID(inboxPath:)`: the expected file_id from a
  path. Every reader takes one.
- `vault.openObject`, `decryptObject`, `verifyObject`, `writeObject`.
- `vault.makeInboxSealer().seal`, `vault.openInbox`, `vault.ingest`,
  `vault.compareIngested` (already-ingested rule).

I/O goes through `NdesInput`/`NdesOutput` (`FileInput`, `FileOutput`,
`DataInput`, `DataOutput`, `DiscardOutput`). Readers request at most one stored
chunk (65552 bytes) per read; writers keep at most two plaintext chunks (the
one-chunk lookahead). `FileInput` and `FileOutput` drain an autorelease pool
per call, because `FileHandle` returns autoreleased buffers; without that,
memory grew with file size (see `../interop/RESULTS.md`, Memory). Peak
footprint is about 3 MiB for any file size via `Vault(vk:)`, and about 66 MiB
with a passphrase unlock (Argon2id).

No public function takes a key, nonce, salt, or random source, with two
deliberate exceptions: `Vault(vk:)` (required by SPEC 9) and the recovery-key
string. Readers take an *expected* file_id, which comes from a path; writers
always generate the file_id themselves.

## Interop with the Go CLI

`ndes-swift-tool` is a test aid with no safety features (no temp files, no
outside-the-vault checks). The passphrase comes from stdin only, one line.

```sh
ndes-swift-tool decrypt-object <vault.json> <object-file> <out>
ndes-swift-tool encrypt-object <vault.json> <in> <out-object> --name N --dir D
ndes-swift-tool seal-inbox     <vault.json> <in> <out-inbox>  --name N --dir D
ndes-swift-tool init           <vault-dir>
ndes-swift-tool unlock         <vault.json>
ndes-swift-tool show-meta      <vault.json> <object-file>
ndes-swift-tool show-keys      <vault.json>   # only with --traits NDES_TESTVECTORS
```

`show-keys` prints `inbox_pub`, `k_auth`, the recovery key and VK. Also only
in test builds, `decrypt-object` and `encrypt-object` accept `--vk-stdin` (VK
as hex on stdin, opened with `Vault(vk:)`, no Argon2) for memory measurement.
Both are compiled only with the test trait, and the release check verifies
that a normal build of the tool rejects them.

`encrypt-object` and `seal-inbox` print the new file_id; the caller moves the
file to `objects/<xx>/<id>.obj` or `inbox/<id>.inb`. `seal-inbox` exists for
check (c) below.

`../interop/run.sh` builds the Go CLI from `cmd/ndes` and this tool, creates a
temp vault with `ndes init --passphrase-stdin`, and checks with files of 0, 1,
65536 and 200000 bytes: (a) `ndes add` output decrypts in Swift to identical
bytes; (b) Swift objects pass `ndes verify` and come back identical from
`ndes get`; (c) Swift-sealed inbox files ingest with `ndes ingest` and come
back identical from `ndes get` and from Swift; (d) one vault.json unlocks in
both and `inbox_pub`, `k_auth` and the recovery key agree; (e) vaults created
by either side are accepted by the other; (f) names with å, é and Hangul
round-trip and NFD input is stored as NFC. The passphrase is random, kept in a
0600 temp file and passed on stdin only; keys are compared with `cmp` and never
printed. Results: `../interop/RESULTS.md`.

## Test-only randomness

Fixed values enter only through `TestHooks.withFixedRandom`, compiled only with
the `NDES_TESTVECTORS` package trait (not a default trait). The hook is
task-local, so parallel tests cannot see each other's values.
`scripts/check-release-symbols.sh` builds in release mode without the trait,
fails if any hook symbol is present, and runs a control build with the trait to
prove the check can fail.

## Memory wiping: what Swift can and cannot do

Honest limits:

- **Passphrases as `String` cannot be wiped.** Swift strings are immutable
  values with opaque storage; NFC normalization bridges through NSString and
  makes more copies. The normalized UTF-8 bytes handed to Argon2 are a
  `[UInt8]` that is wiped with `memset_s` after use. Callers that read the
  passphrase as bytes should use `unlock(vaultJSON:passphraseUTF8:)` and wipe
  their own buffer; the String detour inside NFC still leaves copies.
- **Keys** live in CryptoKit `SymmetricKey` and `Curve25519` key objects,
  whose storage CryptoKit manages (and, per its implementation, zeroes on
  deallocation; this is not something NdesCore can verify). Where the format
  needs raw key bytes (wrapping FK or VK, the inbox HKDF input `DH | K_auth`,
  the recovery-key encoding) a temporary `[UInt8]` is made and wiped. AEAD
  `open` returns the unwrapped VK/FK as a `Data`, which is wiped after it is
  turned into a `SymmetricKey`.
- **Copies the code cannot reach:** copy-on-write may have duplicated an array
  before it is wiped; CryptoKit and Foundation make internal copies; the
  64 MiB Argon2 work area belongs to libsodium.
- **Plaintext chunks** are ordinary `Data` and are not wiped.
- Nothing is `mlock`ed, so key material can reach swap.
- The base32 recovery-key decoder branches on character class, which is a
  minor timing signal on secret input; checksum and every tag or secret
  comparison use a constant-time comparison.

## Swift traps handled

- `Data` slices keep their parent's indices: all parsing works on zero-based
  `[UInt8]` copies.
- String equality and `contains` follow canonical equivalence and grapheme
  clusters (`"/"` + U+0301 is one Character, not `"/"`): every metadata rule
  is checked on UTF-8 bytes.
- `ChaChaPoly.SealedBox(nonce:ciphertext:tag:)` is used, never `combined`.
- CryptoKit's empty HKDF salt equals 32 zero bytes (tested against K_wrap).
- X25519: the all-zero shared secret is rejected explicitly.
- All lengths are `Int64` with checked arithmetic; `mtime` and `rev` are parsed
  as `Int64` (Int64.min accepted, overflow rejected), never via `Double`.
