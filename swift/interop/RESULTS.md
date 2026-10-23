# Interop results: Go CLI and Swift ValvCore

Run of `swift/interop/run.sh` on 2026-10-19.

## Environment

| | |
|---|---|
| Go code | built from `cmd/valv` at repository commit `08056fba3701dda17babb135798b8164e922eb1d` (main). `core/`, `cmd/`, `go.mod` and `go.sum` last changed in `f5fb8e6df0be0106adb14764707ce49fd47e3609` (the v1 format freeze). |
| Go | go1.26.3 darwin/arm64 |
| Swift | Apple Swift 6.4 (swiftlang-6.4.0.34.1), Xcode 27.1 (27A9275) |
| OS | macOS 26.6.2, arm64 |
| Argon2id | libsodium 1.0.22 via swift-sodium `Clibsodium`, revision `cfd195c76882aa9b997560ca7cb95d72fbf5db00` |

The Swift unit tests (55 with `VALV_TESTVECTORS`, 51 without) also pass.
`xcodebuild -scheme ValvCore -destination 'generic/platform=iOS' build`
succeeds under Xcode 27.1.

## Checks

Sizes for (a) to (c): 0, 1, 65536 and 200000 bytes.

| Check | Result |
|---|---|
| (a) Go `valv add` writes objects, Swift decrypts each to identical bytes (4 sizes) | PASS |
| (b) Swift writes objects; `valv verify` reports 0 problems | PASS |
| (b) `valv get` returns each Swift object identical (4 sizes) | PASS |
| (c) Swift seals inbox files; `valv ingest`: "ingested 4, already ingested 0, failed 0"; inbox empty afterwards | PASS |
| (c) each ingested object identical via `valv get` and via Swift (4 sizes) | PASS |
| (d) Go unlocks the vault.json made by `valv init` | PASS |
| (d) Swift unlocks the same vault.json with the same passphrase | PASS |
| (d) `inbox_pub`: Go `server-config` equals Swift | PASS |
| (d) `k_auth`: Go `server-config` equals Swift | PASS |
| (d) `inbox_pub` equals the value stored in vault.json | PASS |
| (d) recovery key printed by `valv init` equals Swift's encoding of VK | PASS |
| (e) Swift creates a vault (vault.json, `objects/`, `inbox/`) | PASS |
| (e) `valv ls` accepts the Swift vault.json, empty vault, empty listing | PASS |
| (e) `valv add` into the Swift vault, then `valv ls` lists exactly that file | PASS |
| (e) Swift vault: `valv verify` 0 problems; `valv get` and Swift decrypt identical | PASS |
| (e) Swift vault: `inbox_pub` and `k_auth` agree between Go and Swift, `inbox_pub` equals vault.json | PASS |
| (e) Swift accepts the vault made by `valv init` (unlock and decrypt) | PASS |
| (f) NFC input, Go writes: stored NFC, Swift reads exact bytes, `valv get` by NFC path | PASS |
| (f) NFC input, Swift writes an object: stored NFC, `valv ls` and `valv get` by NFC path | PASS |
| (f) NFD input, Go writes: stored as NFC | PASS |
| (f) NFD input, Swift writes an object: stored as NFC | PASS |
| (f) NFC input, Swift-sealed inbox file ingested by Go: stored NFC | PASS |
| (f) NFD input, Swift-sealed inbox file ingested by Go: stored as NFC | PASS |
| (f) no stored name or dir contains a combining accent (`valv ls`) | PASS |
| Final `valv verify` over the whole Go vault: 18 objects, 0 problems | PASS |

(f) uses the name `café å 한` and the dir `Hem/Kök/한국`, each with a
writer-specific suffix. The NFD form uses combining U+0301, U+030A and U+0308
and conjoining Hangul jamo (U+1112 U+1161 U+11AB, U+1100 U+116E U+11A8). The
stored name and dir are compared byte for byte (UTF-8 hex from `show-meta`)
with the NFC form.

## Divergences

None.

## Limits of these checks

- The recovery key is compared only for the Go-created vault: the Go CLI
  prints it only at `valv init`, so there is no Go output to compare for the
  Swift-created vault. That vault's recovery key is covered by the Swift unit
  tests (encode/decode and the vector `recovery_key`).
- Keys are compared with `cmp` on 0600 files in the run's temp directory and
  never printed. Printing them needs the `show-keys` command, which exists only
  in a build with `--traits VALV_TESTVECTORS`;
  `swift/ValvCore/scripts/check-release-symbols.sh` checks that a normal
  release build of the tool rejects `show-keys` and contains no key-export
  symbols.

## Tool commands added for (d) to (f)

- `init <vault-dir>`: creates vault.json (read back and unlocked), `objects/`
  and `inbox/`. Prints nothing.
- `unlock <vault.json>`: prints `unlocked` on success.
- `show-meta <vault.json> <object-file>`: authenticates the object and prints
  the stored name and dir as UTF-8 hex and whether they are NFC. Metadata only,
  no keys.
- `show-keys <vault.json>`: test-only (trait `VALV_TESTVECTORS`). Prints
  `inbox_pub`, `k_auth` in the same lines as `valv server-config`, and
  `recovery_key`.

## iOS builds (2026-10-19, Xcode 27.1, build 27A9275, iOS SDK 27.1)

Run in `swift/ValvCore`:

| Command | Result |
|---|---|
| `xcodebuild -scheme ValvCore -destination 'generic/platform=iOS' clean build` | BUILD SUCCEEDED, 0 warnings |
| `xcodebuild -scheme ValvCore -destination 'generic/platform=iOS Simulator' clean build` | BUILD SUCCEEDED, 0 warnings |
| `xcodebuild -scheme ValvCore-Package -destination 'generic/platform=iOS Simulator' build-for-testing` | TEST BUILD SUCCEEDED |
| `xcodebuild -scheme ValvCore-Package -destination 'platform=iOS Simulator,name=iPhone 17' test` | not run: no iOS Simulator runtime is installed (`xcrun simctl list runtimes` is empty), so there is no device |

No warning mentions concurrency, Sendable or a deprecated API. (The only log
lines containing "concurrency" are the module name `_SwiftConcurrencyShims` in
build steps.) The package builds in Swift 6 language mode with strict
concurrency checking.

To run the unit tests on a simulator, install a runtime first
(`xcodebuild -downloadPlatform iOS`, several GB), then use the `test` command
above. Note that xcodebuild does not enable the `VALV_TESTVECTORS` trait, so a
simulator run would execute the 51 tests that do not need it.

## Memory (`swift/interop/measure-memory.sh`, release build, macOS arm64)

Peak memory footprint and maximum resident set size from `/usr/bin/time -l`.
"passphrase" opens the vault with Argon2id first, as the main app would; "vk"
uses `--vk-stdin` (test build only), which calls `Vault(vk:)` with no Argon2,
as a File Provider extension would.

| Step | 50 MB (footprint / RSS) | 500 MB (footprint / RSS) |
|---|---|---|
| unlock alone (passphrase, Argon2id) | 65.7 MiB / 70.1 MiB | — |
| encrypt (passphrase) | 65.7 MiB / 70.2 MiB | 65.7 MiB / 70.2 MiB |
| decrypt (passphrase) | 65.7 MiB / 70.1 MiB | 65.7 MiB / 70.1 MiB |
| encrypt (vk, no Argon2) | 3.7 MiB / 9.5 MiB | 3.6 MiB / 9.4 MiB |
| decrypt (vk, no Argon2) | 3.5 MiB / 9.1 MiB | 3.5 MiB / 9.2 MiB |

Peak memory does not grow with file size; the script fails if a 500 MB run
uses more than 4 MiB above the 50 MB run. Using `Vault(vk:)` saves the
extension about 62 MiB, all of it Argon2id's 64 MiB work area.

### Divergence found and fixed: memory grew with file size

The first measurement, before the fix:

| Step | 50 MB | 500 MB |
|---|---|---|
| encrypt (vk) | 50.7 MiB | 482.3 MiB |
| decrypt (vk) | 62.7 MiB | 604.3 MiB |

Cause: `FileHandle.read(upToCount:)` returns autoreleased buffers. ValvCore's
`FileInput.read` called it once per chunk inside one long loop with no
autorelease pool, so every chunk stayed alive until the process ended. A File
Provider extension would hit the same thing, since a GCD work item drains its
pool only when the whole operation finishes. A standalone loop over a 300 MB
file showed it (peak RSS):

| Loop body | no pool | `autoreleasepool` per iteration |
|---|---|---|
| `read(upToCount: 65536)` only | 293.5 MiB | 6.3 MiB |
| read + `write(contentsOf:)` | 293.5 MiB | 6.3 MiB |
| read + ChaChaPoly.seal + write | 294.1 MiB | 7.0 MiB |

Fix (library only, no format change): `FileInput.read` and `FileOutput.write`
in `Sources/ValvCore/IO.swift` now wrap each call in `autoreleasepool`. The
chunking logic was already bounded (at most two plaintext chunks when writing,
one stored chunk per read). After the fix the unit tests (55), `run.sh` (all
checks) and both iOS builds pass again.
