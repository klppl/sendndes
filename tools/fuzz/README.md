# Differential fuzzer (Go core vs Swift NdesCore)

Mutates the files in `testvectors/` and checks that the Go library and the Swift library accept and reject exactly the same inputs (SPEC §10 rule 10, D-Q6). When both accept, it also checks that both produce the same output.

## Provenance (read this first)

This is the REVIEWER's library-mode harness as it was on disk in `/tmp/valv-reviewer/` on 2026-10-19. The files there were last modified at 17:09–17:19, which is **before** the F1 commits (`5b18e4d`, `0790469`, 20:53–20:54). So this is most likely the round-1 harness, not the F1 version:

- It still contains the helpers TASKS.md F1 says were removed: `metaSummary` (metadata compared as a SHA-256 over `name|dir|mtime|mime|rev`), `fileIDFromBytes` and `hexDecode` in the Swift worker. Outputs are compared as SHA-256 digests, not byte for byte.
- The **CLI mode** reported in F1 (2,000 cases running the real `ndes` CLI and `ndes-swift-tool` as subprocesses) is not here. It was not found anywhere under `/tmp`. It is lost and would have to be rewritten.

Changes made when committing: the hard-coded paths (`/Users/...`, `/tmp/valv-reviewer/...`) were replaced with relative paths and two flags (`-worker`, `-repo`). Nothing else changed. A one-off debug file (`test-idemp.go`) and build outputs were not committed.

No secrets: the only key in the code is the test-vector VK, which is public in `testvectors/vectors.json`.

## How it calls each implementation

- **Go:** in-process calls to `github.com/klppl/sendndes/core` (via a `replace` to this repo): `ParseConfig`, metadata decoding, `DecryptObject`, `IngestInbox`, `DecodeRecoveryKey`, `ParseObjectPath`/`ParseInboxPath`, `CheckAlreadyIngested`.
- **Swift:** one long-running `SwiftHarness` process linked against `swift/NdesCore`. The Go side writes `[cmd byte][u32 big-endian length][payload]` to its stdin and reads `[status byte][u32 length][data]` from its stdout. Commands 1–9 map to `VaultConfig.parse`, `Metadata.parse`, `vault.decryptObject`, `vault.openInbox`+`decryptAll`, `vault.ingest` (then decrypt), `Vault(recoveryKey:)`, `FileID(objectPath:)`, `FileID(inboxPath:)`, `vault.compareIngested`.
- Both sides use the pre-derived VK from the test vectors, so there is no Argon2id in the loop. The RNG seed is fixed (`0x5EED`), so runs are repeatable.

## Run

From the repo root (needs Go and Swift; Swift fetches `swift-sodium`, the existing NdesCore dependency, if it is not cached):

```bash
swift build -c release --package-path tools/fuzz/swift-harness --scratch-path /tmp/ndes-fuzz/swift
(cd tools/fuzz/go-fuzzer && go build -o /tmp/ndes-fuzz/fuzzer .)
(cd tools/fuzz/go-fuzzer && /tmp/ndes-fuzz/fuzzer -worker /tmp/ndes-fuzz/swift/release/SwiftHarness)
```

`-repo` defaults to `../../..` (the repo root, seen from `go-fuzzer/`). Expected end: `Total mismatches: 0`. Last run on 2026-10-19: 25,000 inputs, 0 mismatches, 3.8 s.

`tools/fuzz/go-fuzzer` is its own Go module, so `go test ./...` at the repo root does not include it.
