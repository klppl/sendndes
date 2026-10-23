<h1 align="center">send n*des</h1>

<p align="center">
  <b>A private vault for your files, and an inbox your devices can drop them into.</b><br>
  Contents, names and folders stay encrypted, wherever the vault is stored or synced.
</p>

<p align="center">
  <img src="docs/screenshots/mac-vault.png" alt="The send n*des Mac app showing an unlocked vault with five files" width="760">
</p>

<p align="center">
  <a href="https://github.com/klppl/sendndes/releases/latest"><b>Download for Mac</b></a> (Apple silicon, macOS 14+, signed and notarized)<br>
  <a href="https://klppl.github.io/sendndes/">Website</a> · <a href="https://klppl.github.io/sendndes/guide/">Guide</a> · <a href="SPEC.md">Format spec</a>
</p>

> **Made by machines, for one person.** This was designed and written by AI, carefully, then attacked by other AI reviewers and cross-checked by three independent implementations (Go, Swift, Python) that agree byte for byte. No human cryptographer has audited it, and none is planned. It was built to satisfy its creator, nobody else, so there are no promises here about anyone else's data. Everything is entropy in the end, ciphertext included. Keep a plaintext backup of anything you can't lose anyway.

## What's in the box

| Piece | What it does |
|---|---|
| **Vault** | A folder of encrypted files. Put it anywhere: this Mac, a NAS, Google Drive, Dropbox. Whoever hosts or syncs it sees only ciphertext. |
| **Mac app** | Create, unlock and browse the vault; send files to your inbox server. |
| **iPhone app** (`ios/`) | Send-only: share photos and files from any app to your inbox. |
| **Inbox server** (`ndesd`) | A write-only drop box your devices send to. It can never read the vault. |
| **CLI** (`ndes`) | Everything the app does, plus verify, recover and change the passphrase. |

Runs on macOS and Linux (not Windows), plus iOS for the phone app.

## Get started

Download the Mac app from the [latest release](https://github.com/klppl/sendndes/releases/latest), or build everything from source (Go 1.27.3+ and Swift):

```bash
go build -o ndes ./cmd/ndes     # CLI
scripts/build-app.sh            # Mac app -> build/sendndes.app
docker compose up -d            # inbox server (optional)
```

Setting up the server, the iPhone app and troubleshooting are in the [guide](https://klppl.github.io/sendndes/guide/). The threat model is in [SPEC.md §7](SPEC.md); app details in [app/README.md](app/README.md).

## Development

```bash
go test ./...                # Go: core, CLI, server
scripts/test-app.sh          # Mac app core tests
```

Layout: `core/` (Go reference implementation), `cmd/` (CLI and server), `app/` (Mac app), `ios/` (iPhone app), `swift/NdesCore` (Swift implementation), `testvectors/`, `coordination/` (design notes).

## License

[The Lagom License](LICENSE) ([klppl.github.io/lagom-license](https://klppl.github.io/lagom-license/)). Copyright (c) 2026 klppl.
