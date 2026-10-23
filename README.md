<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Lagom-8a7bd8" alt="License: The Lagom License"></a>
  <img src="https://img.shields.io/badge/macOS%2014%2B-Apple%20silicon-444" alt="macOS 14 or later, Apple silicon">
</p>

<h1 align="center">send n*des</h1>

<p align="center">
  <b>A private vault for your files, and an inbox your devices can drop them into.</b><br>
  Contents, names and folders stay encrypted, wherever the vault is stored or synced.
</p>

<h2 align="center">
  <a href="https://klppl.github.io/sendndes/">Visit the website &rarr;</a>
</h2>

<p align="center">
  <img src="docs/screenshots/mac-vault.png" alt="The send n*des Mac app showing an unlocked vault with five files" width="760">
</p>

<p align="center">
  <a href="https://github.com/klppl/sendndes/releases/latest"><b>Download for Mac</b></a> ·
  <a href="https://klppl.github.io/sendndes/guide/">Guide</a> ·
  <a href="SPEC.md">Format spec</a>
</p>

> **Made by machines, for one person.** Designed and written by AI, attacked by other AI reviewers, and cross-checked by three independent implementations (Go, Swift, Python) that agree byte for byte. No human cryptographer has audited it, and none is planned. There are no promises here about anyone else's data. Keep a plaintext backup of anything you can't lose.

## How it works

A **vault** is a folder of encrypted files. Keep it anywhere: your Mac, a NAS, Google Drive, Dropbox. Whoever stores or syncs it sees only ciphertext.

An optional **inbox server** lets your other devices send files into the vault. It is write-only and can never read anything.

```
 Mac / iPhone ──encrypt on the device──> inbox server
                                              │
 Mac app ──pull, decrypt, file by name────────┘──> vault folder
```

| Piece | What it does |
|---|---|
| **Mac app** | Create, unlock and browse the vault. Touch ID, Quick Look, auto-lock. Pulls in what the inbox received. |
| **iPhone app** | Send-only. Share photos and files from any app; they are encrypted on the phone. |
| **Inbox server** (`ndesd`) | The drop box. Runs in Docker or as a Linux binary. |
| **CLI** (`ndes`) | Everything the Mac app does, plus verify, recover and change passphrase. |

## Get started

1. **Install the Mac app.** [Download the latest release](https://github.com/klppl/sendndes/releases/latest), open the disk image and drag it to Applications. It is signed and notarized by Apple.
2. **Create a vault.** Open the app and choose *Create a vault*. Write down the recovery key; it is shown once.
3. **Add an inbox (optional).** Run the server on a machine that stays on (from a clone of this repo, or with the prebuilt image in the guide), then connect the Mac app to it:

   ```bash
   docker compose up -d
   docker compose logs ndesd     # shows the one-time setup code
   ```

4. **Add your iPhone (optional).** Build it from `ios/` with your own signing team, then pair it by scanning the QR code in the Mac app.

The [guide](https://klppl.github.io/sendndes/guide/) walks through each step with screenshots, plus troubleshooting.

<details>
<summary>Build from source</summary>

You need Go 1.27.3+ and Swift.

```bash
go build -o ndes ./cmd/ndes     # CLI
scripts/build-app.sh            # Mac app -> build/sendndes.app
scripts/build-linux.sh          # server and CLI binaries -> dist/
```

</details>

## What it protects

- **Encrypted:** file contents, names and folder structure, against the storage host, the sync service and the inbox server. Any tampering is detected.
- **Visible to the host:** how many files there are, roughly how big (sizes are padded), and modification times.
- **Not protected:** malware on an unlocked device, a weak passphrase, losing both passphrase and recovery key, or a host deleting files or rolling them back.

Argon2id for the passphrase, ChaCha20-Poly1305 for content, X25519 for inbox uploads. Full threat model: [SPEC.md §7](SPEC.md).

## Development

```bash
go test ./...                # core, CLI, server
scripts/test-app.sh          # Mac app core tests
```

`core/` Go reference implementation · `cmd/` CLI and server · `app/` Mac app · `ios/` iPhone app · `swift/NdesCore` Swift implementation · `testvectors/` shared vectors · `coordination/` design notes. More in [app/README.md](app/README.md).

## License

[The Lagom License](LICENSE) ([klppl.github.io/lagom-license](https://klppl.github.io/lagom-license/)). Copyright (c) 2026 klppl.
