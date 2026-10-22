<h1 align="center">send n*des</h1>

<p align="center">
  <b>A private vault for your files, and an inbox your devices can drop them into.</b><br>
  Contents, names and folders stay sealed, wherever the vault is stored or synced.
</p>

<p align="center">
  <img src="docs/screenshots/mac-vault.png" alt="The send n*des Mac app showing an unlocked vault with five files" width="760">
</p>

> **Made by machines, for one person.** This was designed and written by AI, carefully, then attacked by other AI reviewers and cross-checked by three independent implementations (Go, Swift, Python) that agree byte for byte. No human cryptographer has audited it, and none is planned. It was built to satisfy its creator, nobody else, so there are no promises here about anyone else's data. Everything is entropy in the end, ciphertext included. Keep a plaintext backup of anything you can't lose anyway.

## What's in the box

| Piece | What it does |
|---|---|
| **Vault** | A folder of sealed files. Put it anywhere: this Mac, a NAS, Google Drive, Dropbox. Whoever hosts or syncs it sees only ciphertext. |
| **Mac app** (`send n*des`) | Create, unlock and browse the vault; add, Quick Look, open and export files; send files to your inbox server. |
| **Inbox server** (`ndesd`) | A write-only drop box your devices send to, with a web admin page. It seals each file for your vault and can never read the vault. |
| **CLI** (`ndes`) | Everything the app does, plus verify, recover and change the passphrase. |

```
 Mac / phone ──send──> ndesd inbox (seals each file for the vault)
                              │
 Mac app or ndes ──pull───────┘──> vault folder (local, NAS, Drive, Dropbox…)
```

Runs on macOS and Linux (not Windows). The format has two independent implementations, Go and Swift, that agree byte for byte ([SPEC.md](SPEC.md)).

## The Mac app

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/mac-welcome.png" alt="Welcome screen with Create a vault and Open a vault"></td>
    <td width="50%"><img src="docs/screenshots/mac-locked.png" alt="Lock screen asking for the passphrase"></td>
  </tr>
  <tr>
    <td><b>First launch.</b> Create a vault or open one you already have.</td>
    <td><b>Locked.</b> Passphrase or Touch ID. Switch between recent vaults from the folder menu.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/mac-vault.png" alt="Unlocked vault with a file selected"></td>
    <td><img src="docs/screenshots/mac-send-setup.png" alt="Send screen asking for the server address and access token"></td>
  </tr>
  <tr>
    <td><b>Unlocked.</b> Drop files in, press Space for Quick Look, export when you need a copy. Files that arrived from the inbox are tagged <i>new</i>.</td>
    <td><b>Send.</b> Works while the vault is locked: connect your inbox server once, then drop files.</td>
  </tr>
</table>

- Locks after inactivity (1–120 min), and at once on sleep, screen lock or user switch.
- Unlocking checks the inbox and brings new files in by itself (can be turned off in Settings).
- The recovery key is shown once at creation; you confirm three random groups of it before you can continue.
- Keyboard: ⌘O add, ⌘R refresh, ⇧⌘I check inbox, ⌘L lock, ⌘, settings.

## The inbox server

<table>
  <tr>
    <td width="68%"><img src="docs/screenshots/web-dashboard.png" alt="ndesd admin dashboard: inbox open, three files waiting, connect details"></td>
    <td width="32%"><img src="docs/screenshots/web-phone.png" alt="The same dashboard on a phone, light mode"></td>
  </tr>
  <tr>
    <td colspan="2"><img src="docs/screenshots/web-setup-reachability.png" alt="Guided setup step 2: choosing how devices reach the server"></td>
  </tr>
</table>

The admin page walks you through setup once: **claim** the server with the one-time code, **link your vault** (paste the server keys from the Mac app), choose **how your devices reach it** (Tailscale, a proxy on the machine, the local network or every interface), then **connect your Mac**. The page tells you when the first file arrives. After that it shows status, what's waiting, connection details and settings.

The server only ever holds the vault's *public* inbox key and an upload-authentication secret. It cannot decrypt anything, past or future.

## Quick start

You need Go 1.27.3+ (and Swift for the Mac app).

### 1. Build

```bash
go build -o ndes ./cmd/ndes          # CLI
scripts/build-app.sh                 # Mac app -> build/sendndes.app
scripts/build-linux.sh               # release binaries into dist/ (ndesd for Linux, ndes for Mac)
```

For a code signature that stays stable between builds (so the Keychain keeps trusting the app), set `SIGN_IDENTITY="Apple Development: Name (TEAMID)"`.

### 2. Make a vault

Open `build/sendndes.app` and choose **Create a vault**, or use the CLI:

```bash
./ndes init ~/MyVault                # prints the recovery key: write it down
export NDES_VAULT=~/MyVault          # or pass --vault after the command
./ndes add photo.jpg
./ndes ls
./ndes get <id> -o photo.jpg
```

### 3. Run the inbox server (optional)

With Docker, on the machine that will receive files:

```bash
docker compose up -d
docker compose logs ndesd            # shows the one-time setup code
```

Open <http://127.0.0.1:8080> and follow the setup. To pull from the command line instead of the Mac app:

```bash
./ndes pull --server http://<tailscale-ip>:8485 --token-file token.txt
```

#### Prebuilt image

Run the **Docker image** workflow from the repo's Actions tab (it publishes `ghcr.io/klppl/sendndes`). If the package is private, make it public or `docker login ghcr.io` on the server. Then save this as `docker-compose.yml` on the server:

```yaml
services:
  ndesd:
    image: ghcr.io/klppl/sendndes:latest
    restart: unless-stopped
    # Only if the admin page is behind a Cloudflare Tunnel / reverse proxy. Protect the
    # hostname with a Cloudflare Access policy too (see coordination/ndesd-deploy.md).
    # environment:
    #   NDESD_ADMIN_BEHIND_PROXY: "1"
    volumes:
      - ndesd-data:/data
    ports:
      - "127.0.0.1:8080:8080"   # admin page, this machine only
      - "8485:8485"             # sync port: put on Tailscale or behind HTTPS
volumes:
  ndesd-data:
```

```bash
docker compose pull && docker compose up -d
```

The sync port (8485) speaks plain HTTP: keep it on Tailscale or a VPN, or put HTTPS in front of it. The admin page only answers this machine, the local network and Tailscale; reach it remotely over an SSH tunnel or Tailscale. More options (systemd, Cloudflare Tunnel, limits): [coordination/ndesd-deploy.md](coordination/ndesd-deploy.md).

## Security in short

**Protected:** file contents, names and folder structure, against the storage host, the sync service and the inbox server. Any change to a file is detected. Argon2id for the passphrase, ChaCha20-Poly1305 for content, X25519 to seal inbox uploads ([SPEC.md §2](SPEC.md)).

**Visible to the host:** how many files there are, their approximate sizes (padded up to at most 12.5% above the real size, minimum 4 KiB, so small files look alike), and modification times.

**Not protected:** malware on an unlocked device, a weak passphrase, a lost passphrase *and* recovery key (the data is gone), and a host deleting files or rolling them back to an older version.

**Good to know**
- Client-sealed upload: once you paste the server keys into the Mac app (Settings → Server, optional), it seals files locally with `inbox_pub` and `K_auth` before sending (`PUT /inbox/{id}`); the inbox server never sees plaintext, filenames, or folder structure. `K_auth` lives in your macOS login keychain (never iCloud-synced). Without those keys the app falls back to server-side sealing (`PUT /inbox`), where the server sees the file, its name and folder in the clear for a moment while it seals them. That route also stays available for scripts and curl. Either way, keep the sync port on Tailscale or behind HTTPS; the Mac app refuses plain HTTP to anything else.
- The server's upload secret can't be rotated in v1. Give it only to your own server.
- The Mac app keeps the server token and client-sealing keys in your login keychain (never iCloud-synced). Opened and Quick Look copies live in a private temporary folder that's emptied on lock and quit; exports stay where you put them.

Full threat model: [SPEC.md §7](SPEC.md). App details: [app/README.md](app/README.md).

## CLI reference

```
ndes init <vault-dir>                       create a new vault
ndes add <file> [--dir <path>] [--name <n>] encrypt a file into the vault
ndes ls [--dir <path>]                      list files
ndes get <id-or-path> [-o <out>]            decrypt a file
ndes pull --server <url> --token-file <f>   pull sealed files from a ndesd server
ndes ingest [--inbox <dir>]                 move sealed inbox files into the vault
ndes verify                                 authenticate every file in the vault
ndes passwd                                 change the passphrase
ndes recover <vault-dir>                    rebuild vault.json from the recovery key
ndes recovery-key                           print the recovery key
ndes server-config                          print the inbox server's keys
```

Common flags: `--vault <dir>` (default `$NDES_VAULT`, then `.`), `--passphrase-stdin`. Run `ndes --help` for the rest.

## Development

```bash
go test ./...                # Go: core, CLI, server
scripts/test-app.sh          # Mac app core tests (builds a real helper and server)
```

| Path | What's there |
|---|---|
| `core/` | Go reference implementation of the format |
| `cmd/ndes`, `cmd/ndesd` | CLI and inbox server (admin page in `cmd/ndesd/web`) |
| `app/` | Mac app (SwiftUI); it runs the bundled `ndes` as a checked helper |
| `swift/NdesCore` | Swift implementation of the format |
| `testvectors/` | Shared vectors both implementations must match |
| `coordination/` | Design notes, reviews and decisions, including the UX write-ups for the [app](coordination/app-ux-v1.md) and the [server](coordination/ndesd-ux-v1.md) |

## License

[The Lagom License](LICENSE) ([klppl.github.io/lagom-license](https://klppl.github.io/lagom-license/)). Copyright (c) 2026 klppl.
