# Easiest setup: connect by approval (no tokens, no keys to copy)

Run the Docker image (managed mode) or `ndesd --pairing --tokens-file <writable file> --inbox <dir> ...` and then:

1. Open the server's web page, finish the guided setup (it only asks where devices reach it), and under **Devices** press **Add a device**. That opens a 10 minute window.
2. Mac app: Settings > Server, type the server's address, press **Connect**. The Mac shows a code like `742 913`.
3. The web page shows the same code next to the Mac's name. Compare, press **Approve**. The Mac now has its own access in its Keychain. Done.
4. Phone: Mac app > Settings > Devices > Show QR code, scan it with the iPhone app. The phone shows a code; your Mac's QR window lists the same code. Press **Approve** there. Done.

To begin again: web page > Settings > Start over. Tick what to remove (devices, settings, vault keys, waiting files); the guided setup returns and your admin password stays.

Remove a device on the web page (Devices > Remove) or in the Mac app (Settings > Devices). It stops working at once. Nothing can connect while the window is closed; it closes by itself.

In managed mode the server holds no vault keys unless you paste them under Advanced (not needed). For a classic (flags) server the tokens file's folder must be writable by `ndesd` (for example `/var/lib/ndesd/tokens`, not `/etc`).

The sections below describe the older manual way (tokens file, reload, shared token), which still works.

---

# Read this first: sealed uploads, token roles, and what changed (2026-10-22)

`ndesd` now has two ways to run, and the phone app needs the sealed-only one. (Not to be confused with "mode A" in SPEC section 8, where a server writes into the vault's inbox on cloud storage.)

**Sealed-only mode (recommended; holds no keys).** The phone and the Mac app seal each file on the device and upload the finished `.inb` with `PUT /inbox/{id}`. The server needs no key material. It needs a tokens file, one line per device:

```
# /etc/ndesd/tokens   (mode 0600, owner ndesd)       <role> <label> <sha256 of the token>
upload iphone-1 3f2c...64 hex characters...9a
both   mac      b71e...64 hex characters...04
```

- Roles: `upload` may only upload (and ping); `pull` may list, download and delete (and ping); `both` may do everything. A phone gets `upload`; the Mac gets `both` (it sends sealed files and runs `ndes pull`).
- Make a phone's line with `ndes sender-config --server https://inbox.example.com --label iphone-1` (or the Mac app: Settings > Devices > Show QR code). It prints the QR payload and the line to add. The line holds only a hash, never the token.
- Make a token for the Mac by hand: `umask 077; openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > mac.token`, then `printf 'both mac %s\n' "$(printf %s "$(cat mac.token)" | sha256sum | cut -d' ' -f1)"`. Keep `mac.token` for `ndes pull --token-file`. Tokens must be random and at least 32 bytes.
- Start it with `ndesd --tokens-file /etc/ndesd/tokens --inbox /var/lib/ndesd/inbox --listen 127.0.0.1:8485` (and `--client-ip-header CF-Connecting-IP` behind a Cloudflare tunnel, see [CLOUDFLARE.md](CLOUDFLARE.md)).
- **Add or remove a device:** edit the tokens file, then `sudo systemctl reload ndesd` (SIGHUP). A broken file is rejected and the old tokens stay in force, with the error in `journalctl -u ndesd`; an empty file is valid and revokes everything in it. **After every revocation check `journalctl -u ndesd -n 5` for "tokens reloaded"**: if it says "reload failed" instead, the stolen token still works. Revoking a stolen phone = delete its line, reload, check.
- The size limit for one sealed upload is `--max-sealed-bytes` (default 95,420,416: the phone's 90 MiB per-file limit plus a MiB for padding and headers).
- `GET /v1/ping` (any valid token, 204) is what the phone's "Test connection" calls.

**Server-side sealing mode (old behaviour, needs the keys).** `PUT /inbox` with `X-Ndes-*` headers and `curl` (section 5 below). It makes the server see the plaintext name and contents for a moment, so it is **off by default**. It needs `--enable-server-sealing` and `--config` (inbox_pub and k_auth).

**If you already run `ndesd --config ...` (including a systemd unit from this guide), it will refuse to start after you upgrade** until you either add `--enable-server-sealing` to its `ExecStart` or move to sealed-only mode. This is deliberate: a server that is not meant to seal files must not hold the keys. The managed mode below (web GUI) keeps its keys by design, so it always has server-side sealing; it also reads an optional `<data>/tokens` file and reloads it on SIGHUP, and `NDESD_CLIENT_IP_HEADER` sets the client IP header.

The plaintext token file (`--token-file`, or `token:` in `--config`) still works as one token with the role `both`, with a deprecation warning at startup. The warning never prints the token.

Systemd for sealed-only mode (`/etc/systemd/system/ndesd.service`, hardening lines as in section 4.2 below):

```ini
[Service]
User=ndesd
ExecStart=/usr/local/bin/ndesd --tokens-file /etc/ndesd/tokens --inbox /var/lib/ndesd/inbox --listen 127.0.0.1:8485 --client-ip-header CF-Connecting-IP
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
```

Not tested on a real tunnel or a real phone yet (see [CLOUDFLARE.md](CLOUDFLARE.md)).

---

# Easy setup: the web GUI (managed mode)

Run `ndesd` with no `--config`/`--inbox` and it starts a small web GUI for setup. No config files, tokens or systemd flags to write by hand.

```bash
ndesd --data /var/lib/ndesd            # or: docker compose up -d
```

- **Admin GUI** on `127.0.0.1:8080` (`--admin-listen`). It is for the owner only: it answers only loopback, private-network and Tailscale addresses (public sources and proxied requests get 403), and it needs a password. Reach it from another machine with an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 server`) or over Tailscale (`--admin-listen <tailscale-ip>:8080`). 
- **Behind Cloudflare Tunnel / Zero Trust:** run `cloudflared` on the same host (or Docker network) pointing at `http://127.0.0.1:8080`, start ndesd with `--admin-behind-proxy` (or `NDESD_ADMIN_BEHIND_PROXY=1`), and protect the hostname with a Cloudflare Access policy. ndesd then accepts proxy headers from a local peer, uses `Cf-Connecting-Ip` for rate limiting and marks the cookie Secure. Access plus the GUI password are your two locks, so do not skip the Access policy. Do **not** route the sync port through the same tunnel unless you add its own Access service-token rule.
- **Sync server** on its own port, `8485` by default. Change address, port, limits and HTTPS in the GUI.
- First run: the log prints a one-time **setup code** (also saved as `<data>/setup-code`). Enter it with a new password to claim the GUI.
- In the GUI: paste the server keys from your vault (`ndes server-config` output), pick the address to listen on, then copy the server URL and token into the send n*des app on your devices. The inbox panel shows files waiting and free disk.
- Everything lives in `--data`: `server.conf` (keys and token, mode 0600), `admin.json` (password hash and settings), `inbox/`.
- Env vars for containers: `NDESD_DATA`, `NDESD_ADMIN_LISTEN`, `NDESD_SYNC_LISTEN` (first-run default).

The manual setup below (flags + systemd) still works unchanged.

---

# `ndesd` Mode B Deployment Checklist (Linux + Tailscale)

This guide walks through deploying `ndesd` (Mode B write-only inbox server, `SPEC.md` § 8) on a Linux host reachable over Tailscale, uploading files with `curl`, and pulling/ingesting them into your vault from a trusted device with `ndes pull`.

---

## 1. Build & Install `ndesd`

On your build machine (macOS or Linux), build the static Linux binary for your server's architecture (`amd64` or `arm64`):

```bash
# For x86_64 Linux:
GOOS=linux GOARCH=amd64 go build -o ndesd ./cmd/ndesd

# For ARM64 (aarch64) Linux:
GOOS=linux GOARCH=arm64 go build -o ndesd ./cmd/ndesd
```

Or run `scripts/build-linux.sh` from the repo root: it builds `dist/ndesd-linux-amd64`, `dist/ndesd-linux-arm64` and `dist/ndes-darwin-arm64` with `-trimpath` and the installed toolchain, and writes `dist/SHA256SUMS`. After copying, check the hash on the server with `sha256sum ndesd` against that file.

Copy `ndesd` to the Linux server and install it owned by `root:root` with mode `0755`:

```bash
sudo install -o root -g root -m 0755 ndesd /usr/local/bin/ndesd
```

---

## 2. Create Dedicated User, Config Directory, and Inbox Storage

On the Linux server, create an unprivileged system user and group (`ndesd`) with no login shell, a configuration directory (`/etc/ndesd`), and the Mode B inbox directory (`/var/lib/ndesd/inbox`):

```bash
sudo groupadd --system ndesd
sudo useradd --system --gid ndesd --home-dir /var/lib/ndesd --no-create-home --shell /usr/sbin/nologin ndesd

sudo install -d -o root  -g ndesd -m 0750 /etc/ndesd
sudo install -d -o ndesd -g ndesd -m 0700 /var/lib/ndesd
sudo install -d -o ndesd -g ndesd -m 0700 /var/lib/ndesd/inbox
```

`ndesd` refuses to start if the inbox directory is writable by group or others (mode `0700` owned by the service user, as above, is the intended setup) and warns if it is readable by them.

> [!IMPORTANT]
> `/var/lib/ndesd/inbox` must be an empty directory dedicated to Mode B `.inb` files. Never point `ndesd --inbox` at a full vault directory containing `vault.json` or `objects/` (`ndesd` will refuse to start).

---

## 3. Generate `server-config` and Bearer Token Without Leaking Secrets

### 3.1 Export `inbox_pub` and `k_auth` on Your Trusted Device (Mac)
Per `SPEC.md` § 3, never print `k_auth` into terminal scrollback or shell history. Redirect `ndes server-config` directly to a regular file; `ndes` automatically sets the output file's permissions to `0600` before writing the secret:

```bash
# On your Mac (where the vault lives):
ndes server-config --vault /path/to/vault > server.conf
```
*(Verify with `ls -l server.conf` that its mode is `-rw-------`.)*

### 3.2 Generate the Bearer Token
`ndesd` requires a bearer token between 32 and 512 printable ASCII characters (no spaces or control characters). Generate a 32-byte (44-character Base64) random token with `umask 077` so it is created with mode `0600` from the start:

```bash
# On your Mac:
(umask 077 && openssl rand -base64 32 > ndesd.token)
```

Keep `ndesd.token` (mode `0600`) on your Mac for `ndes pull --token-file`. Copy `server.conf` and `ndesd.token` to the Linux server **straight to their final paths**, over Tailscale SSH, through stdin. Nothing secret appears in a process argument list, and nothing is parked in `/tmp`:

```bash
# On your Mac. umask 077 on the server makes the new file 0600 from the first byte;
# sudo tee reads the secret from stdin (the ssh input), not from the command line.
ssh <server-host> 'umask 077; sudo tee /etc/ndesd/server.conf >/dev/null' < server.conf
ssh <server-host> 'umask 077; sudo tee /etc/ndesd/ndesd.token >/dev/null' < ndesd.token
```

*(Create `/etc/ndesd` first, see §2. Because the ssh input is the secret, `sudo` must not need to ask for a password on a terminal: ssh in as `root`, or allow `tee` on these two paths without a password in `sudoers`. Otherwise log in on the server and paste the contents into the files yourself with an editor started under `umask 077`.)*

> [!NOTE]
> **About `shred`:** older versions of this guide told you to `shred` the copies. Do not rely on it: `shred` overwrites in place, which does nothing useful on journaled or copy-on-write file systems (ext4 with data journaling, btrfs, ZFS, APFS) and on SSDs with wear levelling. The files above are never written anywhere except their final, `0600` place. On your Mac, keep `server.conf` and `ndesd.token` in a `0700` directory or delete them normally once you no longer need them (`k_auth` can be re-exported from the vault at any time, and the token can be replaced).

### 3.3 Fix Ownership and Mode on the Linux Server (`0400`)
`ndesd` enforces at startup that both `--config` and `--token-file` are regular files (no symlinks) with no group or world permissions (`mode & 0o077 == 0`, i.e. `0600` or `0400`):

```bash
# On the Linux server:
sudo chown ndesd:ndesd /etc/ndesd/server.conf /etc/ndesd/ndesd.token
sudo chmod 0400 /etc/ndesd/server.conf /etc/ndesd/ndesd.token
```

*(Alternatively, instead of a separate `--token-file`, you can append `token: <secret>` as a third line in `/etc/ndesd/server.conf` with mode `0400`.)*

---

## 4. Bind to Tailscale IP & Configure `systemd` Unit

### 4.1 Determine the Server's Tailscale IPv4 Address
Never bind `ndesd` to `0.0.0.0`. Bind it specifically to the server's Tailscale interface IPv4 address (`100.x.y.z`):

```bash
tailscale ip -4
# Example output: 100.101.102.103
```

Because `100.x.y.z` is a non-loopback address and Tailscale already authenticates and encrypts traffic end-to-end with WireGuard, pass `--listen 100.x.y.z:8485 --allow-insecure-http`.

> [!NOTE]
> **Why Direct Tailscale IP Binding Is Preferred Over a Localhost Reverse Proxy (`VALV-REV2-04`)**:
> `ndesd` keys its failed-authentication token bucket on the socket peer address (`r.RemoteAddr`) and deliberately ignores `X-Forwarded-For` and `X-Real-IP` headers so untrusted clients cannot spoof their IP to bypass rate limits. When `ndesd` binds directly to the host's Tailscale IP (`100.x.y.z`), each Tailscale peer connects from its own distinct `100.x.y.z` address and receives an independent rate-limit bucket. If you instead place `ndesd` behind a localhost reverse proxy (`127.0.0.1`), all proxied connections share the `127.0.0.1` rate-limit bucket (5 failed auth attempts before `429 Too Many Requests`), so any reverse proxy in front of `ndesd` must enforce its own per-client authentication or rate limiting.

### 4.1b Recommended: https through `tailscale serve` (ndesd on 127.0.0.1)
Plain http to a `100.x` address is only safe while the traffic really goes through Tailscale. The Mac app and `ndes pull` check this (§6), but https needs no such assumption and is the better setup:

1. Run `ndesd` on loopback: `--listen 127.0.0.1:8485` (no `--allow-insecure-http` needed for loopback).
2. Let Tailscale terminate TLS on the tailnet name: `sudo tailscale serve --bg --https=443 http://127.0.0.1:8485` (enable HTTPS certificates for your tailnet first in the Tailscale admin console).
3. Use `https://<machine>.<tailnet>.ts.net` as the server address in the app and in `ndes pull --server`.

> [!NOTE]
> Behind `tailscale serve` every request reaches `ndesd` from `127.0.0.1`, so the per-IP failed-authentication limiter (5 failures, then 429) becomes **one shared bucket** for all clients. For a single user this is acceptable (a wrong token from any device slows everyone down for a while); it is not a protection against a second, hostile tailnet member beyond that shared limit. See also the note in §4.1.

If you keep the plain-http setup below, `ndesd` binds to the Tailscale IP directly.

### 4.2 Hardened `systemd` Service (`/etc/systemd/system/ndesd.service`)
Create `/etc/systemd/system/ndesd.service` (replacing `100.101.102.103` with your server's `tailscale ip -4` output):

```ini
[Unit]
Description=Ndes Mode B Write-Only Inbox Server
After=network-online.target tailscaled.service
Wants=network-online.target
Requires=tailscaled.service

[Service]
Type=simple
User=ndesd
Group=ndesd
WorkingDirectory=/var/lib/ndesd

# Bind exclusively to the Tailscale IPv4 address.
# Quota & timeout flags can be tuned as needed:
#   --max-upload-bytes 4294967296   (4 GiB per upload)
#   --io-timeout 30s                (abort uploads/downloads stalling > 30s per 64 KiB chunk)
#   --max-concurrent-uploads 4      (max parallel PUT /inbox streams)
#   --max-inbox-files 10000         (max .inb + .part files on disk before HTTP 507)
#   --max-inbox-bytes 2147483648    (max total size of stored inbox files, see §4.3)
#   --min-free-bytes 268435456      (free space to leave on the disk, see §4.3)
#   --min-upload-rate 65536         (slowest accepted upload, bytes/s, see §4.3)
ExecStart=/usr/local/bin/ndesd \
    --enable-server-sealing \
    --config /etc/ndesd/server.conf \
    --token-file /etc/ndesd/ndesd.token \
    --inbox /var/lib/ndesd/inbox \
    --listen 100.101.102.103:8485 \
    --allow-insecure-http \
    --max-upload-bytes 4294967296 \
    --io-timeout 30s \
    --max-concurrent-uploads 4 \
    --max-inbox-files 10000

ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Clean signal handling: ndesd traps SIGTERM, unlinks any in-flight .part files,
# wipes K_auth and token in memory, and exits cleanly.
KillSignal=SIGTERM
TimeoutStopSec=15s

# Disable core dumps so key material (K_auth, ephemeral keys, token) is never written to disk.
LimitCORE=0

# Filesystem & privilege hardening:
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ndesd/inbox
ReadOnlyPaths=/etc/ndesd
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
RemoveIPC=yes
UMask=0077

# Go's runtime on Linux amd64/arm64 does not use JIT or W+X pages, so
# MemoryDenyWriteExecute=yes is fully supported.
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6

# Audit L8 additions (running on a Linux VPS since 2026-10-22, see the note below the unit):
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
LimitNOFILE=4096
MemoryMax=512M
TasksMax=256
PrivateUsers=true
ProtectProc=invisible
ProcSubset=pid

[Install]
WantedBy=multi-user.target
```

> [!WARNING]
> **Validated on one Linux VPS (2026-10-22).** The owner reports the unit with all the "Audit L8 additions" and the new limits flags runs correctly there. A full Linux test pass has not been done, and the distro and systemd version are not recorded. The lines most likely to need adjusting on other hosts are:
> - `SystemCallFilter=~@privileged @resources`: Go's runtime reads `RLIMIT_NOFILE` with `prlimit64`, which is in `@resources`. `SystemCallErrorNumber=EPERM` makes a blocked call fail with an error instead of killing the process with SIGSYS, and the Go runtime tolerates that failure, but this is untested. If `ndesd` does not start, remove the two `SystemCallFilter=` lines first.
> - `PrivateUsers=true` (the service sees only root and its own user; the inbox must be owned by `ndesd`, as in §2) and `ProtectProc=invisible` / `ProcSubset=pid` (needs systemd 247 or newer).
> - `CapabilityBoundingSet=` (empty) is fine for a port above 1023; a port below 1024 would need `CAP_NET_BIND_SERVICE`.
> - `MemoryMax=512M` and `TasksMax=256` are generous for streaming uploads (memory is flat, see below) but are guesses. `LimitNOFILE=4096` allows 32 concurrent requests with plenty of room.
>
> After installing, run `systemd-analyze security ndesd.service`, start the service, upload a file with §5.1 and pull it with §6 before relying on it.

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ndesd.service
sudo systemctl status ndesd.service
```

---

## 4.3 Upload Size Limit and Disk Budget (set these on a small VPS)

`ndesd` has three limits on what the inbox may hold and one on how long an upload may take:

| Flag | Default | What it limits |
|---|---|---|
| `--max-upload-bytes` | `4294967296` (4 GiB) | Plaintext size of one `PUT /inbox` body (for a client-sealed `PUT /inbox/{id}`, the size of the sealed file). A larger `Content-Length` gets 413 at once. Both `PUT /inbox` and `PUT /inbox/{id}` need a `Content-Length` and get 411 without one (for the server-sealed upload the padded size goes into the metadata before the body is read, SPEC 5.3). The old `--max-chunked-duration` flag is gone. |
| `--max-inbox-files` | `10000` | Number of `.inb` + in-flight `.part` files in the inbox directory. When reached, uploads get 507 `inbox file limit reached`. |
| `--max-inbox-bytes` | `2147483648` (2 GiB) | Sum of the sizes of the stored `.inb` files plus what uploads in flight may still add. Checked together with the file count under one lock, so concurrent uploads cannot overshoot it. An upload whose declared `Content-Length` (plus up to 70 KiB of header and 16 bytes per 64 KiB chunk) does not fit in what remains gets 507 `inbox byte limit reached` before any body is read. An upload **without** `Content-Length` (chunked) is admitted against everything that remains, one such upload at a time, and is cut off with the same 507 if it grows past that. The Mac app and `curl --data-binary @file` always send `Content-Length`. |
| `--min-free-bytes` | `268435456` (256 MiB) | Free space on the inbox file system that uploads must leave alone. An upload that would eat into it (by its declared length) gets 507 `server out of space`. `0` turns the margin off. |
| `--min-upload-rate` | `65536` (64 KiB/s) | Slowest accepted upload. The whole upload must finish within **60 s + Content-Length / rate** (a 100 MiB file: 60 s + 1600 s), or within `--max-chunked-duration` (default `10m`) when the length is not declared. This is in addition to `--io-timeout`, which only bounds a single stalled read, so a client that sends one byte every few seconds can no longer hold an upload slot indefinitely: it gets 408 `upload too slow` and the slot is freed. |

The three 507 answers have different bodies so clients can tell them apart: `inbox file limit reached`, `inbox byte limit reached`, `server out of space`. The Mac app shows "Server inbox full; pull first." for the first two and "The server is out of space." for the third. A disk that fills up *during* an upload (ENOSPC or a quota error from the file system) is mapped to 507 `server out of space` as well, and the `.part` file is removed.

The worst-case disk use of the inbox is therefore about:

```
max-inbox-files x (max-upload-bytes x 1.0003 + 70 KiB)
```

(the sealed `.inb` adds a 16-byte tag per 64 KiB chunk plus at most ~66 KiB of header and metadata). With the defaults the byte quota (`--max-inbox-bytes`, 2 GiB) and the free-space margin (`--min-free-bytes`, 256 MiB) are what actually bound the inbox, so the defaults are safe for a small disk. Tune them to the space you are willing to give the inbox, and use the file/size flags to shape what is accepted:

0. The byte quota is the simple knob: `--max-inbox-bytes` = the budget below. The steps that follow tune the per-file flags.
1. On the VPS, check free space on the filesystem that holds `/var/lib/ndesd`: `df -h /var/lib/ndesd`.
2. Choose a budget, e.g. half of the free space, leaving the rest for the OS, logs and journald.
3. Set `--max-upload-bytes` to the largest single file you expect to send, and `--max-inbox-files` to `budget / max-upload-bytes`, rounded down.

Examples:

| Free disk | Budget | `--max-upload-bytes` | `--max-inbox-files` | Worst case |
|---|---|---|---|---|
| 20 GB | 10 GiB | `1073741824` (1 GiB) | `10` | ~10 GiB |
| 20 GB | 10 GiB | `268435456` (256 MiB) | `40` | ~10 GiB |
| 50 GB | 20 GiB | `2147483648` (2 GiB) | `10` | ~20 GiB |

A low `--max-inbox-files` also caps the number of small files waiting on the server, so pull regularly. If you need many small files *and* some large ones, the formula is still the bound: there is no mixed rule.

Put the values you chose into the `ExecStart=` line in §4.2 (`--max-inbox-bytes` as well as the two above). For a hard guarantee independent of these flags, put `/var/lib/ndesd` on its own small filesystem (a separate partition or volume); then a full inbox cannot fill the root filesystem.

Tested: the byte quota (including concurrent uploads), the free-space margin and the error-to-status mapping, with unit tests. Not tested: a real file system that actually runs out of space in the middle of an upload (the mapping of ENOSPC to 507 is tested with a synthetic error; an earlier manual run on a tiny disk image showed the `.part` file being removed and the server surviving).

The "send n*des" Mac app sends one file at a time (`PUT /inbox/{id}` with the server keys saved, `PUT /inbox` without), so each file you drop must be at most `--max-upload-bytes`; a larger one fails with 413 and the app shows that it is too large for the server.

---

## 5. Uploading Files to `ndesd` with `curl`

All requests require `Authorization: Bearer <token>` and hit `http://100.101.102.103:8485/inbox`.

**Do not put the token on the command line.** Anything in a process argument list (`curl -H "Authorization: Bearer $TOKEN"`, `TOKEN=$(cat …)` expanded into an argument) is visible to every local user through `ps`, and ends up in shell history if typed. Build a header file once and let curl read it with `-H @file` (curl 7.55 or newer):

```bash
(umask 077 && sed 's/^/Authorization: Bearer /' /path/to/ndesd.token > /path/to/auth.hdr)
```

`sed` reads the token from the file and writes the header line to `auth.hdr` (mode `0600`); no argument contains the token. Delete `auth.hdr` when you are done, or keep it in the same `0700` place as the token. The examples below use `-H @/path/to/auth.hdr`.

### 5.1 Upload a File with an ASCII Filename and Folder (`X-Ndes-Name`, `X-Ndes-Dir`)
Use `--data-binary @<path>` so `curl` streams the exact bytes without stripping newlines or loading the entire file into memory:

```bash
curl --fail-with-body -sS -X PUT \
  -H @/path/to/auth.hdr \
  -H "X-Ndes-Name: receipt-2026-10.pdf" \
  -H "X-Ndes-Dir: Finance/Receipts" \
  -H "X-Ndes-Mime: application/pdf" \
  -H "X-Ndes-Mtime: $(date +%s)000000000" \
  --data-binary @./receipt-2026-10.pdf \
  http://100.101.102.103:8485/inbox
```
Response (`201 Created`):
```json
{"id":"4f8a9c1e2b3d4e5f60718293a4b5c6d7"}
```
*(Note: `X-Ndes-Dir`, `X-Ndes-Mime`, and `X-Ndes-Mtime` are optional. If `X-Ndes-Mtime` is omitted, `ndesd` records the current server time in Unix nanoseconds.)*

### 5.2 Upload a File with Non-ASCII / UTF-8 Filename or Folder (`X-Ndes-Name-B64`, `X-Ndes-Dir-B64`)
When a filename or folder contains non-ASCII characters (e.g. `Räksmörgås.txt` in `Kök/2026`) or leading/trailing spaces, pass standard RFC 4648 Base64 in `X-Ndes-Name-B64` / `X-Ndes-Dir-B64` (`ndesd` validates UTF-8 and normalizes to NFC before encrypting):

```bash
NAME_B64=$(printf '%s' 'Räksmörgås.txt' | base64 | tr -d '\n')
DIR_B64=$(printf '%s' 'Kök/2026' | base64 | tr -d '\n')

curl --fail-with-body -sS -X PUT \
  -H @/path/to/auth.hdr \
  -H "X-Ndes-Name-B64: ${NAME_B64}" \
  -H "X-Ndes-Dir-B64: ${DIR_B64}" \
  -H "X-Ndes-Mime: text/plain" \
  --data-binary @./Raksmorgas.txt \
  http://100.101.102.103:8485/inbox
```

### 5.3 List Sealed Files Waiting on the Server (`GET /inbox`)
```bash
curl --fail-with-body -sS \
  -H @/path/to/auth.hdr \
  http://100.101.102.103:8485/inbox
```
Response (`200 OK`):
```json
{"ids":["4f8a9c1e2b3d4e5f60718293a4b5c6d7","9b1d2e3f4a5b6c7d8e9f001122334455"]}
```

---

## 6. Pulling & Ingesting into the Vault from Your Mac (`ndes pull`)

From your Mac (connected to the same Tailscale tailnet):

```bash
# 1. Pull, authenticate, ingest, verify object read-back, and delete from server:
ndes pull \
  --vault /path/to/vault \
  --server http://100.101.102.103:8485 \
  --token-file /path/to/ndesd.token

# Output:
# Passphrase:
# ingested 2, already ingested 0, failed 0
```

*(Note: `ndes pull` allows plain `http://` only for an IPv4 loopback (`127.0.0.0/8`) or Tailscale (`100.64.0.0/10`) address written as an IP literal without leading zeros, or `[::1]` (not `localhost`; same rules as the Mac app, tested against one shared list). For a Tailscale address it also checks the route first: it asks the OS which local interface would carry packets to that address (a connected UDP socket, nothing is sent) and requires a Tailscale interface (`utun*` on macOS, `tailscale*` on Linux). If the route goes elsewhere, for example because Tailscale is off or just woke from sleep, it stops with "the route to this address does not go through Tailscale; is Tailscale connected?" and never falls back to another route. The check runs at the start and again before every file. For an unusual setup, name extra interfaces with `--tailscale-interfaces=wg0,...`. https is not checked.)*

Verify and inspect the newly ingested files in the vault:

```bash
# 2. List vault contents:
ndes ls --vault /path/to/vault

# 3. Run full vault verification:
ndes verify --vault /path/to/vault
```

### Safety Guarantees During `ndes pull` (`SPEC.md` §§ 6.3, 8)
- Each `.inb` file is downloaded into a private temporary directory **outside the vault** (`os.TempDir`, mode `0700`, unpredictable name, file `0600`, created exclusively) and authenticated there. Only a file that passes is copied into `<vault>/inbox/<id>.inb` (through a `.ndes-<16 hex>.part` file) and ingested. A file that fails authentication is reported as not authentic, removed from the temporary directory, and stays on the server; nothing is written to the vault. The temporary directory is removed on every exit path and on SIGINT/SIGTERM/SIGHUP/SIGQUIT.
- Downloads are bounded by `--max-download-bytes` (default `4294967296`, 4 GiB per file), `--max-total-bytes` (default 16 GiB per pull run) and a per-read progress watchdog `--io-timeout` (default `30s`); if a server sends an oversized or stalling stream, `ndes pull` aborts that download.
- `ndes pull` authenticates `K_auth`, `meta_blob`, and every 64 KiB chunk, writes the object to `<vault>/objects/<xx>/<id>.obj`, and re-opens the final object file to verify its metadata and every chunk (`verifyObjectAt`).
- **`DELETE /inbox/{id}` is sent to `ndesd` ONLY after local ingest and read-back verification succeed** (or after `CheckAlreadyIngested` verifies that an identical authenticated object already exists). If any authentication or I/O error occurs, the file stays on `ndesd`.

---

## 7. Scope & Explicit Non-Goals (What Is NOT Covered)

1. **No TLS Termination Beyond Tailscale WireGuard by Default**:
   - The configuration above relies on Tailscale's WireGuard tunnel for transport encryption and node-level network access control. If you expose `ndesd` outside Tailscale or want application-layer HTTPS on top of Tailscale (e.g. via `tailscale cert`), pass `--tls-cert /etc/ndesd/tls.crt --tls-key /etc/ndesd/tls.key` (TLS 1.3 minimum) and remove `--allow-insecure-http`.
2. **No Automatic Backup of the Server's Inbox Directory**:
   - `/var/lib/ndesd/inbox` is a transient staging area holding sealed `.inb` files until `ndes pull` ingests and deletes them. If the server's disk is lost before you run `ndes pull`, unpulled inbox files on that disk are lost. Back up `/var/lib/ndesd/inbox` if uploads sit unpulled for extended periods.
3. **No `K_auth` Rotation in v1 (`SPEC.md` §§ 3, 7, 12)**:
   - `K_auth` is derived deterministically from `VK` (inbox epoch 0) and cannot be rotated in v1. While a compromised `ndesd` server cannot decrypt any past or future uploads or vault objects, an attacker who extracts `K_auth` can forge authentic `.inb` uploads. After any suspected server compromise, shut down `ndesd` and do not blindly run `ndes pull` or `ndes ingest` without inspecting the inbox first.
4. **Exact Size & Upload Timing Visibility**:
   - As stated in `SPEC.md` § 7, `ndesd` and the server's host can observe the number of uploaded `.inb` files, their exact sizes (the stored size reveals the plaintext length exactly: 16 bytes of tag per 64 KiB chunk plus a header of padded metadata; there is no size padding in v1), and upload timestamps. Plaintext filenames, folder paths, MIME types, and file contents are encrypted.
