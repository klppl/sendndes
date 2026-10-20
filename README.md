# Valv

Personal, single-user encrypted vault. File contents, names and folders are unreadable to whoever hosts or syncs the vault. Experimental: keep plaintext backups of anything important. Format: [SPEC.md](SPEC.md).

Runs on macOS, iOS and Linux (not Windows). Needs Go 1.26+.

## 1. Build

```bash
go build -o valv ./cmd/valv          # CLI
scripts/build-linux.sh               # release binaries into dist/ (valvd for Linux, valv for Mac)
scripts/build-app.sh                 # Mac app -> build/sendndes.app (needs Swift)
```

## 2. Use the vault

```bash
./valv init ~/MyVault                # prints a recovery key: write it down
export VALV_VAULT=~/MyVault          # or pass --vault after the command
./valv add photo.jpg
./valv ls
./valv get <id> -o photo.jpg
```

Put the vault folder anywhere (Drive, NAS, local). It only ever sees ciphertext.

## 3. Optional: inbox server (`valvd`)

A write-only server your devices can send files to. It can't read your vault.

```bash
docker compose up -d                 # or: valvd --data /var/lib/valvd
docker compose logs valvd            # shows the one-time setup code
```

1. Open <http://127.0.0.1:8080> and enter the setup code with a new password.
2. Paste the output of `./valv server-config` into the GUI.
3. Copy the server URL and token into the Mac app (or save the token to a file).
4. Pull received files into your vault:

```bash
./valv pull --server http://<tailscale-ip>:8485 --token-file token.txt
```

### Run the prebuilt image

Run the **Docker image** workflow from the repo's Actions tab (it publishes `ghcr.io/klppl/valv`). If the package is private, make it public or `docker login ghcr.io` on the server. Then on the server, save as `docker-compose.yml`:

```yaml
services:
  valvd:
    image: ghcr.io/klppl/valv:latest
    restart: unless-stopped
    # Only if the GUI is behind a Cloudflare Tunnel / reverse proxy. Protect the
    # hostname with a Cloudflare Access policy too (see coordination/valvd-deploy.md).
    # environment:
    #   VALVD_ADMIN_BEHIND_PROXY: "1"
    volumes:
      - valvd-data:/data
    ports:
      - "127.0.0.1:8080:8080"   # admin GUI, this machine only
      - "8485:8485"             # sync port: put on Tailscale or behind HTTPS
volumes:
  valvd-data:
```

```bash
docker compose pull && docker compose up -d
```

The sync port (8485) is plain HTTP: keep it on Tailscale/VPN or behind an HTTPS proxy. The GUI is local-only by default; use an SSH tunnel or Tailscale to reach it remotely. More options (systemd, Cloudflare Tunnel, limits): [coordination/valvd-deploy.md](coordination/valvd-deploy.md).

## Tests

```bash
go test ./...
scripts/test-app.sh
```
