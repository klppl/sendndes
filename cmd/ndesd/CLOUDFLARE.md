# ndesd behind a Cloudflare tunnel (phone uploads over https)

Status: written 2026-10-22 from the code and from Cloudflare's published limits. **Not tested on a real tunnel, a real WAF or a real phone.** Everything marked "check" is something to confirm the first time you set it up.

The picture: the phone seals a file on the device and uploads the ciphertext with `PUT https://inbox.example.com/inbox/<id>`. Cloudflare terminates TLS and forwards the request through `cloudflared` to `ndesd`, which listens only on loopback.

## 1. What Cloudflare can and cannot see

- Can see: the bearer token (it is in the `Authorization` header and TLS ends at Cloudflare), the file id in the URL, sizes, timing, and the phone's IP address.
- Cannot see: names, folders, types or contents. Uploads from the app and the Mac app are sealed on the device, so the body is ciphertext; the metadata is inside it. Do not use the old server-side sealing endpoint (`PUT /inbox` with headers) through a proxy: there the plaintext would pass through Cloudflare.
- Consequence: treat **every token that crosses Cloudflare as observable by Cloudflare**, including the Mac's `both` token if the Mac pulls or sends through the same hostname. Prefer to pull over Tailscale or loopback, or give the Mac its own hostname. Treat the **upload token as observable by Cloudflare**. That is why phones get `upload`-only tokens (they cannot read or delete anything) and why revoking a token is a one-line delete plus `systemctl reload ndesd`.
- A leaked `k_auth` (it is in the QR payload, so only the phone has it) lets anyone who also has a token upload files that ingest accepts. It cannot be rotated in v1; see `SPEC.md` section 7.

## 2. Set it up

1. Run `ndesd` bound to loopback in sealed-only mode (no key material on the server, see [DEPLOY.md](DEPLOY.md)):

   ```
   ndesd --tokens-file /etc/ndesd/tokens --inbox /var/lib/ndesd/inbox \
         --listen 127.0.0.1:8485 --client-ip-header CF-Connecting-IP
   ```

   `--client-ip-header` is honoured only when the TCP peer is loopback (that is `cloudflared`) and the header holds exactly one IP address. Without it every request arrives from 127.0.0.1, so all wrong-token attempts share one bucket (a valid token is never blocked by it, but you lose per-client limiting). If `cloudflared` runs in another container or on another host, the TCP peer is not loopback and the header is ignored on purpose. `X-Forwarded-For` is never used. Leave the flag off if you do not run a proxy on the same host.
2. Point a tunnel at it, in `cloudflared`'s config: `ingress: - hostname: inbox.example.com, service: http://127.0.0.1:8485` and a final `service: http_status:404`. Do not expose `ndesd` on a public port; the tunnel is the only way in.
3. Pair a phone (Mac app, Settings > Devices, or `ndes sender-config --server https://inbox.example.com --label iphone-1`), add the printed line to `/etc/ndesd/tokens`, run `sudo systemctl reload ndesd`.
4. Tokens must be random and at least 32 bytes. `sender-config` makes them with the system's secure random generator. Never reuse one token on two devices: you could not revoke one without the other.

## 3. Cloudflare limits that matter (checked against Cloudflare's documentation on 2026-10-22)

- **Request body limit: 100 MB on the Free and Pro plans** (200 MB Business; Enterprise can raise it, check the current figure); a larger request gets a 413 from Cloudflare before it reaches you. The phone's per-file limit is 90 MiB (94,371,840 bytes). A sealed file is a little bigger than its plaintext, but not by much at that size: the padded length of a 90 MiB file is exactly 90 MiB (Padme rounds up to a multiple of 2 MiB there, and 90 MiB is one), plus 16 bytes of tag per 64 KiB chunk (about 23 KB) and a header of about 600 bytes, so at most about 94.4 MB on the wire. That is under the 100 MB (100,000,000 bytes) Free and Pro cap, with about 5.6 MB to spare. Smaller files pad less than that. A sealed upload larger than `--max-sealed-bytes` (95,420,416 by default) is refused by `ndesd` with 413. On a Free or Pro zone do not raise the phone limit above about 94 MiB of plaintext. This arithmetic is from the padding rule, not from a real upload: check it with a real 90 MiB file.
- **Proxy timeouts:** Cloudflare documents a proxy read timeout of 125 seconds (error 524: the origin took too long to answer) and a proxy write timeout of 30 seconds. `ndesd` itself also drops an upload whose body stalls for 30 seconds (`--io-timeout`). A slow cellular upload is fine as long as bytes keep flowing. The app retries with the same bytes and the same id; `ndesd` answers 200 "already stored" if the first try actually arrived (idempotent).
- Cloudflare may answer 524, 520 or 52x when the origin is down or slow; the app treats any non-2xx other than the documented codes as "retry later".

## 4. WAF, bot protection and other pitfalls (the phone is not a browser)

- **Bot Fight Mode, Super Bot Fight Mode, "I'm Under Attack", Managed Challenge rules and Browser Integrity Check can block or challenge the app** (it is a non-browser client that cannot solve a challenge). A challenged request shows up in the app as an unexpected non-2xx and the item stays "failed, retry later". Add a WAF custom rule that skips these for the upload paths only:
  - If: hostname equals `inbox.example.com` and ((method equals `PUT` and URI path starts with `/inbox/`) or (method equals `GET` and URI path equals `/v1/ping`) or (URI path starts with `/v1/pair/`))
  - Then: Skip, the managed rules, Super Bot Fight Mode and Browser Integrity Check.
  `GET /inbox`, `GET /inbox/{id}` and `DELETE` stay under all your normal protections; they are for your Mac only.
- **Cloudflare Access** in front of the whole hostname would block the phone unless you use an Access **service token** (two headers the app does not send). Not required and not supported by the app; leave Access off for this hostname, or put Access on a separate hostname for the admin page.
- **Caching:** set a rule to bypass cache for the hostname. `ndesd` sends no cache headers on upload responses, and nothing here should ever be cached.
- **Rate limiting at Cloudflare** is optional. If you add it, count by `CF-Connecting-IP` and leave generous room: a share of 20 files is 20 uploads.
- **Do not turn on "Rocket Loader", "Auto Minify", HTML rewriting or "Email Obfuscation"** for this hostname; they rewrite responses. Response bodies here are tiny JSON.
- **Do not rely on Cloudflare for authentication.** The bearer token is checked by `ndesd` in constant time, and failed attempts are limited per client address. A valid token is never blocked by that limiter.
- **The admin web GUI (managed mode)** is a different listener (default `127.0.0.1:8080`, `--admin-behind-proxy`). Expose it, if at all, on a separate hostname behind Cloudflare Access; do not put it on the upload hostname.

## 5. Day-to-day

- Add a phone: pair it, add its line, reload. Remove one: delete its line, reload. `journalctl -u ndesd` shows "tokens reloaded" or "reload failed, keeping the previous tokens: ..." (the message never contains a token or hash).
- `curl -fsS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" https://inbox.example.com/v1/ping` prints 204 for a valid token (any role) and 401 otherwise. The phone's "Test connection" does the same.
- Pull on the Mac as before (`ndes pull`, or Check inbox in the app) with a token that has the role `pull` or `both`.
- The inbox directory should only ever hold `.inb` files. `ndesd` writes nothing else besides `.ndes-*.part` files while an upload is in flight.

## 6. Not tested

- A real `cloudflared` tunnel, a real WAF skip rule, a challenge page, a 524, a real 90 MiB upload through Cloudflare, and the behaviour of `CF-Connecting-IP` with a real tunnel (the code path is tested with synthetic requests only).
- The 100 MB cap against a real sealed 90 MiB file (the numbers above come from reading the documentation and the padding rule, not from an upload).
