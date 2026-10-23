# send n*des (Mac app, milestone 1)

Build: `scripts/build-app.sh` → `build/sendndes.app` (arm64, ad-hoc signed, not sandboxed). Tests: `scripts/test-app.sh`.

Trust and secrets, in plain words:
- With the server keys saved (Settings → Server, optional), the app seals each file on your Mac and the server only ever stores ciphertext. Without them, the app falls back to server-side sealing, but only if the server has it turned on (`--enable-server-sealing`, off by default): then the server sees the file's contents, name and folder for a moment while it seals them. A server with it off answers "This server only accepts files sealed on your Mac" and you add the keys. The Send screen says which mode is active. Settings → Devices pairs a phone: a QR code with an upload-only token (see [ios/README.md](../ios/README.md)).
- The bearer token is stored in your **login keychain** (legacy keychain): not synchronizable, not iCloud-synced, readable while the login keychain is unlocked (normally the whole login session). macOS may ask you to allow access after each rebuild of the app.
- For a pull the token is written to a 0600 file in a private temp directory and deleted as soon as the helper has read it, and on lock, quit and next launch. A force-kill (SIGKILL) can leave it until the next launch.
- The passphrase is kept in memory until you lock. A Swift String cannot be wiped, so it may stay in freed memory until overwritten.
- Names in the list are cleaned of control and direction characters before display. Look-alike names are told apart by the short id.
- With Google Drive "stream" or Dropbox online-only folders, listing opens every file and can make the sync client download them.

What the vault window does: browse by folder (breadcrumbs and folder buttons; a search looks in every folder), Quick Look, Open and Export of decrypted copies, add files by drop or ⌘O, Check inbox, **Verify vault** (⇧⌘V: reads every file once and says how many are intact and authentic), and in Settings > Security **Change passphrase** (the vault key and recovery key stay the same; a saved Touch ID passphrase is replaced) and the recovery key shown again on request. Settings > Devices pairs a phone. The vault key is not cached beyond the session: Touch ID unlock keeps the passphrase in the login keychain if you turn it on. The app is not sandboxed, so vault folders in Google Drive or Dropbox need no security-scoped bookmarks.

Look and feel: `Theme.swift` (palette, sticker cards), `Mascot.swift` (Aster, the asterisk with moods), `Components.swift` (buttons, banners, pills). Motion stops under Reduce Motion; all file names still go through `Text(verbatim:)`.

Icon: Aster on a mint rounded square. `scripts/make-icon.sh [mint|cream|plum]` renders it from `Mascot.swift` into `app/Resources/AppIcon.icns`; `build-app.sh` bundles it.

## Plain http and Tailscale

Plain `http://` is accepted only for loopback or a Tailscale address (100.64.0.0/10). For a Tailscale address the app also checks, before every upload and before a pull, which network interface the Mac would use to reach it, and refuses unless it is a Tailscale one (`utun*` or `tailscale*`): "The route to this address does not go through Tailscale; is Tailscale connected?". There is no fallback to another route. For an unusual setup (for example a WireGuard interface with another name) list extra interface names:

```
defaults write se.klippel.sendndes tailscaleInterfaces -string "wg0,utun9"
```

https is not checked. The recommended setup is https through `tailscale serve`; see [cmd/ndesd/DEPLOY.md](../cmd/ndesd/DEPLOY.md) (§4.1b).

## Auto-lock, token binding, signing

- The app locks after 10 minutes without input (Settings: 1–120 minutes), and at once when the Mac sleeps, the screen locks or the screensaver starts, or you switch user. The inactivity timer never interrupts a running pull, add, export or send; the other triggers cancel it ("Interrupted…": a pull's helper is terminated and its token file deleted, a send goes back to waiting).
- The token is saved in the Keychain together with the server address (scheme, host, port) it was saved for. If the configured address differs (for example someone edited the app's preferences), the token is not sent and Settings asks for it again.
- The app and its helper are ad-hoc signed with the hardened runtime (`codesign --options runtime`, no entitlements), so `DYLD_INSERT_LIBRARIES` and similar are ignored.
- Uploads stream from the file descriptor that was checked (no re-open by path) and exactly the checked size is sent; if the file changed by the end, the item fails and the partial copy is deleted from the server.
