# send n*des (Mac app, milestone 1)

Build: `scripts/build-app.sh` → `build/sendndes.app` (arm64, ad-hoc signed, not sandboxed). Tests: `scripts/test-app.sh`.
Manual steps: `coordination/app-manual-test-m1.md`. Design: `coordination/app-design-v0.md`.

Trust and secrets, in plain words:
- The server sees your file's contents, name and folder for a moment while it seals them (inside the Tailscale tunnel). Client-side sealing comes later.
- The bearer token is stored in your **login keychain** (legacy keychain): not synchronizable, not iCloud-synced, readable while the login keychain is unlocked (normally the whole login session). macOS may ask you to allow access after each rebuild of the app.
- For a pull the token is written to a 0600 file in a private temp directory and deleted as soon as the helper has read it, and on lock, quit and next launch. A force-kill (SIGKILL) can leave it until the next launch.
- The passphrase is kept in memory until you lock. A Swift String cannot be wiped, so it may stay in freed memory until overwritten.
- Names in the list are cleaned of control and direction characters before display. Look-alike names are told apart by the short id.
- With Google Drive "stream" or Dropbox online-only folders, listing opens every file and can make the sync client download them.

Look and feel: `Theme.swift` (palette, sticker cards), `Mascot.swift` (Aster, the asterisk with moods), `Components.swift` (buttons, banners, pills). Motion stops under Reduce Motion; all file names still go through `Text(verbatim:)`.

Icon: Aster on a mint rounded square. `scripts/make-icon.sh [mint|cream|plum]` renders it from `Mascot.swift` into `app/Resources/AppIcon.icns`; `build-app.sh` bundles it.
