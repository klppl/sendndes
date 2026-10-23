# send n*des for iPhone (send-only, version 1.0)

Share anything from the iPhone share sheet to "send n*des". The phone locks it on the device and uploads the locked file to your own `ndesd`. The phone has no vault key and no File Provider, cannot browse or decrypt anything, and does not talk to anyone but your server. Larger files than 90 MiB go through the Mac app.

Code: `ios/` (SwiftPM package `SendndesIOS`: `SenderCore` = all logic, tested on macOS; `SenderUI` = SwiftUI screens in the Mac app's look; `App/` and `ShareExtension/` = thin entry points). Spec of the upload API: `SPEC.md` section 8. Server setup: `ndesd-deploy.md` (sealed-only mode) and `ndesd-cloudflare.md`.

## Build

```
scripts/build-ios.sh        # tests on macOS (incl. a real ndesd on loopback) + builds for the iOS Simulator and a generic device, unsigned
```

For a real install you need XcodeGen and your own signing team (this phase did not install anything):

```
brew install xcodegen                              # you install it; no script does
cp ios/Local.xcconfig.example ios/Local.xcconfig   # then set DEVELOPMENT_TEAM (the file is not committed)
cd ios && xcodegen && open SendndesIOS.xcodeproj   # run the Sendndes scheme on your iPhone
```

Placeholders in `ios/project.yml` that you confirm or change: bundle ids `se.klippel.sendndes.ios` and `se.klippel.sendndes.ios.share`, App Group `group.se.klippel.sendndes`, keychain group `$(AppIdentifierPrefix)se.klippel.sendndes.shared`, display name "send n*des".

## Pair

1. Server: `ndesd` behind your Cloudflare tunnel ([cmd/ndesd/CLOUDFLARE.md](../cmd/ndesd/CLOUDFLARE.md)), with pairing on (the Docker image has it).
2. Mac: Settings > Server > type the address > Connect, and approve the code on the server's web page (once, for the Mac).
3. Mac: Settings > Devices > name the device, give the server's https address > Show QR code (the server's pairing window opens by itself).
4. iPhone: open send n*des > Scan the QR code from your Mac > compare the check value with the Mac > Pair. The phone shows a code; your Mac's QR window shows the same code: press Approve there. Then Test connection.

No token is typed, copied or saved anywhere by you. (The older way, `ndes sender-config` without `--pair` and a tokens-file line, still works.)

## Send

Open a photo, PDF, note or web page, tap Share, choose send n*des. Items are locked and queued; the system uploads them in the background. The app lists what is waiting, what failed (with Retry and Discard), and a history ("Stored on server" means the server has the locked file, nothing more). Up to 20 items per share, 90 MiB per file. Failed items are kept 7 days.

## Remove or revoke

- On the phone: Settings > Remove configuration deletes the keys, the saved address, waiting files and the history.
- On the server (what actually stops a lost phone): delete its line from the tokens file, reload, check the log. The phone still holds `k_auth`, which cannot be rotated in format v1: with a token anyone could upload files that ingest accepts as authentic. Revoking the token is what stops that.

## Status, honestly

- Made by AI for one person. Model-reviewed only (two fresh AI reviewers on the server and the app, not human); no human security audit, none planned.
- Cloudflare terminates TLS and sees the upload token, file ids, sizes and timing, never names or contents (everything is locked on the phone first).
- `k_auth` cannot be rotated in v1. A stolen phone = remove its token line and reload.
- Run on the iOS Simulator (iOS 27.1, 2026-10-23): pairing against a real `ndesd`, the share extension (a link from Safari), the background upload and `ndes pull` reading the file back in the vault. The simulator has no camera, so debug builds have a paste field for the `ndes sender-config --pair` payload. On a real iPhone (same day): QR scan, approval and the token check were done, and the owner then tried the share sheet and the background upload there and they worked (which item types were shared was not recorded). Everything that can run on macOS also did: the payload parser (incl. a 20,000-case fuzz), URL and name rules, sealing of 0 to 90 MiB files (memory flat), the outbox state machine with a fake transport, and real uploads to a real `ndesd` that `ndes pull` then reads back byte for byte.

## What the second review changed

A fresh AI reviewer attacked the app and found 3 High and 7 Medium problems; all are fixed and covered by tests:
- Background sessions follow redirects on their own, so a login page or gateway in front of the server could answer 200 and make a file look stored. Now a file counts as stored only if the answer is exactly ndesd's `{"id":"<this id>"}` and the request was not redirected; anything else keeps the file and shows a clear message.
- Results of the share extension's session are recorded by whichever process hears them; the app no longer resets the extension's uploads and sends them twice.
- Uploading works while the phone is locked (it needs only the address and the token); a locked Keychain is no longer mistaken for "not paired".
- Wi-Fi only now applies at once; files are only sent to the server they were locked for; Remove configuration cancels running uploads; the app and the extension share one lock file for the outbox; text and links are not copied twice; Cancel in the share sheet really cancels; retries back off (30 s, 60 s, ... up to an hour).

Open owner question (the format is frozen, so I did not change anything): the check value shown on both screens is 8 hex characters (32 bits). Someone who can get a QR code scanned could, with hours of CPU, grind a key with the same check value. Showing more digits needs no format change (the phone can compute them from the key), but the Mac's `sender-config` and QR window would show the same longer value. Say if you want that.

Also yours to decide: export-compliance (`ITSAppUsesNonExemptEncryption` is now `true` in `project.yml`, since the app's job is encryption; App Store Connect will ask the follow-up export questions at upload, and the answers are yours to give), and file names are kept in plaintext on the phone (outbox records and history, protected until first unlock, excluded from backup) until you clear them.

## Not tested

- On a real iPhone, not recorded as checked: each kind of item (photos, movies, PDFs, text, links), large and slow background uploads, `handleEventsForBackgroundURLSession` with two session identifiers, file protection and Keychain access groups on device, extension memory in Xcode's gauge.
- A real Cloudflare tunnel, WAF rules, 524 responses, a 90 MiB upload through Cloudflare.
- Real Keychain attributes (tests use a fake store; the attribute choice is unit-tested only).
- Dark mode, Dynamic Type and VoiceOver on the phone screens.
