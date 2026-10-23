# iPhone app: manual test on a real device

Do this once with your own signing team. Nothing here was run yet. Use a throwaway vault and a test hostname if you can.

## 0. Before you start

- `scripts/build-ios.sh` passes on the Mac.
- `brew install xcodegen`, `cp ios/Local.xcconfig.example ios/Local.xcconfig`, set `DEVELOPMENT_TEAM`, `cd ios && xcodegen`, open `SendndesIOS.xcodeproj`, select the Sendndes scheme and your iPhone, Run. If signing fails for the App Group or the keychain group, change the identifiers in `ios/project.yml` (and the same strings in `ios/App/SendndesApp.swift` and `ios/ShareExtension/ShareViewController.swift`), then ask to have them reviewed: they decide where the keys live.
- Server: sealed-only `ndesd` with a tokens file and the Cloudflare tunnel from [CLOUDFLARE.md](../cmd/ndesd/CLOUDFLARE.md). `curl -i https://inbox.example.com/v1/ping` should answer 401 (no token), then 204 with a valid one.

## 1. Pair

1. Mac app > Settings > Devices: device name `iphone-1`, your https address > Show QR code. Note the check value.
2. Add the token line to the server's tokens file, `sudo systemctl reload ndesd`, `journalctl -u ndesd -n 3` shows "tokens reloaded".
3. iPhone: Scan the QR code. Allow the camera. The Confirm screen shows the host, the name and the same check value. Pair.
4. Test connection: "Connected". Then repeat with a wrong QR (an old one after revoking, a random QR code): the app says it is not a send n*des code, nothing is saved.

## 2. Send

Share each of these from the share sheet and check the Mac afterwards (`ndes pull`, Check inbox):

- a photo from Photos (HEIC stays HEIC, no conversion), a PDF from Files, plain text from Notes (arrives as a .txt), a web page URL from Safari (arrives as a .url), a 50 MB video,
- a file over 90 MiB: listed as "Not sent" with "Maximum 90 MiB per file. Use the Mac app for larger files."; the other items in the same share still go,
- 25 items at once: the first 20 queue, the rest say only 20 can be sent at once,
- the same file twice (two different ids, both arrive).

Check on the VPS: the inbox folder holds only `.inb` files (`ls /var/lib/ndesd/inbox`), the journal shows no file names, no ids, no tokens. `ndes pull` ingests them; `ndes ls` shows them under the folder `iPhone`.

## 3. Failure paths

- Airplane mode, share a file, check it waits; go online and open the app: it is sent.
- Wrong token (edit the tokens file hash, reload): item fails with "The server rejected the token. Scan the QR code again."
- Revoked token (delete the line, reload): same message, Retry does not help until you pair again.
- Server down (stop ndesd): items stay waiting; start it: they go after the next app launch or foreground.
- Wi-Fi only (Settings): on cellular nothing starts; on Wi-Fi it does.
- Discard a failed item; check it disappears and the history says Discarded.
- Remove configuration: the app returns to the welcome screen; share again: the sheet says the phone is not paired.

## 4. Cloudflare checks

- A WAF challenge on `/inbox/`: the app shows a failure, not a hang. Add the skip rule from [CLOUDFLARE.md](../cmd/ndesd/CLOUDFLARE.md) and retry.
- A slow cellular upload of about 85 MiB: it should finish; note the time. If Cloudflare answers 524 or the connection drops, the item goes back to waiting; retry sends the same bytes and the server answers 200 "already stored" if the first attempt actually arrived.
- A file near 90 MiB must pass the 100 MB cap (it is about 94.4 MB sealed).
- Kill the app while an upload runs; reopen it: the item is either stored or sent again (never lost, never a second copy on the server: same id).

## 5. Memory and privacy

- Xcode > Debug Navigator > Memory while sharing a 80 MiB video: the extension should stay far below its limit (about 120 MB), well under 30 MB growth.
- Lock the phone right after sharing: uploads continue (token readable after first unlock). Reboot and do not unlock: nothing sends until the first unlock.
- Settings > Wi-Fi only, Folder: change to `Phone/2026`, share, check the folder in the vault.
- Device backup: the outbox and the keys must not be in a backup (flag set in code; check in a device backup if you can).
- What must not appear: file names in the VPS logs or in Cloudflare logs (names are sealed inside the file; the URL holds only a random id).

## 6. Report back

For each step: what happened, screenshots of any failure, and `journalctl -u ndesd` lines. Anything that did not work goes into a GitHub issue.
