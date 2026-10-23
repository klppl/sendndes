# App Store submission copy

Paste these into App Store Connect. Privacy policy URL: https://klppl.github.io/sendndes/privacy/ (needs the site republished first).

## Listing

**Name** (max 30): `send n*des`
Fallback if review objects to the name: `Sendndes: Private Vault Inbox` (the home-screen name can stay "send n*des").

**Subtitle** (max 30): `Encrypted share to your server`

**Promotional text** (max 170):
Share photos, files and links from any app to your own inbox. Encrypted on your iPhone before they leave, sent in the background.

**Description:**
send n*des is the iPhone companion to the send n*des Mac app and self-hosted inbox. It does one thing: it takes what you share and delivers it, encrypted, to a server you run.

Pick send n*des in the share sheet of any app. Photos, files, text and web links are encrypted on your phone, queued, and uploaded in the background, retrying if the connection drops. Only your Mac can open them.

• Encrypted on the device before anything is uploaded
• Send-only: the phone holds an upload-only key and cannot read or delete anything
• Pair by scanning a QR code from your Mac, then approving a code on your server
• Up to 20 items per share, 90 MiB per file
• No account, no analytics, no tracking, no ads
• Sends only to your own server, over HTTPS

You need the send n*des Mac app and an inbox server (ndesd) that you run yourself. Both are free and open source. Setup guide: https://klppl.github.io/sendndes/guide/

**Keywords** (max 100, comma-separated, no spaces after commas):
`encrypted,inbox,share,vault,private,self-hosted,upload,files,secure,transfer,backup`

**Support URL:** https://github.com/klppl/sendndes/issues
**Marketing URL:** https://klppl.github.io/sendndes/
**Category:** Utilities (secondary: Productivity)
**Copyright:** 2026 Alexander Klippel (adjust to the name on your developer account)

## Age rating
Answer "None" to every content question (no violence, sexual content, profanity, gambling, etc.). Expect 4+.
Do not tick "unrestricted web access". The app talks only to the server the user pairs with.

## App Privacy ("nutrition label")
Select **Data Not Collected**. The developer receives nothing: no analytics, no SDKs, no accounts, and uploads go to the user's own server.

## Export compliance
`ITSAppUsesNonExemptEncryption` is `true` (custom cryptography beyond OS-provided TLS). In App Store Connect answer that the app uses encryption, that it is not exempt, and complete the follow-up questions. Check the current US BIS self-classification requirement (annual report) and any France documentation before choosing territories.

## Review notes (paste into "Notes" in App Review Information)

send n*des is a send-only client for a self-hosted encrypted inbox. It cannot do anything until it is paired with a server, so I have set one up for review.

Demo server: https://REPLACE-WITH-LIVE-DEMO-ADDRESS
To pair (no Mac needed):
1. Open the app. On the scan screen, tap "Use pasted code" and paste this pairing code: REPLACE-WITH-PAIRING-CODE-TEXT (the same text the Mac app encodes in its QR code).
2. Tap "Pair". The app shows a six-digit code. [REPLACE: I approve it on the server page within minutes, contact REPLACE-WITH-EMAIL / OR: the demo server auto-approves.]
3. Once paired, open Photos or Files, tap Share, choose "send n*des". The item is encrypted and queued, then shows as sent on the app's home screen.

Notes for review:
- It is an encrypted file transfer tool. It contains no explicit content and no user-generated public content.
- Camera is used only to scan the pairing QR code; a pasted-code option is available.
- All traffic uses HTTPS only (no ATS exceptions). No accounts, ads, analytics or third-party SDKs.
- Encryption: uses standard, published algorithms; export compliance is declared in the build settings.
- Source code and format spec: https://github.com/klppl/sendndes

## Before submitting, still on you
- Stand up the demo server and keep it online through review. Fill in the placeholders above.
- Verify the pairing steps against the real app, and generate the pairing code text for the demo server.
- Republish the site so the privacy URL resolves.
- App Store screenshots in the required sizes (6.9" and 6.5"/6.3" iPhone); the ones in docs/screenshots may not match.
