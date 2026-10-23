#!/bin/sh
# Builds a signed, notarized, stapled build/sendndes-<version>.dmg for a GitHub release.
#   SIGN_IDENTITY="Developer ID Application: Name (TEAMID)" scripts/release-mac.sh
# One-time setup of the notarization credentials (stored in the login Keychain, never in the repo):
#   xcrun notarytool store-credentials sendndes --apple-id you@example.com --team-id TEAMID
# NOTARY_PROFILE overrides the profile name (default "sendndes").
set -eu
: "${SIGN_IDENTITY:?set SIGN_IDENTITY to your \"Developer ID Application: ...\" certificate}"
NOTARY_PROFILE=${NOTARY_PROFILE:-sendndes}

cd "$(dirname "$0")/.."
APP=build/sendndes.app

sh scripts/build-app.sh
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$APP/Contents/Info.plist")
DMG=build/sendndes-$VERSION.dmg

# Notarization needs a Developer ID signature, the hardened runtime and a secure timestamp.
codesign --force --options runtime --timestamp -s "$SIGN_IDENTITY" "$APP/Contents/Helpers/ndes"
codesign --force --options runtime --timestamp -s "$SIGN_IDENTITY" "$APP"
codesign --verify --strict --deep "$APP"

# Disk image: the app plus an Applications shortcut to drag it onto.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
ditto "$APP" "$STAGE/sendndes.app"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -quiet -volname "send n*des" -srcfolder "$STAGE" -format UDZO "$DMG"
codesign --force --timestamp -s "$SIGN_IDENTITY" "$DMG"

xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
spctl --assess --type open --context context:primary-signature -v "$DMG"

(cd build && shasum -a 256 "$(basename "$DMG")" > "$(basename "$DMG").sha256")
echo "ready: $DMG (and $DMG.sha256)"
