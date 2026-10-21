#!/bin/sh
# Builds build/sendndes.app (arm64, ad-hoc signed) with the installed Go and Swift toolchains.
#   scripts/build-app.sh
# Steps: build the helper (scripts/build-linux.sh) -> sign it and hash it -> write the hash into a
# build copy of the Swift package -> swift build -c release -> assemble -> sign the app -> re-hash
# the helper and fail if it changed. Swift compiler output is kept in build/swift-build.log.
#   SIGN_IDENTITY="Apple Development: Name (TEAMID)" scripts/build-app.sh   (stable identity: the Keychain
#   keeps trusting the app across rebuilds; default "-" is ad-hoc and changes on every build)
set -eu
SIGN_IDENTITY=${SIGN_IDENTITY:--}

cd "$(dirname "$0")/.."
ROOT=$(pwd)
APP=build/sendndes.app
SRC=build/app-src

# No logging of anything in the app sources (secrets must not reach a log).
if grep -rnE '(^|[^A-Za-z_])(print|debugPrint|NSLog|os_log|dump)\(|Logger\(|import os\b|import OSLog' app/Sources; then
	echo "error: logging calls found in app/Sources" >&2
	exit 1
fi

sh scripts/build-linux.sh >/dev/null
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$APP/Contents/Resources"
cp app/Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
cp dist/valv-darwin-arm64 "$APP/Contents/Helpers/valv"
chmod 755 "$APP/Contents/Helpers/valv"
codesign --force --options runtime -s "$SIGN_IDENTITY" "$APP/Contents/Helpers/valv"
HASH=$(shasum -a 256 "$APP/Contents/Helpers/valv" | cut -d' ' -f1)

mkdir -p "$SRC"
rsync -a --delete --exclude .build app/ "$SRC/"
ln -sfn ../swift "$SRC/../swift"
printf 'let helperSHA256: String? = "%s"\n' "$HASH" > "$SRC/Sources/sendndes/HelperHash.swift"
(cd "$SRC" && swift build -c release --arch arm64) 2>&1 | tee build/swift-build.log
BIN=$(cd "$SRC" && swift build -c release --arch arm64 --show-bin-path)
cp "$BIN/sendndes" "$APP/Contents/MacOS/sendndes"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key><string>sendndes</string>
	<key>CFBundleIconFile</key><string>AppIcon</string>
	<key>CFBundleIdentifier</key><string>se.klippel.sendndes</string>
	<key>CFBundleName</key><string>sendndes</string>
	<key>CFBundleDisplayName</key><string>send n*des</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>0.1</string>
	<key>CFBundleVersion</key><string>1</string>
	<key>LSMinimumSystemVersion</key><string>14.0</string>
	<key>NSPrincipalClass</key><string>NSApplication</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

codesign --force --options runtime -s "$SIGN_IDENTITY" "$APP"
AFTER=$(shasum -a 256 "$APP/Contents/Helpers/valv" | cut -d' ' -f1)
if [ "$HASH" != "$AFTER" ]; then
	echo "error: helper changed while signing the app" >&2
	exit 1
fi
codesign --verify --strict "$APP"
echo "built $ROOT/$APP (helper sha256 $HASH)"
echo "swift warnings: $(grep -c 'warning:' build/swift-build.log || true)"
