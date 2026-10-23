#!/bin/sh
# Builds and tests send n*des for iPhone without signing anything.
#   scripts/build-ios.sh
# 1. builds ndes and ndesd into build/test-bin and runs the SenderCore tests on macOS (`swift test`), including the
#    tests that seal on the "phone", upload to a real ndesd on loopback and read the files back with ndes;
# 2. builds the app and the share extension entry points for the generic iOS Simulator and the generic iOS device
#    with CODE_SIGNING_ALLOWED=NO (Swift package targets: no XcodeGen needed);
# 3. if XcodeGen is installed and ios/Local.xcconfig exists, also generates the Xcode project and builds it.
# It cannot sign, install on a device or use an Apple account; see ios/MANUAL-TEST.md.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
export GOTOOLCHAIN=local CGO_ENABLED=0
mkdir -p build/test-bin
go build -trimpath -o build/test-bin/ndes ./cmd/ndes
go build -trimpath -o build/test-bin/ndesd ./cmd/ndesd

echo "== SenderCore tests (macOS)"
(cd ios && NDES_TEST_BIN="$ROOT/build/test-bin" swift test 2>&1 | tail -n 4)

DD="$ROOT/build/ios-derived"
xb() { # scheme destination
	echo "== $1 for $2"
	(cd ios && xcodebuild -scheme "$1" -destination "$2" -derivedDataPath "$DD" CODE_SIGNING_ALLOWED=NO build 2>&1 \
		| grep -E "error:|warning:|BUILD (SUCCEEDED|FAILED)" | sort -u)
}
for scheme in SendndesApp ShareExtensionEntry; do
	xb "$scheme" "generic/platform=iOS Simulator"
	xb "$scheme" "generic/platform=iOS"
done

if command -v xcodegen >/dev/null 2>&1 && [ -f ios/Local.xcconfig ]; then
	echo "== XcodeGen project"
	(cd ios && xcodegen >/dev/null && xcodebuild -project SendndesIOS.xcodeproj -scheme Sendndes -destination "generic/platform=iOS Simulator" \
		-derivedDataPath "$DD" CODE_SIGNING_ALLOWED=NO build 2>&1 | grep -E "error:|warning:|BUILD (SUCCEEDED|FAILED)" | sort -u)
else
	echo "== XcodeGen project skipped (install: brew install xcodegen; then cp ios/Local.xcconfig.example ios/Local.xcconfig)"
fi
