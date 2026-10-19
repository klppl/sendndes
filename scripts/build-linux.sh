#!/bin/sh
# Builds the release binaries into dist/ with the installed Go toolchain:
#   dist/valvd-linux-amd64, dist/valvd-linux-arm64  (server, for the VPS)
#   dist/valv-darwin-arm64                          (CLI; the Mac app embeds it)
#   dist/SHA256SUMS
# GOTOOLCHAIN=local stops Go from downloading a different toolchain.
# dist/ is ignored by git.
set -eu

cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local CGO_ENABLED=0
mkdir -p dist

build() { # GOOS GOARCH package output
	echo "building $4 ($1/$2)"
	GOOS=$1 GOARCH=$2 go build -trimpath -o "dist/$4" "$3"
}

build linux amd64 ./cmd/valvd valvd-linux-amd64
build linux arm64 ./cmd/valvd valvd-linux-arm64
build darwin arm64 ./cmd/valv valv-darwin-arm64

cd dist
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum valvd-linux-amd64 valvd-linux-arm64 valv-darwin-arm64 > SHA256SUMS
else
	shasum -a 256 valvd-linux-amd64 valvd-linux-arm64 valv-darwin-arm64 > SHA256SUMS
fi
echo "toolchain: $(go version)"
cat SHA256SUMS
