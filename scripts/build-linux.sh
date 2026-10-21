#!/bin/sh
# Builds the release binaries into dist/ with the installed Go toolchain:
#   dist/ndesd-linux-amd64, dist/ndesd-linux-arm64  (server, for the VPS)
#   dist/ndes-darwin-arm64                          (CLI; the Mac app embeds it)
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

build linux amd64 ./cmd/ndesd ndesd-linux-amd64
build linux arm64 ./cmd/ndesd ndesd-linux-arm64
build darwin arm64 ./cmd/ndes ndes-darwin-arm64

cd dist
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum ndesd-linux-amd64 ndesd-linux-arm64 ndes-darwin-arm64 > SHA256SUMS
else
	shasum -a 256 ndesd-linux-amd64 ndesd-linux-arm64 ndes-darwin-arm64 > SHA256SUMS
fi
echo "toolchain: $(go version)"
cat SHA256SUMS
