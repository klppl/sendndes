#!/bin/sh
# Runs the AppCore tests (a few minutes): builds the real `ndes` helper and a loopback `ndesd`
# into build/test-bin, then `swift test`. Usage: scripts/test-app.sh [swift test args]
set -eu
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local CGO_ENABLED=0
mkdir -p build/test-bin
go build -trimpath -o build/test-bin/ndes ./cmd/ndes
go build -trimpath -o build/test-bin/ndesd ./cmd/ndesd
cd app
NDES_TEST_BIN="$(cd ../build/test-bin && pwd)" swift test "$@"
