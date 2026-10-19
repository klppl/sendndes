#!/bin/sh
# Runs the AppCore tests (a few minutes): builds the real `valv` helper and a loopback `valvd`
# into build/test-bin, then `swift test`. Usage: scripts/test-app.sh [swift test args]
set -eu
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local CGO_ENABLED=0
mkdir -p build/test-bin
go build -trimpath -o build/test-bin/valv ./cmd/valv
go build -trimpath -o build/test-bin/valvd ./cmd/valvd
cd app
VALV_TEST_BIN="$(cd ../build/test-bin && pwd)" swift test "$@"
