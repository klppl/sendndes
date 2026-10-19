#!/bin/sh
# Checks that a normal release build contains no way to inject fixed keys,
# ids, nonces or randomness (SPEC 10.9).
#
# 1. Builds ValvCore and valv-swift-tool in release mode without traits and
#    fails if any object file or the tool binary has a symbol of the test hook.
# 2. As a control, builds again with --traits VALV_TESTVECTORS and requires
#    the same symbols to be present, so the first check cannot pass vacuously.
set -eu
cd "$(dirname "$0")/.."

pattern='TestHooks|FixedRandomSource|withFixedRandom|fixedRandom'

symbols() {
    # $1: build path. Lists symbols of every ValvCore object file and the tool.
    find "$1" -path '*ValvCore.build/*.o' -type f | while read -r o; do nm -a "$o" 2>/dev/null; done
    nm -a "$1/release/valv-swift-tool" 2>/dev/null
}

plain=.build/check-release-plain
trait=.build/check-release-trait

swift build -c release --build-path "$plain" >/dev/null
if symbols "$plain" | grep -E "$pattern" >/dev/null; then
    echo "FAIL: release build contains test-hook symbols:" >&2
    symbols "$plain" | grep -E "$pattern" | head >&2
    exit 1
fi
if strings "$plain/release/valv-swift-tool" | grep -E 'test hook' >/dev/null; then
    echo "FAIL: release build contains test-hook strings" >&2
    exit 1
fi

swift build -c release --build-path "$trait" --traits VALV_TESTVECTORS >/dev/null
if ! symbols "$trait" | grep -E "$pattern" >/dev/null; then
    echo "FAIL: control build with VALV_TESTVECTORS has no test-hook symbols; the check is broken" >&2
    exit 1
fi

echo "OK: release build has no test-hook symbols (control build with the trait has them)"
