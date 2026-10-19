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

pattern='TestHooks|FixedRandomSource|withFixedRandom|fixedRandom|TestExports|keyReport'

symbols() {
    # $1: build path, $2: tool binary. Lists symbols of every ValvCore object
    # file and of the tool. Build paths are emptied first, so nothing is stale.
    find "$1" -path '*ValvCore*' -name '*.o' -type f | while read -r o; do nm -a "$o" 2>/dev/null; done
    nm -a "$2"
}

plain=.build/check-release-plain
trait=.build/check-release-trait

rm -rf "$plain" "$trait"

swift build -c release --build-path "$plain" >/dev/null
plain_tool="$(swift build -c release --build-path "$plain" --show-bin-path)/valv-swift-tool"
[ -x "$plain_tool" ] || { echo "FAIL: no tool binary at $plain_tool" >&2; exit 1; }
if symbols "$plain" "$plain_tool" | grep -E "$pattern" >/dev/null; then
    echo "FAIL: release build contains test-hook symbols:" >&2
    symbols "$plain" "$plain_tool" | grep -E "$pattern" | head >&2
    exit 1
fi
if strings "$plain_tool" | grep -E 'test hook' >/dev/null; then
    echo "FAIL: release build contains test-hook strings" >&2
    exit 1
fi
# Behaviour, not just symbols: the release tool must not know show-keys.
# (Swift keeps literals of up to 15 bytes inline in code, so `strings`
# cannot be used to look for short command names.)
rc=0; "$plain_tool" show-keys /nonexistent/vault.json </dev/null >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 2 ]; then
    echo "FAIL: release tool accepts show-keys (exit $rc, expected usage error 2)" >&2
    exit 1
fi
rc=0; "$plain_tool" decrypt-object /nonexistent/vault.json /x/00/x.obj /x/out --vk-stdin </dev/null >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 2 ]; then
    echo "FAIL: release tool accepts --vk-stdin (exit $rc, expected usage error 2)" >&2
    exit 1
fi

swift build -c release --build-path "$trait" --traits VALV_TESTVECTORS >/dev/null
trait_tool="$(swift build -c release --build-path "$trait" --traits VALV_TESTVECTORS --show-bin-path)/valv-swift-tool"
rc=0; "$trait_tool" show-keys /nonexistent/vault.json </dev/null >/dev/null 2>&1 || rc=$?
if ! nm -a "$trait_tool" | grep -E 'keyReport' >/dev/null || ! nm -a "$trait_tool" | grep -E "$pattern" >/dev/null || [ "$rc" -ne 1 ]; then
    echo "FAIL: control build with VALV_TESTVECTORS has no test-hook symbols; the check is broken" >&2
    exit 1
fi

echo "OK: release build has no test-hook symbols and no show-keys command (control build with the trait has both)"
