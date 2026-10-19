#!/bin/sh
# Runs the test suite with the test-vector hook enabled.
# With only the Command Line Tools installed (no Xcode), Swift Testing lives
# outside the default search paths, so point the compiler and linker at it.
set -eu
cd "$(dirname "$0")/.."
extra=""
clt=/Library/Developer/CommandLineTools/Library/Developer
if ! xcode-select -p 2>/dev/null | grep -q Xcode.app && [ -d "$clt/Frameworks/Testing.framework" ]; then
    F="$clt/Frameworks"; L="$clt/usr/lib"
    extra="-Xswiftc -F$F -Xlinker -F$F -Xlinker -rpath -Xlinker $F -Xlinker -rpath -Xlinker $L"
fi
# shellcheck disable=SC2086
exec swift test --traits VALV_TESTVECTORS $extra "$@"
