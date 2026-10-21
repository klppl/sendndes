#!/bin/sh
# Peak memory of ndes-swift-tool (release build) for encrypt and decrypt at
# 50 MB and 500 MB, and of unlock alone. Uses /usr/bin/time -l and reports
# "maximum resident set size" and "peak memory footprint".
#
# Two ways to open the vault:
#   passphrase  normal tool: Argon2id (64 MiB) runs first, as in the main app
#   vk          test build (--traits NDES_TESTVECTORS) with --vk-stdin:
#               Vault(vk:), no Argon2, as in a File Provider extension
#
# Random input files live in a temp directory that is deleted on exit.
# Passphrase and VK are passed on stdin from 0600 files, never argv or env.
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
pkg="$repo/swift/NdesCore"
work=$(mktemp -d "${TMPDIR:-/tmp}/ndes-mem.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP
umask 077

swift build -c release --package-path "$pkg" --product ndes-swift-tool >/dev/null 2>&1
tool="$(swift build -c release --package-path "$pkg" --show-bin-path)/ndes-swift-tool"
swift build -c release --package-path "$pkg" --build-path "$pkg/.build/interop-keys" \
    --traits NDES_TESTVECTORS --product ndes-swift-tool >/dev/null 2>&1
keytool="$(swift build -c release --package-path "$pkg" --build-path "$pkg/.build/interop-keys" \
    --traits NDES_TESTVECTORS --show-bin-path)/ndes-swift-tool"

pass="$work/passphrase"
head -c 24 /dev/urandom | base64 | tr -d '\n=' > "$pass"
printf '\n' >> "$pass"
vault="$work/vault"
"$tool" init "$vault" < "$pass"
"$keytool" show-keys "$vault/vault.json" < "$pass" | sed -n 's/^vk: //p' > "$work/vk"

# measure LABEL CMD... (stdin from $IN): prints one result row.
measure() {
    label=$1; shift
    /usr/bin/time -l "$@" < "$IN" > "$work/stdout" 2> "$work/time"
    rss=$(awk '/maximum resident set size/ {print $1}' "$work/time")
    foot=$(awk '/peak memory footprint/ {print $1}' "$work/time")
    echo "$foot" > "$work/foot_$(echo "$label" | tr -c 'a-zA-Z0-9\n' _)"
    printf '%-34s %10.1f MiB RSS %10.1f MiB footprint\n' "$label" \
        "$(echo "$rss / 1048576" | bc -l)" "$(echo "$foot / 1048576" | bc -l)"
}

IN=$pass
measure "unlock (passphrase, Argon2id)" "$tool" unlock "$vault/vault.json"

for mb in 50 500; do
    plain="$work/plain_$mb"
    head -c $((mb * 1000 * 1000)) /dev/urandom > "$plain"

    IN=$pass
    measure "encrypt ${mb} MB (passphrase)" "$tool" encrypt-object "$vault/vault.json" "$plain" "$work/obj_tmp" --name "f$mb" --dir m
    id=$(cat "$work/stdout")
    obj="$vault/objects/$(echo "$id" | cut -c1-2)/$id.obj"
    mkdir -p "$(dirname "$obj")"
    mv "$work/obj_tmp" "$obj"
    measure "decrypt ${mb} MB (passphrase)" "$tool" decrypt-object "$vault/vault.json" "$obj" "$work/out"
    cmp -s "$plain" "$work/out" || { echo "MISMATCH at $mb MB (passphrase)"; exit 1; }

    IN="$work/vk"
    measure "encrypt ${mb} MB (vk, no Argon2)" "$keytool" encrypt-object "$vault/vault.json" "$plain" "$work/obj_tmp2" --name "g$mb" --dir m --vk-stdin
    id2=$(cat "$work/stdout")
    obj2="$vault/objects/$(echo "$id2" | cut -c1-2)/$id2.obj"
    mkdir -p "$(dirname "$obj2")"
    mv "$work/obj_tmp2" "$obj2"
    measure "decrypt ${mb} MB (vk, no Argon2)" "$keytool" decrypt-object "$vault/vault.json" "$obj2" "$work/out2" --vk-stdin
    cmp -s "$plain" "$work/out2" || { echo "MISMATCH at $mb MB (vk)"; exit 1; }

    rm -f "$plain" "$work/out" "$work/out2" "$obj" "$obj2"
done

# Peak memory must not grow with file size: the 500 MB run may use at most
# 4 MiB more footprint than the 50 MB run (it is one chunk either way).
status=0
for step in "encrypt" "decrypt"; do
    for how in "passphrase" "vk, no Argon2"; do
        a=$(cat "$work/foot_$(echo "$step 50 MB ($how)" | tr -c 'a-zA-Z0-9\n' _)")
        b=$(cat "$work/foot_$(echo "$step 500 MB ($how)" | tr -c 'a-zA-Z0-9\n' _)")
        if [ "$b" -gt $((a + 4 * 1048576)) ]; then
            echo "FAIL: $step ($how) grows with file size: $a -> $b bytes"
            status=1
        fi
    done
done
[ "$status" -eq 0 ] && echo "OK: peak memory does not grow with file size"
exit "$status"
