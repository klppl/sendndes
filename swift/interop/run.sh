#!/bin/sh
# Go <-> Swift interop check for the v1 format.
#
# Builds the Go CLI (cmd/valv) and valv-swift-tool, creates a temp vault with
# `valv init --passphrase-stdin`, and checks in both directions:
#   (a) objects written by `valv add` are decrypted by Swift to identical bytes;
#   (b) objects written by Swift pass `valv verify` and come back identical
#       from `valv get`;
#   (c) inbox files sealed by Swift ingest cleanly with `valv ingest`, and the
#       result comes back identical from `valv get` (and from Swift).
# Sizes: 0, 1, 65536 and 200000 bytes.
#
# The passphrase is random, kept in a 0600 file in the temp directory and fed
# to every command on stdin; it never appears in argv or the environment.
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/valv-interop.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP
umask 077

sizes="0 1 65536 200000"
fails=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fails=$((fails + 1)); }

echo "building Go CLI and valv-swift-tool"
(cd "$repo" && go build -o "$work/valv" ./cmd/valv)
swift build -c release --package-path "$repo/swift/ValvCore" --product valv-swift-tool >/dev/null
tool="$(swift build -c release --package-path "$repo/swift/ValvCore" --show-bin-path)/valv-swift-tool"
valv="$work/valv"

pass="$work/passphrase"
head -c 24 /dev/urandom | base64 | tr -d '\n=' > "$pass"
printf '\n' >> "$pass"

vault="$work/vault"
"$valv" init "$vault" --passphrase-stdin < "$pass" > /dev/null
echo "vault created by Go: $vault"

for n in $sizes; do
    : > "$work/plain_$n"
    [ "$n" -gt 0 ] && head -c "$n" /dev/urandom > "$work/plain_$n"  # BSD head rejects -c 0
done

echo "(a) Go writes, Swift reads"
for n in $sizes; do
    id=$("$valv" add "$work/plain_$n" --vault "$vault" --dir go --name "go_$n.bin" --passphrase-stdin < "$pass")
    obj="$vault/objects/$(echo "$id" | cut -c1-2)/$id.obj"
    if "$tool" decrypt-object "$vault/vault.json" "$obj" "$work/a_out_$n" < "$pass" \
        && cmp -s "$work/plain_$n" "$work/a_out_$n"; then
        ok "$n bytes ($id)"
    else
        bad "$n bytes ($id)"
    fi
done

echo "(b) Swift writes, Go reads"
b_ids=""
for n in $sizes; do
    id=$("$tool" encrypt-object "$vault/vault.json" "$work/plain_$n" "$work/b_obj_$n" \
        --name "swift_$n.bin" --dir swift < "$pass")
    mkdir -p "$vault/objects/$(echo "$id" | cut -c1-2)"
    mv "$work/b_obj_$n" "$vault/objects/$(echo "$id" | cut -c1-2)/$id.obj"
    b_ids="$b_ids $n:$id"
done
if "$valv" verify --vault "$vault" --passphrase-stdin < "$pass" > "$work/verify_b" 2>&1; then
    ok "valv verify: $(cat "$work/verify_b")"
else
    bad "valv verify: $(cat "$work/verify_b")"
fi
for pair in $b_ids; do
    n=${pair%%:*}; id=${pair#*:}
    if "$valv" get "$id" -o "$work/b_out_$n" --vault "$vault" --passphrase-stdin < "$pass" > /dev/null \
        && cmp -s "$work/plain_$n" "$work/b_out_$n"; then
        ok "$n bytes via valv get ($id)"
    else
        bad "$n bytes via valv get ($id)"
    fi
done

echo "(c) Swift seals inbox files, Go ingests"
c_ids=""
for n in $sizes; do
    id=$("$tool" seal-inbox "$vault/vault.json" "$work/plain_$n" "$work/c_inb_$n" \
        --name "inbox_$n.bin" --dir inbox < "$pass")
    mv "$work/c_inb_$n" "$vault/inbox/$id.inb"
    c_ids="$c_ids $n:$id"
done
if "$valv" ingest --vault "$vault" --passphrase-stdin < "$pass" > "$work/ingest_c" 2>&1; then
    ok "valv ingest: $(cat "$work/ingest_c")"
else
    bad "valv ingest: $(cat "$work/ingest_c")"
fi
if [ -n "$(ls -A "$vault/inbox")" ]; then
    bad "inbox not empty after ingest: $(ls "$vault/inbox")"
fi
for pair in $c_ids; do
    n=${pair%%:*}; id=${pair#*:}
    obj="$vault/objects/$(echo "$id" | cut -c1-2)/$id.obj"
    if "$valv" get "$id" -o "$work/c_out_$n" --vault "$vault" --passphrase-stdin < "$pass" > /dev/null \
        && cmp -s "$work/plain_$n" "$work/c_out_$n" \
        && "$tool" decrypt-object "$vault/vault.json" "$obj" "$work/c_swift_$n" < "$pass" \
        && cmp -s "$work/plain_$n" "$work/c_swift_$n"; then
        ok "$n bytes ingested, identical via valv get and Swift ($id)"
    else
        bad "$n bytes ingested ($id)"
    fi
done

echo "final check"
if "$valv" verify --vault "$vault" --passphrase-stdin < "$pass" > "$work/verify_final" 2>&1; then
    ok "valv verify: $(cat "$work/verify_final")"
else
    bad "valv verify: $(cat "$work/verify_final")"
fi
"$valv" ls --vault "$vault" --passphrase-stdin < "$pass"

if [ "$fails" -ne 0 ]; then
    echo "INTEROP FAILED: $fails check(s)"
    exit 1
fi
echo "INTEROP OK"
