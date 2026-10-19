#!/bin/sh
# Go <-> Swift interop check for the v1 format.
#
# Builds the Go CLI (cmd/valv) and valv-swift-tool, creates a temp vault with
# `valv init --passphrase-stdin`, and checks in both directions:
#   (a) objects written by `valv add` are decrypted by Swift to identical bytes;
#   (b) objects written by Swift pass `valv verify` and come back identical
#       from `valv get`;
#   (c) inbox files sealed by Swift ingest cleanly with `valv ingest`, and the
#       result comes back identical from `valv get` (and from Swift);
#   (d) the same vault.json unlocks in both from the same passphrase, and
#       inbox_pub, K_auth (`valv server-config`) and the recovery key agree;
#   (e) a vault created by Swift is accepted by Go (`valv ls` empty, then after
#       `valv add`), and a vault created by `valv init` is accepted by Swift;
#   (f) names and dirs with å, é and a Hangul syllable round-trip in both
#       directions, and NFD input is stored as NFC by both writers.
# Sizes for (a) to (c): 0, 1, 65536 and 200000 bytes.
#
# The passphrase is random, kept in a 0600 file in the temp directory and fed
# to every command on stdin; it never appears in argv or the environment.
# Keys are only written to 0600 files in the temp directory and compared with
# cmp; they are never printed. Printing keys needs a second build of the tool
# with --traits VALV_TESTVECTORS (`show-keys`); the normal build cannot.
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
swift build -c release --package-path "$repo/swift/ValvCore" --build-path "$repo/swift/ValvCore/.build/interop-keys" \
    --traits VALV_TESTVECTORS --product valv-swift-tool >/dev/null
keytool="$(swift build -c release --package-path "$repo/swift/ValvCore" --build-path "$repo/swift/ValvCore/.build/interop-keys" \
    --traits VALV_TESTVECTORS --show-bin-path)/valv-swift-tool"
valv="$work/valv"

pass="$work/passphrase"
head -c 24 /dev/urandom | base64 | tr -d '\n=' > "$pass"
printf '\n' >> "$pass"

vault="$work/vault"
# init prints the recovery key; keep it in a 0600 file for (d), never on screen.
"$valv" init "$vault" --passphrase-stdin < "$pass" > "$work/go_init_out"
echo "vault created by Go: $vault"

for n in $sizes; do
    : > "$work/plain_$n"
    [ "$n" -gt 0 ] && head -c "$n" /dev/urandom > "$work/plain_$n"  # BSD head rejects -c 0
done

echo "(a) Go writes, Swift reads"
for n in $sizes; do
    id=$("$valv" add "$work/plain_$n" --vault "$vault" --dir go --name "go_$n.bin" --passphrase-stdin < "$pass")
    echo "$id" >> "$work/a_ids"
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

hexof() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
objpath() { echo "$1/objects/$(echo "$2" | cut -c1-2)/$2.obj"; }

echo "(d) one vault.json, both implementations"
if "$valv" ls --vault "$vault" --passphrase-stdin < "$pass" > /dev/null 2>&1; then
    ok "Go unlocks the vault.json made by valv init"
else
    bad "Go cannot unlock its own vault.json"
fi
if [ "$("$tool" unlock "$vault/vault.json" < "$pass" 2>&1)" = unlocked ]; then
    ok "Swift unlocks the same vault.json with the same passphrase"
else
    bad "Swift cannot unlock the Go vault.json"
fi

# keys_agree LABEL VAULTDIR: compares inbox_pub and k_auth from
# `valv server-config` with Swift's show-keys, and inbox_pub with vault.json.
keys_agree() {
    "$valv" server-config --vault "$2" --passphrase-stdin < "$pass" > "$work/go_keys_$1" 2>/dev/null || true
    "$keytool" show-keys "$2/vault.json" < "$pass" > "$work/sw_keys_$1" 2>/dev/null || true
    for k in inbox_pub k_auth; do
        grep "^$k: " "$work/go_keys_$1" > "$work/go_${k}_$1" || true
        grep "^$k: " "$work/sw_keys_$1" > "$work/sw_${k}_$1" || true
        if [ -s "$work/go_${k}_$1" ] && cmp -s "$work/go_${k}_$1" "$work/sw_${k}_$1"; then
            ok "$1 vault: $k agrees (Go server-config = Swift)"
        else
            bad "$1 vault: $k differs between Go server-config and Swift"
        fi
    done
    sed -n 's/^  "inbox_pub": "\(.*\)"$/inbox_pub: \1/p' "$2/vault.json" > "$work/json_inbox_pub_$1"
    if cmp -s "$work/json_inbox_pub_$1" "$work/sw_inbox_pub_$1"; then
        ok "$1 vault: inbox_pub equals the value stored in vault.json"
    else
        bad "$1 vault: inbox_pub does not equal the value in vault.json"
    fi
}
keys_agree go "$vault"

grep -E '^ *[A-Z2-7]{4}(-[A-Z2-7]{4}){13} *$' "$work/go_init_out" | tr -d ' ' \
    | sed 's/^/recovery_key: /' > "$work/go_recovery" || true
grep '^recovery_key: ' "$work/sw_keys_go" > "$work/sw_recovery" || true
if [ -s "$work/go_recovery" ] && cmp -s "$work/go_recovery" "$work/sw_recovery"; then
    ok "go vault: recovery key printed by valv init equals Swift's encoding of VK"
else
    bad "go vault: recovery key differs between valv init and Swift"
fi

echo "(e) vault.json created by each side, accepted by the other"
swvault="$work/swift_vault"
if "$tool" init "$swvault" < "$pass"; then
    ok "Swift creates a vault (vault.json, objects/, inbox/)"
else
    bad "Swift init failed"
fi
rc=0; out=$("$valv" ls --vault "$swvault" --passphrase-stdin < "$pass" 2>&1) || rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then
    ok "valv ls accepts the Swift vault.json (empty vault)"
else
    bad "valv ls on the empty Swift vault: exit $rc: $out"
fi
id=$("$valv" add "$work/plain_65536" --vault "$swvault" --dir e --name e.bin --passphrase-stdin < "$pass" 2>&1) || true
rc=0; out=$("$valv" ls --vault "$swvault" --passphrase-stdin < "$pass" 2>&1) || rc=$?
if [ "$rc" -eq 0 ] && [ "$(echo "$out" | wc -l | tr -d ' ')" = 1 ] && echo "$out" | grep -q "^$id .*e/e.bin$"; then
    ok "valv add, then valv ls lists one file in the Swift vault ($id)"
else
    bad "valv ls after add on the Swift vault: exit $rc: $out"
fi
if "$valv" verify --vault "$swvault" --passphrase-stdin < "$pass" > "$work/verify_e" 2>&1 \
    && "$valv" get "$id" -o "$work/e_go" --vault "$swvault" --passphrase-stdin < "$pass" > /dev/null \
    && cmp -s "$work/plain_65536" "$work/e_go" \
    && "$tool" decrypt-object "$swvault/vault.json" "$(objpath "$swvault" "$id")" "$work/e_swift" < "$pass" \
    && cmp -s "$work/plain_65536" "$work/e_swift"; then
    ok "Swift vault: valv verify ($(cat "$work/verify_e")), valv get and Swift decrypt agree"
else
    bad "Swift vault: verify/get/decrypt: $(cat "$work/verify_e" 2>/dev/null)"
fi
keys_agree swift "$swvault"
if "$tool" unlock "$vault/vault.json" < "$pass" > /dev/null \
    && "$tool" decrypt-object "$vault/vault.json" "$(objpath "$vault" "$(sed -n 1p "$work/a_ids")")" "$work/e_go_vault" < "$pass"; then
    ok "Swift accepts the vault created by valv init (unlock and decrypt; see also (a))"
else
    bad "Swift does not accept the vault created by valv init"
fi

echo "(f) Unicode names: å, é, Hangul; NFD input stored as NFC"
# "café å 한" and "Hem/Kök/한국", in NFC and in NFD (decomposed accents and
# conjoining Hangul jamo).
name_nfc=$(printf 'caf\303\251 \303\245 \355\225\234')
dir_nfc=$(printf 'Hem/K\303\266k/\355\225\234\352\265\255')
name_nfd=$(printf 'cafe\314\201 a\314\212 \341\204\222\341\205\241\341\206\253')
dir_nfd=$(printf 'Hem/Ko\314\210k/\341\204\222\341\205\241\341\206\253\341\204\200\341\205\256\341\206\250')
printf 'unicode test\n' > "$work/plain_f"

# meta_ok ID NAME_NFC: Swift reads the stored metadata as the NFC bytes.
meta_ok() {
    "$tool" show-meta "$vault/vault.json" "$(objpath "$vault" "$1")" < "$pass" > "$work/meta_$1" 2>&1 || return 1
    grep -qx "name_hex: $(hexof "$2")" "$work/meta_$1" && grep -qx "dir_hex: $(hexof "$dir_nfc")" "$work/meta_$1" \
        && grep -qx "nfc: true" "$work/meta_$1"
}
# go_reads NAME_NFC: valv ls lists dir/name in NFC and valv get by that path returns the file.
go_reads() {
    "$valv" ls --vault "$vault" --passphrase-stdin < "$pass" > "$work/ls_f" 2>&1 || return 1
    LC_ALL=C grep -qF "$dir_nfc/$1" "$work/ls_f" || return 1
    "$valv" get "$dir_nfc/$1" -o "$work/f_get" --force --vault "$vault" --passphrase-stdin < "$pass" > /dev/null 2>&1 || return 1
    cmp -s "$work/plain_f" "$work/f_get"
}

inbox_cases=""
for form in nfc nfd; do
    if [ "$form" = nfc ]; then name=$name_nfc; dir=$dir_nfc; else name=$name_nfd; dir=$dir_nfd; fi

    want="${name_nfc}_go_$form.txt"
    id=$("$valv" add "$work/plain_f" --vault "$vault" --dir "$dir" --name "${name}_go_$form.txt" --passphrase-stdin < "$pass" 2>&1) || true
    if meta_ok "$id" "$want" && go_reads "$want"; then
        ok "$form input, Go writes: stored as NFC, Swift reads it, valv get by NFC path"
    else
        bad "$form input, Go writes ($id): $(cat "$work/meta_$id" 2>/dev/null | tr '\n' ' ')"
    fi

    want="${name_nfc}_swift_$form.txt"
    id=$("$tool" encrypt-object "$vault/vault.json" "$work/plain_f" "$work/f_obj" --name "${name}_swift_$form.txt" --dir "$dir" < "$pass")
    mkdir -p "$vault/objects/$(echo "$id" | cut -c1-2)"
    mv "$work/f_obj" "$(objpath "$vault" "$id")"
    if meta_ok "$id" "$want" && go_reads "$want"; then
        ok "$form input, Swift writes an object: stored as NFC, valv ls and valv get by NFC path"
    else
        bad "$form input, Swift writes an object ($id): $(cat "$work/meta_$id" 2>/dev/null | tr '\n' ' ')"
    fi

    id=$("$tool" seal-inbox "$vault/vault.json" "$work/plain_f" "$work/f_inb" --name "${name}_inbox_$form.txt" --dir "$dir" < "$pass")
    mv "$work/f_inb" "$vault/inbox/$id.inb"
    inbox_cases="$inbox_cases $form:$id"
done
"$valv" ingest --vault "$vault" --passphrase-stdin < "$pass" > "$work/ingest_f" 2>&1 || true
for pair in $inbox_cases; do
    form=${pair%%:*}; id=${pair#*:}
    want="${name_nfc}_inbox_$form.txt"
    if [ ! -e "$vault/inbox/$id.inb" ] && meta_ok "$id" "$want" && go_reads "$want"; then
        ok "$form input, Swift seals an inbox file, Go ingests: stored as NFC, valv get by NFC path"
    else
        bad "$form input, Swift-sealed inbox file ($id): $(cat "$work/ingest_f") $(cat "$work/meta_$id" 2>/dev/null | tr '\n' ' ')"
    fi
done
if LC_ALL=C grep -qF "$(printf '\314')" "$work/ls_f"; then
    bad "valv ls shows a combining mark: some name was stored in NFD"
else
    ok "no stored name or dir contains a combining accent"
fi

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
