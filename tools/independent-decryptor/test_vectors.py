"""
Test runner to verify all positive and negative vectors in testvectors/vectors.json
using tools/independent-decryptor/dec.py.
"""

import os
import sys
import json
import base64
import unicodedata
import math

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "../.."))
sys.path.insert(0, SCRIPT_DIR)

from dec import (
    NdesError,
    unlock_vault_json,
    derive_subkeys_from_vk,
    decode_recovery_key,
    parse_and_validate_canonical_metadata,
    decrypt_object_bytes,
    decrypt_inbox_bytes,
)
import argon2.low_level as argon2_ll


def run_tests():
    repo_dir = REPO_DIR
    vectors_path = os.path.join(repo_dir, "testvectors/vectors.json")
    with open(vectors_path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    print("=== TASK 1: INDEPENDENT DECRYPTOR VERIFICATION ===")
    
    # 1. Vault test
    print("\n--- 1. Testing Vault Unlock & Derivations ---")
    v = doc["vault"]
    vault_bytes = open(os.path.join(repo_dir, "testvectors", v["file"]), "rb").read()
    vk, subkeys = unlock_vault_json(vault_bytes, v["passphrase"])
    assert vk.hex() == v["vk"], f"VK mismatch: {vk.hex()} != {v['vk']}"
    assert subkeys["kek"].hex() == v["kek"], f"KEK mismatch: {subkeys['kek'].hex()} != {v['kek']}"
    assert subkeys["k_wrap"].hex() == v["k_wrap"], f"k_wrap mismatch: {subkeys['k_wrap'].hex()} != {v['k_wrap']}"
    assert subkeys["k_auth"].hex() == v["k_auth"], f"k_auth mismatch: {subkeys['k_auth'].hex()} != {v['k_auth']}"
    assert subkeys["inbox_priv"].hex() == v["inbox_priv"], f"inbox_priv mismatch: {subkeys['inbox_priv'].hex()} != {v['inbox_priv']}"
    assert subkeys["inbox_pub"].hex() == v["inbox_pub"], f"inbox_pub mismatch: {subkeys['inbox_pub'].hex()} != {v['inbox_pub']}"
    print("  [PASS] vault.json unlocked successfully. All keys matched byte-for-byte.")

    # 1b. Passphrase normalization
    p_norm = v["passphrase_normalization"]
    salt = bytes.fromhex(v["salt"])
    for form in ["nfd_hex", "nfc_hex"]:
        p_bytes = bytes.fromhex(p_norm[form])
        p_str = p_bytes.decode("utf-8")
        # Normalize to NFC
        p_nfc = unicodedata.normalize("NFC", p_str).encode("utf-8")
        derived_kek = argon2_ll.hash_secret_raw(
            secret=p_nfc,
            salt=salt,
            time_cost=v["t"],
            memory_cost=v["m_kib"],
            parallelism=v["p"],
            hash_len=32,
            type=argon2_ll.Type.ID
        )
        assert derived_kek.hex() == p_norm["kek"], f"Passphrase norm KEK mismatch for {form}"
    print("  [PASS] Passphrase normalization (NFD and NFC) derived identical KEK.")

    # 2. Recovery keys
    print("\n--- 2. Testing Recovery Keys ---")
    rk_pos_count = 0
    rk_neg_count = 0
    for i, rk in enumerate(doc["recovery_keys"]):
        inp = rk["input"]
        exp_err = rk.get("error")
        if exp_err is None:
            # Positive vector
            dec_vk = decode_recovery_key(inp)
            assert dec_vk.hex() == v["vk"], f"Recovery key {i} decoded to wrong VK: {dec_vk.hex()}"
            rk_pos_count += 1
            print(f"  [PASS] Positive recovery key {i} verified.")
        else:
            # Negative vector
            try:
                decode_recovery_key(inp)
                raise AssertionError(f"Recovery key {i} unexpectedly passed, expected {exp_err}")
            except NdesError as e:
                assert e.err_class == exp_err, f"Recovery key {i} error mismatch: {e.err_class} != {exp_err}"
                rk_neg_count += 1
                print(f"  [PASS] Negative recovery key {i} rejected with expected class: {exp_err}")
    print(f"  Total recovery keys: {rk_pos_count} positive passed, {rk_neg_count} negative rejected correctly.")

    # 3. Metadata vectors
    print("\n--- 3. Testing Metadata Vectors ---")
    meta_pos_count = 0
    meta_neg_count = 0
    for i, m in enumerate(doc["metadata"]):
        exp_err = m.get("error")
        inp = m["input"]
        name = bytes.fromhex(inp["name_hex"]).decode("utf-8", errors="replace")
        dir_str = bytes.fromhex(inp["dir_hex"]).decode("utf-8", errors="replace")
        mime = bytes.fromhex(inp["mime_hex"]).decode("utf-8", errors="replace")
        mtime = int(inp["mtime"])
        rev = int(inp["rev"])
        size = int(inp["size"])
        
        # Test writer serialization and parser
        if exp_err is None:
            # Positive metadata vector
            # Reconstruct the padded bytes and test parse_and_validate_canonical_metadata
            canon_bytes = bytes.fromhex(m["canonical_json"])
            pad_len = m["padded_len"]
            padded = canon_bytes + b" " * (pad_len - len(canon_bytes))
            parsed = parse_and_validate_canonical_metadata(padded)
            # Check fields
            assert parsed["name"] == unicodedata.normalize("NFC", name), f"Metadata {i} name mismatch"
            assert parsed["dir"] == unicodedata.normalize("NFC", dir_str), f"Metadata {i} dir mismatch"
            assert parsed["mtime"] == mtime, f"Metadata {i} mtime mismatch"
            assert parsed["mime"] == mime, f"Metadata {i} mime mismatch"
            assert parsed["rev"] == rev, f"Metadata {i} rev mismatch"
            assert parsed["size"] == size, f"Metadata {i} size mismatch"
            meta_pos_count += 1
            print(f"  [PASS] Positive metadata vector {i} ('{m['description']}') verified.")
        else:
            # Negative metadata vector (writer must reject)
            is_rejected = False
            try:
                name_raw = bytes.fromhex(inp["name_hex"])
                name_str = name_raw.decode("utf-8")
            except UnicodeDecodeError:
                is_rejected = True

            try:
                dir_raw = bytes.fromhex(inp["dir_hex"])
                dir_str = dir_raw.decode("utf-8")
            except UnicodeDecodeError:
                is_rejected = True

            if not is_rejected:
                name_nfc = unicodedata.normalize("NFC", name_str)
                dir_nfc = unicodedata.normalize("NFC", dir_str)
                if not name_nfc or name_nfc in [".", ".."] or "/" in name_nfc or "\x00" in name_nfc:
                    is_rejected = True
                if dir_nfc != "":
                    if dir_nfc.startswith("/") or dir_nfc.endswith("/"):
                        is_rejected = True
                    for c in dir_nfc.split("/"):
                        if not c or c in [".", ".."] or "/" in c or "\x00" in c:
                            is_rejected = True
                if rev < 1:
                    is_rejected = True
                if size < 0 or size > (1 << 60):
                    is_rejected = True
                # Check padded size <= 65536
                canon = f'{{"name":"{name_nfc}","dir":"{dir_nfc}","mtime":{mtime},"mime":"{mime}","rev":{rev},"size":{size}}}'.encode('utf-8')
                pad_len = math.ceil(len(canon) / 512) * 512
                if pad_len > 65536:
                    is_rejected = True

            assert is_rejected, f"Negative metadata {i} was not rejected by writer rules"
            meta_neg_count += 1
            print(f"  [PASS] Negative metadata vector {i} ('{m['description']}') correctly rejected by writer.")

    # 4. Objects (5 positive objects)
    print("\n--- 4. Testing Positive Objects ---")
    obj_pos_count = 0
    for obj_entry in doc["objects"]:
        rel_path = obj_entry["file"]
        obj_path = os.path.join(repo_dir, "testvectors", rel_path)
        data = open(obj_path, "rb").read()
        expected_path = obj_entry["path"]
        
        meta, plaintext = decrypt_object_bytes(data, expected_path, subkeys["k_wrap"])
        
        # Verify plaintext
        plain_path = os.path.join(repo_dir, "testvectors", obj_entry["plaintext_file"])
        expected_plain = open(plain_path, "rb").read()
        assert plaintext == expected_plain, f"Plaintext mismatch for {rel_path}: {len(plaintext)} != {len(expected_plain)}"
        
        # Verify metadata
        exp_meta = obj_entry["meta"]
        assert meta["name"] == bytes.fromhex(exp_meta["name_hex"]).decode("utf-8"), f"Name mismatch for {rel_path}"
        assert meta["dir"] == bytes.fromhex(exp_meta["dir_hex"]).decode("utf-8"), f"Dir mismatch for {rel_path}"
        assert meta["mtime"] == int(exp_meta["mtime"]), f"Mtime mismatch for {rel_path}"
        assert meta["mime"] == bytes.fromhex(exp_meta["mime_hex"]).decode("utf-8"), f"Mime mismatch for {rel_path}"
        assert meta["rev"] == int(exp_meta["rev"]), f"Rev mismatch for {rel_path}"
        
        obj_pos_count += 1
        print(f"  [PASS] Object '{rel_path}' ({len(plaintext)} bytes) decrypted & verified byte-for-byte.")

    # 5. Inbox (1 inbox file and 1 ingested object)
    print("\n--- 5. Testing Positive Inbox Vectors ---")
    inb_pos_count = 0
    for inb_entry in doc["inbox"]:
        rel_path = inb_entry["file"]
        inb_path = os.path.join(repo_dir, "testvectors", rel_path)
        inb_data = open(inb_path, "rb").read()
        
        meta, plaintext = decrypt_inbox_bytes(
            inb_data,
            inb_entry["path"],
            subkeys["inbox_priv"],
            subkeys["k_auth"],
            subkeys["inbox_pub"]
        )
        plain_path = os.path.join(repo_dir, "testvectors", inb_entry["plaintext_file"])
        expected_plain = open(plain_path, "rb").read()
        assert plaintext == expected_plain, f"Plaintext mismatch for {rel_path}"
        inb_pos_count += 1
        print(f"  [PASS] Inbox file '{rel_path}' ({len(plaintext)} bytes) decrypted & verified byte-for-byte.")
        
        # Also verify ingested object
        ingest_rel = inb_entry["ingest"]["file"]
        ingest_path = os.path.join(repo_dir, "testvectors", ingest_rel)
        ingest_data = open(ingest_path, "rb").read()
        expected_obj_path = f"objects/{inb_entry['file_id'][:2]}/{inb_entry['file_id']}.obj"
        ingest_meta, ingest_plain = decrypt_object_bytes(
            ingest_data,
            expected_obj_path,
            subkeys["k_wrap"]
        )
        assert ingest_plain == expected_plain, f"Plaintext mismatch for ingested object {ingest_rel}"
        assert ingest_meta == meta, f"Metadata mismatch for ingested object {ingest_rel}"
        inb_pos_count += 1
        print(f"  [PASS] Ingested object '{ingest_rel}' ({len(ingest_plain)} bytes) decrypted & verified byte-for-byte.")

    # Summary of positive vectors verified:
    # 1 vault + 2 passphrase normalization + 3 recovery keys + 5 objects + 2 inbox + 9 metadata = 22 positive cases!
    print(f"\nPositive vectors summary: All positive vectors verified byte-for-byte!")

    # 6. Negative vectors (57 vectors)
    print("\n--- 6. Testing All Negative Vectors ---")
    neg_passed = 0
    neg_failed = 0
    for i, neg in enumerate(doc["negative"]):
        name = neg["name"]
        kind = neg["kind"]
        expected_err = neg["expect"]
        rel_file = neg["file"]
        file_path = os.path.join(repo_dir, "testvectors", rel_file)
        data = open(file_path, "rb").read()
        actual_err = None
        
        try:
            if kind == "vault":
                passphrase = neg.get("passphrase", "correct horse battery staple")
                unlock_vault_json(data, passphrase)
            elif kind == "object":
                path = neg.get("path")
                decrypt_object_bytes(data, path, subkeys["k_wrap"])
            elif kind == "inbox":
                path = neg.get("path")
                decrypt_inbox_bytes(data, path, subkeys["inbox_priv"], subkeys["k_auth"], subkeys["inbox_pub"])
            else:
                raise ValueError(f"Unknown kind {kind}")
        except NdesError as e:
            actual_err = e.err_class
        except Exception as e:
            actual_err = f"UnexpectedException({type(e).__name__}: {e})"

        if actual_err == expected_err:
            neg_passed += 1
            print(f"  [PASS] Negative {i:02d}: {name} -> rejected with {actual_err}")
        else:
            neg_failed += 1
            print(f"  [FAIL] Negative {i:02d}: {name} -> expected {expected_err}, got {actual_err}")

    print(f"\nNegative vectors summary: {neg_passed}/57 passed, {neg_failed} failed.")
    assert neg_failed == 0, f"{neg_failed} negative vectors failed!"
    print("\nALL POSITIVE AND NEGATIVE TEST VECTORS VERIFIED SUCCESSFULLY!")


if __name__ == "__main__":
    run_tests()
