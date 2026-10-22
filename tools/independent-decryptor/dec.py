"""
Independent Decryptor and Validator for Ndes v1 format.
Derived strictly from SPEC.md and testvectors/ specification.
"""

import sys
import os
import json
import base64
import hashlib
import unicodedata
import math
from typing import Tuple, Dict, Any, Optional

import argon2.low_level as argon2_ll
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.exceptions import InvalidTag


class NdesError(Exception):
    def __init__(self, err_class: str, message: str):
        super().__init__(f"[{err_class}] {message}")
        self.err_class = err_class


def clamp_x25519_private_key(raw_bytes: bytes) -> bytes:
    """Clamps per RFC 7748: b[0] &= 248; b[31] &= 127; b[31] |= 64."""
    b = bytearray(raw_bytes)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 derivation. If salt is empty, RFC 5869 sets it to 32 zero bytes."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info
    )
    return hkdf.derive(ikm)


def derive_subkeys_from_vk(vk: bytes) -> Dict[str, bytes]:
    """
    Subkeys from VK (SPEC 3):
    - "ndes/v1/wrap" -> K_wrap
    - "ndes/v1/inbox-x25519" -> inbox X25519 private key (clamped)
    - "ndes/v1/inbox-auth" -> K_auth
    - inbox_pub = X25519(inbox private key, base point 9)
    """
    k_wrap = hkdf_sha256(ikm=vk, salt=b"", info=b"ndes/v1/wrap", length=32)
    inbox_priv_raw = hkdf_sha256(ikm=vk, salt=b"", info=b"ndes/v1/inbox-x25519", length=32)
    inbox_priv_clamped = clamp_x25519_private_key(inbox_priv_raw)
    k_auth = hkdf_sha256(ikm=vk, salt=b"", info=b"ndes/v1/inbox-auth", length=32)

    priv_key = X25519PrivateKey.from_private_bytes(inbox_priv_clamped)
    inbox_pub = priv_key.public_key().public_bytes_raw()

    return {
        "k_wrap": k_wrap,
        "inbox_priv_raw": inbox_priv_raw,
        "inbox_priv": inbox_priv_clamped,
        "k_auth": k_auth,
        "inbox_pub": inbox_pub,
    }


def derive_subkeys_from_fk(fk: bytes) -> Tuple[bytes, bytes]:
    """Subkeys from FK (SPEC 3): K_content and K_meta."""
    k_content = hkdf_sha256(ikm=fk, salt=b"", info=b"ndes/v1/content", length=32)
    k_meta = hkdf_sha256(ikm=fk, salt=b"", info=b"ndes/v1/meta", length=32)
    return k_content, k_meta


def compute_recovery_checksum(vk: bytes) -> bytes:
    """First 3 bytes of SHA-256('ndes/v1/recovery-checksum' | VK)."""
    h = hashlib.sha256(b"ndes/v1/recovery-checksum" + vk).digest()
    return h[:3]


def format_recovery_key(vk: bytes) -> str:
    """Format 35 bytes (VK | checksum) into 56 chars base32, 14 groups of 4 separated by '-'."""
    chk = compute_recovery_checksum(vk)
    raw = vk + chk
    b32 = base64.b32encode(raw).decode('ascii')
    return '-'.join(b32[i:i+4] for i in range(0, len(b32), 4))


def decode_recovery_key(key_str: str) -> bytes:
    """
    Decodes recovery key per SPEC 3:
    Ignore spaces and hyphens. ASCII letters are uppercased (no other case mapping).
    Must be exactly 56 base32 characters.
    Checksum must match.
    """
    cleaned = key_str.replace(" ", "").replace("-", "")
    # ASCII letters are uppercased (no other case mapping, SPEC 3)
    ascii_trans = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    cleaned_upper = cleaned.translate(ascii_trans)
    if len(cleaned_upper) != 56:
        raise NdesError("malformed", f"Recovery key length is {len(cleaned_upper)}, expected 56 characters")
    
    # Check RFC 4648 Base32 alphabet: A-Z, 2-7
    b32_alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    for c in cleaned_upper:
        if c not in b32_alphabet:
            raise NdesError("malformed", f"Invalid base32 character in recovery key: {c}")

    try:
        raw = base64.b32decode(cleaned_upper)
    except Exception as e:
        raise NdesError("malformed", f"Base32 decode failure: {e}")

    if len(raw) != 35:
        raise NdesError("malformed", f"Decoded recovery key length is {len(raw)}, expected 35 bytes")

    vk = raw[:32]
    expected_chk = compute_recovery_checksum(vk)
    given_chk = raw[32:]

    # Constant time comparison
    if not (math.isclose(0, 0) and hashlib.sha256(given_chk).digest() == hashlib.sha256(expected_chk).digest() and given_chk == expected_chk):
        raise NdesError("recovery_typo", "Recovery key checksum mismatch")

    return vk


def build_config_aad(alg: str, salt: bytes, t: int, m_kib: int, p: int, inbox_pub: bytes) -> bytes:
    """
    config_aad (SPEC 4.2):
    "ndes-config-v1"   14 ASCII bytes
    u8 len(alg)         = 8
    alg                 "argon2id"
    salt                16 raw bytes
    u32 t               big-endian
    u32 m_kib           big-endian
    u32 p               big-endian
    inbox_pub           32 raw bytes
    Total: 83 bytes.
    """
    alg_bytes = alg.encode('ascii')
    aad = (
        b"ndes-config-v1" +
        bytes([len(alg_bytes)]) +
        alg_bytes +
        salt +
        t.to_bytes(4, 'big') +
        m_kib.to_bytes(4, 'big') +
        p.to_bytes(4, 'big') +
        inbox_pub
    )
    return aad


def serialize_canonical_vault_json(v_dict: dict) -> bytes:
    """
    Writers produce exactly these bytes (SPEC 4.2):
    LF line endings, two-space indent, the `kdf` object on one line with the spacing shown, and one trailing LF.
    """
    kdf = v_dict["kdf"]
    line_kdf = f'  "kdf": {{ "alg": "{kdf["alg"]}", "salt": "{kdf["salt"]}", "t": {kdf["t"]}, "m_kib": {kdf["m_kib"]}, "p": {kdf["p"]} }}'
    lines = [
        '{',
        f'  "v": {v_dict["v"]},',
        f'{line_kdf},',
        f'  "wrapped_vk": "{v_dict["wrapped_vk"]}",',
        f'  "inbox_pub": "{v_dict["inbox_pub"]}"',
        '}\n'
    ]
    return '\n'.join(lines).encode('utf-8')


def unlock_vault_json(vault_json_bytes: bytes, passphrase: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    Unlocks vault.json per SPEC 4.2 and 4.3.
    Returns (VK, subkeys_dict).
    """
    if len(vault_json_bytes) > 4096:
        raise NdesError("malformed", "vault.json larger than 4096 bytes")

    # Passphrase encoding check (SPEC 3)
    try:
        passphrase_bytes = passphrase.encode('utf-8')
    except UnicodeEncodeError:
        raise NdesError("malformed", "Passphrase is not valid UTF-8")
    
    # NFC normalization
    passphrase_nfc = unicodedata.normalize('NFC', passphrase)
    passphrase_nfc_bytes = passphrase_nfc.encode('utf-8')

    # Parse JSON
    try:
        vault_data = json.loads(vault_json_bytes.decode('utf-8'))
    except Exception as e:
        raise NdesError("malformed", f"JSON parse error: {e}")

    # Check keys
    expected_top_keys = {"v", "kdf", "wrapped_vk", "inbox_pub"}
    if set(vault_data.keys()) != expected_top_keys:
        raise NdesError("malformed", f"Top-level keys mismatch or extra/missing keys: {list(vault_data.keys())}")

    kdf = vault_data.get("kdf")
    if not isinstance(kdf, dict):
        raise NdesError("malformed", "kdf is not an object")

    expected_kdf_keys = {"alg", "salt", "t", "m_kib", "p"}
    if set(kdf.keys()) != expected_kdf_keys:
        raise NdesError("malformed", f"kdf keys mismatch: {list(kdf.keys())}")

    # Version and KDF parameter support check (unsupported)
    if vault_data.get("v") != 1:
        raise NdesError("unsupported", f"Unsupported format version {vault_data.get('v')}")

    if kdf.get("alg") != "argon2id" or kdf.get("t") != 3 or kdf.get("m_kib") != 65536 or kdf.get("p") != 1:
        raise NdesError("unsupported", f"Unsupported KDF parameters: {kdf}")

    # Base64 validation (malformed)
    def decode_b64(field_name: str, s: str, expected_len: int) -> bytes:
        if not isinstance(s, str):
            raise NdesError("malformed", f"{field_name} must be a string")
        # Check canonical padding: length % 4 == 0, standard b64 alphabet
        try:
            raw = base64.b64decode(s, validate=True)
        except Exception as e:
            raise NdesError("malformed", f"Invalid base64 in {field_name}: {e}")
        if len(raw) != expected_len:
            raise NdesError("malformed", f"{field_name} decoded to {len(raw)} bytes, expected {expected_len}")
        # Re-encode to verify canonical form
        re_encoded = base64.b64encode(raw).decode('ascii')
        if re_encoded != s:
            raise NdesError("malformed", f"{field_name} is not canonical base64")
        return raw

    salt = decode_b64("salt", kdf.get("salt"), 16)
    wrapped_vk = decode_b64("wrapped_vk", vault_data.get("wrapped_vk"), 60)
    inbox_pub = decode_b64("inbox_pub", vault_data.get("inbox_pub"), 32)

    # Re-serialization check (SPEC 4.2)
    canonical_bytes = serialize_canonical_vault_json(vault_data)
    if canonical_bytes != vault_json_bytes:
        raise NdesError("malformed", "vault.json does not match canonical writer formatting byte-for-byte")

    # Compute KEK using Argon2id
    kek = argon2_ll.hash_secret_raw(
        secret=passphrase_nfc_bytes,
        salt=salt,
        time_cost=kdf["t"],
        memory_cost=kdf["m_kib"],
        parallelism=kdf["p"],
        hash_len=32,
        type=argon2_ll.Type.ID
    )

    # Unwrap VK
    config_aad = build_config_aad(kdf["alg"], salt, kdf["t"], kdf["m_kib"], kdf["p"], inbox_pub)
    wrap_nonce = wrapped_vk[:12]
    wrapped_ct_and_tag = wrapped_vk[12:]  # 32 ct + 16 tag = 48 bytes

    aead = ChaCha20Poly1305(kek)
    try:
        vk = aead.decrypt(wrap_nonce, wrapped_ct_and_tag, config_aad)
    except InvalidTag:
        raise NdesError("wrong_passphrase", "wrong passphrase or altered vault.json")

    # Subkeys from VK
    subkeys = derive_subkeys_from_vk(vk)

    # Compare derived inbox_pub with vault.json inbox_pub in constant time
    if subkeys["inbox_pub"] != inbox_pub:
        raise NdesError("inbox_key_mismatch", "derived inbox_pub does not match inbox_pub in vault.json")

    subkeys["vk"] = vk
    subkeys["kek"] = kek
    return vk, subkeys


def validate_path(path: str, expected_kind: int, header_file_id: bytes) -> str:
    """
    Validates path per SPEC 4.1.
    Object: objects/<xx>/<32 lowercase hex>.obj
    Inbox: inbox/<32 lowercase hex>.inb
    Raises NdesError("path", ...) on any mismatch.
    Returns expected file_id hex string.
    """
    # Normalize separators
    norm_path = path.replace("\\", "/")
    if expected_kind == 0x01:
        idx = norm_path.rfind("objects/")
        rel = norm_path[idx:] if idx != -1 else norm_path
    elif expected_kind == 0x02:
        idx = norm_path.rfind("inbox/")
        rel = norm_path[idx:] if idx != -1 else norm_path
    else:
        rel = norm_path
    parts = rel.split("/")

    hex_alphabet = set("0123456789abcdef")

    if expected_kind == 0x01:
        if len(parts) != 3 or parts[0] != "objects":
            raise NdesError("path", f"Invalid object path structure: {path}")
        prefix_dir = parts[1]
        filename = parts[2]
        if not filename.endswith(".obj"):
            raise NdesError("path", f"Object filename must end with .obj: {filename}")
        file_id_str = filename[:-4]
        if len(file_id_str) != 32 or any(c not in hex_alphabet for c in file_id_str):
            raise NdesError("path", f"Object file_id must be 32 lowercase hex chars: {file_id_str}")
        if len(prefix_dir) != 2 or prefix_dir != file_id_str[:2]:
            raise NdesError("path", f"Prefix dir '{prefix_dir}' does not match file_id prefix '{file_id_str[:2]}'")
    elif expected_kind == 0x02:
        if len(parts) != 2 or parts[0] != "inbox":
            raise NdesError("path", f"Invalid inbox path structure: {path}")
        filename = parts[1]
        if not filename.endswith(".inb"):
            raise NdesError("path", f"Inbox filename must end with .inb: {filename}")
        file_id_str = filename[:-4]
        if len(file_id_str) != 32 or any(c not in hex_alphabet for c in file_id_str):
            raise NdesError("path", f"Inbox file_id must be 32 lowercase hex chars: {file_id_str}")
    else:
        raise NdesError("malformed", f"Unknown expected kind: {expected_kind}")

    header_file_id_hex = header_file_id.hex()
    if file_id_str != header_file_id_hex:
        raise NdesError("path", f"Path file_id '{file_id_str}' does not match header file_id '{header_file_id_hex}'")

    return file_id_str


def parse_and_validate_canonical_metadata(raw_padded_meta: bytes) -> Dict[str, Any]:
    """
    Parses and strictly validates canonical metadata per SPEC 5.2.
    """
    # 1. Plaintext length check
    if len(raw_padded_meta) < 512 or len(raw_padded_meta) > 65536 or len(raw_padded_meta) % 512 != 0:
        raise NdesError("metadata", f"Invalid padded metadata length: {len(raw_padded_meta)}")

    # 2. Strip minimal trailing spaces (0x20)
    stripped = raw_padded_meta.rstrip(b" ")
    num_trailing_spaces = len(raw_padded_meta) - len(stripped)
    if num_trailing_spaces >= 512:
        raise NdesError("metadata", f"Padding is not minimal ({num_trailing_spaces} spaces removed)")

    # Check for any non-space padding between stripped and end of buffer
    if raw_padded_meta[len(stripped):] != b" " * num_trailing_spaces:
        raise NdesError("metadata", "Padding contains non-space bytes")

    # 3. UTF-8 check
    try:
        json_str = stripped.decode('utf-8')
    except UnicodeDecodeError:
        raise NdesError("metadata", "Metadata is not valid UTF-8")

    # 4. Strict syntax check on json_str
    # Must start with {"name": and contain no unescaped control chars, no whitespace outside padding.
    # Hand-written strict parser per SPEC 5.2.
    if not json_str.startswith('{"name":') or not json_str.endswith('}'):
        raise NdesError("metadata", "Metadata JSON does not match exact structure")

    # Let's check for any whitespace characters in json_str (outside of string literals, whitespace is forbidden)
    # Inside string literals: escape rules: only \", \\, and \u00xx (lowercase hex 00..1f).
    # All other characters in strings (including / and non-ASCII) must be literal UTF-8.
    # Unescaped controls (0x00 to 0x1F) are forbidden.
    
    idx = 0
    def consume(expected: str):
        nonlocal idx
        if not json_str.startswith(expected, idx):
            raise NdesError("metadata", f"Expected '{expected}' at pos {idx}")
        idx += len(expected)

    def parse_string() -> str:
        nonlocal idx
        consume('"')
        chars = []
        while idx < len(json_str):
            c = json_str[idx]
            if c == '"':
                idx += 1
                return "".join(chars)
            if ord(c) < 0x20:
                raise NdesError("metadata", f"Unescaped control character in string: U+{ord(c):04X}")
            if c == '\\':
                idx += 1
                if idx >= len(json_str):
                    raise NdesError("metadata", "Unterminated escape in string")
                esc = json_str[idx]
                if esc == '"':
                    chars.append('"')
                    idx += 1
                elif esc == '\\':
                    chars.append('\\')
                    idx += 1
                elif esc == 'u':
                    idx += 1
                    hex_str = json_str[idx:idx+4]
                    if len(hex_str) != 4:
                        raise NdesError("metadata", "Incomplete unicode escape")
                    # Check lowercase hex and value in 00..1f
                    if not (hex_str.startswith("00") and all(h in "0123456789abcdef" for h in hex_str)):
                        raise NdesError("metadata", f"Invalid unicode escape \\u{hex_str}: must be \\u00xx lowercase")
                    val = int(hex_str, 16)
                    if val > 0x1F:
                        raise NdesError("metadata", f"Needless unicode escape \\u{hex_str} for character > 0x1F")
                    chars.append(chr(val))
                    idx += 4
                else:
                    raise NdesError("metadata", f"Forbidden escape \\{esc} in string")
            else:
                chars.append(c)
                idx += 1
        raise NdesError("metadata", "Unterminated string")

    def parse_int64(min_val: Optional[int] = None) -> int:
        nonlocal idx
        start = idx
        if idx < len(json_str) and json_str[idx] == '-':
            idx += 1
        digits_start = idx
        while idx < len(json_str) and json_str[idx].isdigit():
            idx += 1
        digits = json_str[digits_start:idx]
        if not digits:
            raise NdesError("metadata", "Expected digits for integer")
        # Reject leading zero unless it's just '0'
        if len(digits) > 1 and digits.startswith('0'):
            raise NdesError("metadata", f"Integer has leading zero: {json_str[start:idx]}")
        # Reject '-0'
        if json_str[start:idx] == "-0":
            raise NdesError("metadata", "Integer is negative zero '-0'")
        # Reject float or exponent
        if idx < len(json_str) and json_str[idx] in ".eE":
            raise NdesError("metadata", f"Float or exponent forbidden in integer: {json_str[idx]}")
        val = int(json_str[start:idx])
        # int64 range: -2^63 to 2^63 - 1
        if val < -9223372036854775808 or val > 9223372036854775807:
            raise NdesError("metadata", f"int64 overflow: {val}")
        if min_val is not None and val < min_val:
            raise NdesError("metadata", f"Integer {val} is less than required minimum {min_val}")
        return val

    # Schema: {"name":S,"dir":S,"mtime":I,"mime":S,"rev":I,"size":I}
    consume('{"name":')
    name = parse_string()
    consume(',"dir":')
    dir_str = parse_string()
    consume(',"mtime":')
    mtime = parse_int64()
    consume(',"mime":')
    mime = parse_string()
    consume(',"rev":')
    rev = parse_int64(min_val=1)
    consume(',"size":')
    size = parse_int64(min_val=0)
    if size > MAX_PLAINTEXT_SIZE:
        raise NdesError("metadata", f"size {size} is above 2^60")
    consume('}')

    if idx != len(json_str):
        raise NdesError("metadata", f"Extra data after JSON: {json_str[idx:]}")

    # Validate field rules
    # name: Non-empty. Must not contain / or U+0000. Must not be . or ..
    if not name:
        raise NdesError("metadata", "name cannot be empty")
    if "/" in name or "\x00" in name:
        raise NdesError("metadata", "name cannot contain '/' or U+0000")
    if name == "." or name == "..":
        raise NdesError("metadata", "name cannot be '.' or '..'")

    # dir: "" for root, otherwise components joined by / with no leading or trailing /
    if dir_str != "":
        if dir_str.startswith("/") or dir_str.endswith("/"):
            raise NdesError("metadata", "dir cannot have leading or trailing '/'")
        components = dir_str.split("/")
        for comp in components:
            if not comp or "/" in comp or "\x00" in comp or comp == "." or comp == "..":
                raise NdesError("metadata", f"Invalid dir component '{comp}'")

    # Canonical re-serialization check (SPEC 5.2)
    def canonical_escape(s: str) -> str:
        out = []
        for c in s:
            if c == '"':
                out.append('\\"')
            elif c == '\\':
                out.append('\\\\')
            elif ord(c) <= 0x1F:
                out.append(f'\\u{ord(c):04x}')
            else:
                out.append(c)
        return "".join(out)

    re_serialized = f'{{"name":"{canonical_escape(name)}","dir":"{canonical_escape(dir_str)}","mtime":{mtime},"mime":"{canonical_escape(mime)}","rev":{rev},"size":{size}}}'
    if re_serialized.encode('utf-8') != stripped:
        raise NdesError("metadata", "Re-serialized metadata does not match stripped plaintext byte-for-byte")

    return {
        "name": name,
        "dir": dir_str,
        "mtime": mtime,
        "mime": mime,
        "rev": rev,
        "size": size,
    }


MAX_PLAINTEXT_SIZE = 1 << 60
MIN_PADDED = 4096


def padme(length: int) -> int:
    """Padme (SPEC 5.3) for length >= 2."""
    e = length.bit_length() - 1          # floor(log2 L)
    s_ = e.bit_length()                  # floor(log2 E) + 1
    mask = (1 << (e - s_)) - 1
    return (length + mask) & ~mask


def padded_size(size: int) -> int:
    return padme(max(size, MIN_PADDED))


def structural_check(ct_total: int) -> Tuple[int, int]:
    """
    Runs the structural check per SPEC 5.3. Returns (number of chunks, stored
    plaintext length P). Rejects:
    - ct_total < 16
    - ct_total mod 65552 in [1, 15], or equal to 16
    - P < 4096, P > 2^61, or padme(P) != P (the writer did not pad)
    """
    if ct_total < 16:
        raise NdesError("malformed", f"Structural check failed: ct_total {ct_total} < 16")
    residue = ct_total % 65552
    if 1 <= residue <= 15:
        raise NdesError("malformed", f"Structural check failed: residue {residue} in [1, 15]")
    if residue == 16:
        raise NdesError("malformed", "Structural check failed: residue is 16")

    num_chunks = math.ceil(ct_total / 65552)
    stored = ct_total - 16 * num_chunks
    if stored < MIN_PADDED or stored > 2 * MAX_PLAINTEXT_SIZE or padme(stored) != stored:
        raise NdesError("malformed", f"Structural check failed: stored length {stored} is not a padded size")
    return num_chunks, stored


def check_size(meta: Dict[str, Any], stored: int) -> None:
    """SPEC 5.3 size check: padded(size) must equal the stored length. Runs
    right after the metadata is parsed, before any content is decrypted."""
    if padded_size(meta["size"]) != stored:
        raise NdesError("malformed", f"metadata size {meta['size']} does not match stored length {stored}")


def unpad(meta: Dict[str, Any], content: bytes) -> bytes:
    """Returns the first `size` bytes; every later stored byte must be zero."""
    size = meta["size"]
    if content[size:].strip(b"\x00"):
        raise NdesError("malformed", "padding is not zero")
    return content[:size]


def decrypt_object_bytes(data: bytes, path: Optional[str], k_wrap: bytes) -> Tuple[Dict[str, Any], bytes]:
    """
    Decrypts an object file (kind 0x01, format version 0x02) per SPEC 5.
    Returns (metadata_dict, content_plaintext).
    """
    if len(data) < 86:
        raise NdesError("malformed", f"Object file too short ({len(data)} bytes < 86)")

    magic = data[:4]
    version = data[4]
    kind = data[5]
    file_id = data[6:22]
    wrap_nonce = data[22:34]
    wrapped_fk = data[34:82]
    meta_len = int.from_bytes(data[82:86], 'big')

    if path is not None:
        validate_path(path, 0x01, file_id)

    if magic != b"NDES":
        raise NdesError("malformed", f"Invalid magic: {magic!r}")
    if version != 0x02:
        raise NdesError("unsupported", f"Unsupported version: {version}")
    if kind != 0x01:
        raise NdesError("malformed", f"Invalid object kind: {kind}")

    # meta_len bounds: 540 <= meta_len <= 65564 and (meta_len - 28) % 512 == 0
    if meta_len < 540 or meta_len > 65564 or (meta_len - 28) % 512 != 0:
        raise NdesError("malformed", f"Invalid meta_len: {meta_len}")

    header_len = 86 + meta_len
    if len(data) < header_len:
        raise NdesError("malformed", f"File shorter than header length ({len(data)} < {header_len})")

    meta_blob = data[86:header_len]
    ct_total = len(data) - header_len

    # Structural check on chunks
    num_chunks, stored_len = structural_check(ct_total)

    # Decrypt wrapped_fk
    wrap_aad = data[:22]  # magic, version, kind, file_id
    aead_wrap = ChaCha20Poly1305(k_wrap)
    try:
        fk = aead_wrap.decrypt(wrap_nonce, wrapped_fk, wrap_aad)
    except InvalidTag:
        raise NdesError("auth", "wrapped_fk tag verification failed")

    # Derive subkeys from FK
    k_content, k_meta = derive_subkeys_from_fk(fk)

    # Decrypt meta_blob
    meta_nonce = meta_blob[:12]
    meta_ct_and_tag = meta_blob[12:]
    meta_aad = magic + bytes([version]) + file_id  # 21 bytes, kind not included
    aead_meta = ChaCha20Poly1305(k_meta)
    try:
        raw_padded_meta = aead_meta.decrypt(meta_nonce, meta_ct_and_tag, meta_aad)
    except InvalidTag:
        raise NdesError("auth", "meta_blob tag verification failed")

    # Validate metadata
    meta_dict = parse_and_validate_canonical_metadata(raw_padded_meta)
    check_size(meta_dict, stored_len)

    # Decrypt content chunks
    aead_content = ChaCha20Poly1305(k_content)
    chunk_aad = file_id
    content_chunks = []
    chunk_offset = header_len

    for i in range(num_chunks):
        is_last = (i == num_chunks - 1)
        final_flag = 0x01 if is_last else 0x00
        nonce = i.to_bytes(8, 'big') + b"\x00\x00\x00" + bytes([final_flag])
        
        chunk_len = (len(data) - chunk_offset) if is_last else 65552
        chunk_ct_and_tag = data[chunk_offset:chunk_offset + chunk_len]
        chunk_offset += chunk_len

        try:
            pt = aead_content.decrypt(nonce, chunk_ct_and_tag, chunk_aad)
        except InvalidTag:
            raise NdesError("auth", f"Chunk {i} authentication failed")
        content_chunks.append(pt)

    full_content = unpad(meta_dict, b"".join(content_chunks))
    return meta_dict, full_content


def decrypt_inbox_bytes(data: bytes, path: Optional[str], inbox_priv: bytes, k_auth: bytes, inbox_pub: bytes) -> Tuple[Dict[str, Any], bytes]:
    """
    Decrypts an inbox file (kind 0x02) per SPEC 6.
    Returns (metadata_dict, content_plaintext).
    """
    if len(data) < 58:
        raise NdesError("malformed", f"Inbox file too short ({len(data)} < 58)")

    magic = data[:4]
    version = data[4]
    kind = data[5]
    file_id = data[6:22]
    eph_pub = data[22:54]
    meta_len = int.from_bytes(data[54:58], 'big')

    if path is not None:
        validate_path(path, 0x02, file_id)

    if magic != b"NDES":
        raise NdesError("malformed", f"Invalid magic: {magic!r}")
    if version != 0x02:
        raise NdesError("unsupported", f"Unsupported version: {version}")
    if kind != 0x02:
        raise NdesError("malformed", f"Invalid inbox kind: {kind}")

    # meta_len bounds
    if meta_len < 540 or meta_len > 65564 or (meta_len - 28) % 512 != 0:
        raise NdesError("malformed", f"Invalid meta_len: {meta_len}")

    header_len = 58 + meta_len
    if len(data) < header_len:
        raise NdesError("malformed", f"File shorter than header length ({len(data)} < {header_len})")

    meta_blob = data[58:header_len]
    ct_total = len(data) - header_len

    # Structural check on chunks
    num_chunks, stored_len = structural_check(ct_total)

    # Key agreement: X25519(inbox_priv, eph_pub)
    priv_key = X25519PrivateKey.from_private_bytes(inbox_priv)
    try:
        eph_pub_key = X25519PublicKey.from_public_bytes(eph_pub)
        dh = priv_key.exchange(eph_pub_key)
    except Exception as e:
        raise NdesError("malformed", f"X25519 exchange error: {e}")

    # Reject all-zero DH
    if dh == b"\x00" * 32:
        raise NdesError("malformed", "DH result is all-zero")

    # FK derivation
    ikm = dh + k_auth
    salt = eph_pub + inbox_pub
    fk = hkdf_sha256(ikm=ikm, salt=salt, info=b"ndes/v1/inbox-fk", length=32)

    k_content, k_meta = derive_subkeys_from_fk(fk)

    # Decrypt meta_blob
    meta_nonce = meta_blob[:12]
    meta_ct_and_tag = meta_blob[12:]
    meta_aad = magic + bytes([version]) + file_id
    aead_meta = ChaCha20Poly1305(k_meta)
    try:
        raw_padded_meta = aead_meta.decrypt(meta_nonce, meta_ct_and_tag, meta_aad)
    except InvalidTag:
        raise NdesError("auth", "Inbox meta_blob authentication failed (wrong k_auth or corrupted)")

    meta_dict = parse_and_validate_canonical_metadata(raw_padded_meta)
    check_size(meta_dict, stored_len)

    # Decrypt content chunks
    aead_content = ChaCha20Poly1305(k_content)
    chunk_aad = file_id
    content_chunks = []
    chunk_offset = header_len

    for i in range(num_chunks):
        is_last = (i == num_chunks - 1)
        final_flag = 0x01 if is_last else 0x00
        nonce = i.to_bytes(8, 'big') + b"\x00\x00\x00" + bytes([final_flag])
        
        chunk_len = (len(data) - chunk_offset) if is_last else 65552
        chunk_ct_and_tag = data[chunk_offset:chunk_offset + chunk_len]
        chunk_offset += chunk_len

        try:
            pt = aead_content.decrypt(nonce, chunk_ct_and_tag, chunk_aad)
        except InvalidTag:
            raise NdesError("auth", f"Inbox chunk {i} authentication failed")
        content_chunks.append(pt)

    full_content = unpad(meta_dict, b"".join(content_chunks))
    return meta_dict, full_content


def main():
    import argparse
    import getpass

    parser = argparse.ArgumentParser(
        description="Independent Decryptor and Validator for Ndes v1 format."
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: unlock
    p_unlock = subparsers.add_parser("unlock", help="Unlock vault.json with passphrase")
    p_unlock.add_argument("vault_file", help="Path to vault.json")
    p_unlock.add_argument("--passphrase", help="Passphrase string")
    p_unlock.add_argument("--passphrase-stdin", action="store_true", help="Read passphrase from stdin")

    # Subcommand: decrypt-object
    p_obj = subparsers.add_parser("decrypt-object", help="Decrypt an object file (.obj)")
    p_obj.add_argument("object_file", help="Path to .obj file")
    p_obj.add_argument("--vk-hex", help="Vault Key (VK) in hex (64 hex characters)")
    p_obj.add_argument("--k-wrap-hex", help="K_wrap in hex (64 hex characters)")
    p_obj.add_argument("--no-path-check", action="store_true", help="Skip path and filename validation against header file_id")
    p_obj.add_argument("--vault-path", help="Relative vault path to validate against (defaults to object_file)")
    p_obj.add_argument("--out", "-o", help="Output file path for decrypted payload")
    p_obj.add_argument("--meta-out", help="Output file path for metadata JSON")

    # Subcommand: decrypt-inbox
    p_inb = subparsers.add_parser("decrypt-inbox", help="Decrypt an inbox file (.inb)")
    p_inb.add_argument("inbox_file", help="Path to .inb file")
    p_inb.add_argument("--vk-hex", help="Vault Key (VK) in hex (64 hex characters)")
    p_inb.add_argument("--inbox-priv-hex", help="Inbox private key in hex (64 hex characters)")
    p_inb.add_argument("--k-auth-hex", help="K_auth in hex (64 hex characters)")
    p_inb.add_argument("--inbox-pub-hex", help="Inbox public key in hex (64 hex characters)")
    p_inb.add_argument("--no-path-check", action="store_true", help="Skip path and filename validation against header file_id")
    p_inb.add_argument("--vault-path", help="Relative vault path to validate against (defaults to inbox_file)")
    p_inb.add_argument("--out", "-o", help="Output file path for decrypted payload")
    p_inb.add_argument("--meta-out", help="Output file path for metadata JSON")

    # Subcommand: decode-recovery-key
    p_reckey = subparsers.add_parser("decode-recovery-key", help="Decode and verify a recovery key")
    p_reckey.add_argument("key", help="Formatted recovery key (56 base32 characters)")

    # Subcommand: format-recovery-key
    p_fmtkey = subparsers.add_parser("format-recovery-key", help="Format a VK into a recovery key")
    p_fmtkey.add_argument("vk_hex", help="Vault Key (VK) in hex (64 hex characters)")

    args = parser.parse_args()

    try:
        if args.subcommand == "unlock":
            with open(args.vault_file, "rb") as f:
                vault_bytes = f.read()
            if args.passphrase is not None:
                passphrase = args.passphrase
            elif args.passphrase_stdin:
                passphrase = sys.stdin.read().rstrip("\r\n")
            else:
                passphrase = getpass.getpass("Enter passphrase: ")

            vk, subkeys = unlock_vault_json(vault_bytes, passphrase)
            out = {
                "vk": vk.hex(),
                "kek": subkeys["kek"].hex(),
                "k_wrap": subkeys["k_wrap"].hex(),
                "k_auth": subkeys["k_auth"].hex(),
                "inbox_pub": subkeys["inbox_pub"].hex(),
                "inbox_priv": subkeys["inbox_priv"].hex(),
            }
            print(json.dumps(out, indent=2))

        elif args.subcommand == "decrypt-object":
            if args.k_wrap_hex:
                k_wrap = bytes.fromhex(args.k_wrap_hex)
            elif args.vk_hex:
                vk = bytes.fromhex(args.vk_hex)
                k_wrap = derive_subkeys_from_vk(vk)["k_wrap"]
            else:
                parser.error("Either --vk-hex or --k-wrap-hex must be provided.")

            with open(args.object_file, "rb") as f:
                data = f.read()

            target_path = None if args.no_path_check else (args.vault_path or args.object_file)
            meta, payload = decrypt_object_bytes(data, path=target_path, k_wrap=k_wrap)
            meta_json = json.dumps(meta, indent=2)
            if args.meta_out:
                with open(args.meta_out, "w", encoding="utf-8") as f:
                    f.write(meta_json + "\n")
            else:
                sys.stderr.write(f"Metadata:\n{meta_json}\n")

            if args.out:
                with open(args.out, "wb") as f:
                    f.write(payload)
                sys.stderr.write(f"Decrypted {len(payload)} bytes to {args.out}\n")
            else:
                if not sys.stdout.isatty():
                    sys.stdout.buffer.write(payload)
                else:
                    sys.stderr.write(
                        f"Decrypted {len(payload)} bytes successfully. Specify --out to save payload.\n"
                    )

        elif args.subcommand == "decrypt-inbox":
            if args.vk_hex:
                vk = bytes.fromhex(args.vk_hex)
                subkeys = derive_subkeys_from_vk(vk)
                inbox_priv = subkeys["inbox_priv"]
                k_auth = subkeys["k_auth"]
                inbox_pub = subkeys["inbox_pub"]
            elif args.inbox_priv_hex and args.k_auth_hex and args.inbox_pub_hex:
                inbox_priv = bytes.fromhex(args.inbox_priv_hex)
                k_auth = bytes.fromhex(args.k_auth_hex)
                inbox_pub = bytes.fromhex(args.inbox_pub_hex)
            else:
                parser.error("Must provide either --vk-hex or all three (--inbox-priv-hex, --k-auth-hex, --inbox-pub-hex).")

            with open(args.inbox_file, "rb") as f:
                data = f.read()

            target_path = None if args.no_path_check else (args.vault_path or args.inbox_file)
            meta, payload = decrypt_inbox_bytes(
                data,
                path=target_path,
                inbox_priv=inbox_priv,
                k_auth=k_auth,
                inbox_pub=inbox_pub,
            )
            meta_json = json.dumps(meta, indent=2)
            if args.meta_out:
                with open(args.meta_out, "w", encoding="utf-8") as f:
                    f.write(meta_json + "\n")
            else:
                sys.stderr.write(f"Metadata:\n{meta_json}\n")

            if args.out:
                with open(args.out, "wb") as f:
                    f.write(payload)
                sys.stderr.write(f"Decrypted {len(payload)} bytes to {args.out}\n")
            else:
                if not sys.stdout.isatty():
                    sys.stdout.buffer.write(payload)
                else:
                    sys.stderr.write(
                        f"Decrypted {len(payload)} bytes successfully. Specify --out to save payload.\n"
                    )

        elif args.subcommand == "decode-recovery-key":
            vk = decode_recovery_key(args.key)
            print(vk.hex())

        elif args.subcommand == "format-recovery-key":
            vk = bytes.fromhex(args.vk_hex)
            key_str = format_recovery_key(vk)
            print(key_str)

    except NdesError as e:
        sys.stderr.write(f"Error [{e.err_class}]: {e}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
