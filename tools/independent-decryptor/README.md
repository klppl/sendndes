# Independent Ndes Decryptor & Validator

This directory contains a clean-room, independent Python 3 implementation of the **Ndes wire format (object and inbox format version 0x02)** decoder, validator, and decryptor. It was developed independently against `SPEC.md` without referencing the Go or Swift source code to provide an objective external verification tool.

---

## Prerequisites

Python 3.9+ with the following packages:

```bash
pip install cryptography argon2-cffi
```

---

## Components

- **`dec.py`**: Standalone decryption and validation library and CLI tool. Implements:
  - Argon2id passphrase hashing and vault unlocking (`vault.json`).
  - Key derivations (K_wrap, K_auth, K_content, K_meta, inbox X25519 keypair).
  - Recovery key formatting, checksum validation, and decoding.
  - Strict canonical metadata JSON parsing and validation.
  - Chunked streaming ChaCha20-Poly1305 authenticated object and inbox decryption.
  - Sharded directory and file_id path validation (SPEC §4.1).
- **`test_vectors.py`**: Test harness running all positive and all negative test vectors from `testvectors/vectors.json`.
- **`diff_fuzz.py`**: 3-way differential mutation fuzzer comparing the Go CLI (`ndes`), Swift tool (`ndes-swift-tool`), and Python `dec.py`.

---

## Running Against Test Vectors

To verify the independent decryptor against the full test vector suite:

```bash
python3 tools/independent-decryptor/test_vectors.py
```

This tests:
1. Vault unlocking, passphrase NFC normalization, and key derivation against `vault.json`.
2. Positive and negative recovery key formats and typo detection.
3. Canonical metadata constraints and rejection of invalid names/dirs/mtimes.
4. Positive object decryption byte-for-byte (`tiny.obj`, `multi.obj`, `exact.obj`, `empty.obj`, `nfd_name.obj`).
5. Positive inbox decryption byte-for-byte (`inbox.inb` and ingested object).
6. All all negative test vectors (tampered headers, wrong auth, bit flips, truncation, chunk reordering, bad path structures).

---

## Running Against Real Files

`dec.py` provides a CLI interface for interacting with real vault files.

### 1. Unlocking `vault.json`

Extract the Vault Key (VK) and derived subkeys using your passphrase:

```bash
python3 tools/independent-decryptor/dec.py unlock /path/to/vault.json --passphrase "your-passphrase"
```

Or read the passphrase from stdin:

```bash
echo "your-passphrase" | python3 tools/independent-decryptor/dec.py unlock /path/to/vault.json --passphrase-stdin
```

Output:
```json
{
  "vk": "...",
  "kek": "...",
  "k_wrap": "...",
  "k_auth": "...",
  "inbox_pub": "...",
  "inbox_priv": "..."
}
```

### 2. Decrypting an Object File (`.obj`)

Decrypt an encrypted object stored in `objects/xx/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.obj`:

```bash
# Decrypt and save payload to file
python3 tools/independent-decryptor/dec.py decrypt-object \
  /path/to/vault/objects/7c/7c600a1cfb7fd7f124bf7bfc7df095f6.obj \
  --vk-hex <VK_HEX> \
  --out recovered.bin
```

Options:
- `--vk-hex <hex>`: 32-byte Vault Key (derives `k_wrap` automatically).
- `--k-wrap-hex <hex>`: 32-byte K_wrap directly.
- `--out <path>`: Write decrypted content to file (if omitted and stdout is piped, writes to stdout).
- `--meta-out <path>`: Save canonical metadata as JSON.
- `--no-path-check`: Skip checking that the file path matches `objects/<2hex>/<30hex>.obj` matching the header file ID.

### 3. Decrypting an Inbox File (`.inb`)

Decrypt an incoming inbox item stored in `inbox/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.inb`:

```bash
python3 tools/independent-decryptor/dec.py decrypt-inbox \
  /path/to/vault/inbox/c6f7c8ec171c775706aa8f5dd4764d25.inb \
  --vk-hex <VK_HEX> \
  --out recovered.bin
```

Or using explicit inbox subkeys:

```bash
python3 tools/independent-decryptor/dec.py decrypt-inbox \
  /path/to/vault/inbox/c6f7c8ec171c775706aa8f5dd4764d25.inb \
  --inbox-priv-hex <PRIV_HEX> \
  --k-auth-hex <K_AUTH_HEX> \
  --inbox-pub-hex <PUB_HEX> \
  --out recovered.bin
```

### 4. Recovery Keys

Decode a 56-character base32 recovery key to recover the Vault Key:

```bash
python3 tools/independent-decryptor/dec.py decode-recovery-key \
  YZQJ-OKVM-PFZX-N2U7-QVOY-POBU-UHUK-X52P-ULFY-SQG3-F2JL-7RPK-D3KJ-UVUK
```

Format a raw Vault Key hex string into a formatted recovery key:

```bash
python3 tools/independent-decryptor/dec.py format-recovery-key <VK_HEX>
```

---

## 3-Way Differential Fuzzing

To run the mutation-based differential fuzzer that verifies equivalence between Go, Swift, and Python:

```bash
python3 tools/independent-decryptor/diff_fuzz.py --cases 20
```

This fuzzer mutates objects, inbox files, recovery keys, and path headers, ensuring all three implementations accept or reject every case identically.

---

## Security Audit Notice

This tool contains no hardcoded secrets, embedded private keys, or credentials. It operates strictly on standard cryptographic primitives and user-supplied files.
