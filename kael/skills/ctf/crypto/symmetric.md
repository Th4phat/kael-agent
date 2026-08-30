---
name: ctf-crypto-symmetric
description: Symmetric crypto attacks in CTFs — block cipher modes (ECB/CBC/CTR), padding oracles, bit-flipping, hash length extension, AES/DES/XOR weaknesses
---

# CTF Symmetric Crypto

Block and stream ciphers, mode-of-operation attacks, MAC bypass, and the canonical "I broke the encryption and got the flag" workflow.

## 1. Block Cipher Modes — The Big Picture

```
ECB:  c[i] = E_k(p[i])              -- each block independent; PATTERNS LEAK
CBC:  c[i] = E_k(p[i] XOR c[i-1])  -- needs IV; padding oracle applies
CTR:  c[i] = p[i] XOR E_k(IV+i)     -- stream cipher; bit-flip possible
GCM:  c[i] = p[i] XOR E_k(IV+i), tag = GHASH(H, A, C)  -- nonce reuse = GAME OVER
```

## 2. ECB Mode Attacks

### Byte-at-a-time ECB decryption (the canonical CTF)
A server encrypts `prefix || attacker_input || suffix` with AES-ECB and returns the ciphertext. By varying input length and tracking block boundaries, you recover `suffix` byte-by-byte.

```python
from pwn import *
BLOCK = 16
def get_ct(prefix=b''):
    io.sendlineafter(b'> ', prefix.hex().encode())
    return bytes.fromhex(io.recvline().strip().decode())

# Goal: find a block boundary. Pad until the ciphertext length increases.
baseline = len(get_ct(b''))
for pad in range(1, BLOCK+1):
    if len(get_ct(b'A' * pad)) > baseline:
        align = (BLOCK - (baseline - pad) % BLOCK) % BLOCK
        break
# align the input so that the last byte of suffix is the last byte of a block
# Then brute the next byte by changing the last byte of the controlled block
```

**The byte-at-a-time attack:**
```python
# Suppose "AAAAAAAAAA" is 10 bytes of control, "secret" is 6 bytes of unknown
# We want to learn "secret" one byte at a time.
# Block 0: AAAAAAAAAAsecret          — first 10 A + 6 of secret (block 1)
# Block 1: AAAAs                     — first 4 A + 1 of secret (block 1, position 15)
#
# Brute the 1 unknown byte by varying the last A in the controlled prefix:
# "AAAAAAAAA" + "s" + "X"     — try all X, look for matching block 0
```

**Automated implementation:**
```python
# https://github.com/AerialX/cryptopals-py
# Or use cryptopals set 2 challenge 12
```

### Cut-and-paste ECB
When the input is encrypted as `c1 || c2` and the server decodes two separate fields, you can splice blocks together.

Example: server takes `email = "AAAAAAAAAAadmin" || padding` and a `role=`. By controlling the email, you can land a `role=admin` block in the right position.

```python
# Goal: get ciphertext that decrypts to "......admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
# 1. Craft "email" = "AAAAAAAAAAadmin" + 11 bytes of padding
# 2. Submit; the server gives ct = E(prefix || email || suffix)
# 3. Take the block that contains "admin\x0b\x0b..."
# 4. Submit it as the "role" parameter
```

## 3. CBC Bit-Flipping

For CBC mode, flipping a bit in `c[i]` flips the corresponding bit in `p[i+1]` of the next block.

```python
# If the decrypted plaintext is "user=guest" and you want "user=admin"
# Plaintext: "user=guest\x00\x00\x00\x00\x00\x00"
# Block N-1: "user=guest"
# Block N:   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#
# To turn "guest" → "admin?"  (different length: 5 vs 5 — works)
# Target:    "user=admin"
# Original:  "user=guest"
# Flip: "guest" XOR "admin?" = (specific XOR)
# Apply: c[block-1] XOR delta
```

**Example code:**
```python
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

target_pt_block = b"user=admin"   # 10 bytes, pad to 16
actual_pt_block = b"user=guest\x00\x00\x00\x00\x00\x00"   # 16 bytes
delta = xor(target_pt_block[:10], actual_pt_block[:10]) + b'\x00'*6
# delta is the XOR of the 10-byte change + 6 zero bytes
# Apply to c[block-1]: new_c[block-1] = c[block-1] XOR delta
```

**Common pattern — "IV manipulation" attack:**
If the IV is supplied by the user (or controlled via a query param), `p[0] = c[0] XOR IV` lets you set the first block of plaintext freely.

## 4. CBC Padding Oracle (Bleichenbacher for AES)

The server tells you if the decrypted padding is valid. You recover the plaintext in ~256 oracle calls per block.

```python
def padding_oracle_decrypt(oracle, ciphertext, block_size=16):
    """oracle(ct_bytes) -> True if valid padding, False otherwise."""
    plaintext = b''
    # For each byte, brute force from 0x00 to 0xff
    # See: https://github.com/AerialX/cryptopals-py/blob/master/challenge17.py
    # Cryptopals Set 3, Challenge 17
    ...

# The full algorithm (for each byte):
# 1. Set c[i-1] last byte = guess
# 2. Send c' to oracle
# 3. If valid: guess is correct
# 4. Recover the corresponding plaintext byte
```

**Implementation reference:** Cryptopals Set 3 Challenge 17 is the canonical implementation. ~16 * 256 = 4096 oracle calls per 16-byte block.

## 5. CTR Mode

CTR is a stream cipher. Same key + nonce = catastrophic reuse.

```python
# Reused nonce:
# c1 = p1 XOR keystream
# c2 = p2 XOR keystream
# c1 XOR c2 = p1 XOR p2
# If you know p1 (e.g. "user=guest\x00..."), you recover p2
```

### CTR bit-flipping
For CTR, `p[i] = c[i] XOR keystream[i]`. Flipping a bit in `c[i]` flips the corresponding bit in `p[i]`. **No block propagation**, unlike CBC.

```python
# Just XOR the change into the ciphertext at the same position
new_c = bytearray(c)
new_c[off:off+len(delta)] = xor(c[off:off+len(delta)], delta)
```

## 6. GCM (the 2024+ CTF-favored mode)

GCM has a one-shot nonce-reuse attack: if two messages use the same `(key, nonce)`, you recover the **GHASH key H** and forge arbitrary ciphertexts.

**Nonce-reuse scenario:**
```python
# c1, c2 encrypted with same (key, nonce)
# c1 XOR c2 = p1 XOR p2   (keystream cancels)
# If you know p1, you recover p2

# Also: GHASH auth key H is recoverable:
# H = (c1_XOR_known_prefix_of_p1) * inv(...)
# Once you have H, you can forge authentication tags for arbitrary messages
# See: https://github.com/AerialX/cryptopals-py/blob/master/challenge16.py
# Cryptopals Set 7 (AES-GCM)
```

**Polynomial math** (GCM uses GF(2^128)):
```python
# In GF(2^128), multiplication is XOR, exponentiation is a polynomial
# See: https://github.com/AerialX/cryptopals-py/blob/master/util/gf.py
```

## 7. Hash Length Extension (SHA-256, MD5, SHA-512)

If the server computes `MAC(key, message)` as `H(key || message)` and you have `(message, MAC)`, you can extend the message and forge a new MAC.

**Conditions:** key length known (or brute-able), hash is `SHA-256` / `MD5` / `SHA-512` (or another Merkle-Damgård hash), no HMAC construction.

**Tool: `hashpumpy` or `hlextend`**
```bash
pip install hlextend
python3 -c "
import hlextend
sha = hlextend.new('sha256')
new_msg, new_mac = sha.extend(b'attack', b'|admin=true', 16, b'<orig_mac>')
"
```

```python
# Detailed walkthrough:
# Original: server computes sha256(key || msg) and compares to MAC
# Given: msg="comment=view", mac=<hash>
# Want:   msg="comment=view|admin=true" with a valid mac
#
# 1. Pad the original to a multiple of 64 bytes
# 2. Continue the hash with the extension bytes
# 3. Forge a new MAC
# Done.
```

**Defense:** use `HMAC` or `HMAC-SHA256`, not `H(key || msg)`.

## 8. AES-CBC with predictable IV (the 2024+ subtle bug)

If the IV is all zeros (or a constant), and the same plaintext is encrypted twice, the first block of ciphertext is identical. The leak is small but consistent.

**More dangerous:** if the server stores `(IV, ciphertext)` and lets you choose `IV`, you can:
- Decrypt: `p[0] = D(c[0]) XOR IV`. If you have a padding oracle, full decryption.
- Re-encrypt: choose `IV` to make the first block of plaintext whatever you want.

## 9. Stream Cipher Reuse (RC4, ChaCha20)

```python
# RC4 reuse: c1 = p1 XOR keystream, c2 = p2 XOR keystream
# c1 XOR c2 = p1 XOR p2
# If you know p1, recover p2 (crib-dragging)

# ChaCha20 reuse: same, plus the nonce+counter is in the keystream
```

## 10. The "Multi-Layer Encoding" Trap

CTF challenges often layer multiple encodings (a "decoder ring"):

```
flag = base64(aes_enc(key1, base64(xor(b"key2", flag_data))))
```

**Approach:** work backwards, peeling one layer at a time. Use `cyberchef` (the GUI tool) for visual chaining.

## Common Pitfalls

- **Forgetting the IV** — many CTF challenges hide the IV in the cipher; you need to include it for the padding oracle attack
- **Wrong block size** — AES is 16 bytes, ChaCha is 32, etc. Mismatched block size = wrong plaintext recovery
- **Forgetting the key length in length extension** — `hashpumpy` needs the key length; brute it from 0 to 32 if unknown
- **Misidentifying the cipher** — "AES" in a Python script might be AES-ECB on one input and AES-CBC on another
- **CTR keystream alignment** — block index = byte_offset // 16
- **GCM with random nonces** — looks safe; the CTF often makes the nonce visible, so reuse is detectable
- **Subtle: the server uses `H(key || msg)` with a keyed-hash but the key is `""` (empty)** — then length extension works trivially

## Tooling

```bash
# hashpump / hlextend
pip install hlextend

# CyberChef (GUI, install as web app)
# https://github.com/gchq/CyberChef

# pycryptodome
pip install pycryptodome

# Sage for GF(2^128) math (GCM)
sage
```

## One-Liner Cheat Sheet

```python
# Hash length extension
python3 -c "import hlextend; s = hlextend.new('sha256'); print(s.extend(b'data', b'|admin=true', 16, b'mac_bytes'))"

# CBC bit-flip
def flip(c, block, delta): c[block*16:block*16+16] = xor(c[block*16:block*16+16], delta)

# ECB byte-at-a-time brute
# See cryptopals set 2 challenge 12

# GCM nonce-reuse recovery
# See cryptopals set 7 challenge 15-16
```
