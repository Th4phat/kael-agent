---
name: ctf-misc-encodings
description: Multi-layer encodings in CTFs — base64/32/58/85/91, hex, URL, Morse, Braille, ASCII85, UUencode, esoteric languages, and the "decoder ring" workflow
---

# CTF Misc — Encodings

The "decrypt the chain of encodings" challenge. Often the flag is wrapped in 5-10 layers of encodings: base64 → hex → URL → Morse → Braille → something custom.

## 1. The Cheat Sheet (one-liner per encoding)

```bash
# Hex
echo "48656c6c6f" | xxd -r -p
# Or
python3 -c "import binascii; print(binascii.unhexlify('48656c6c6f'))"

# Base64
echo "SGVsbG8=" | base64 -d
# Or: python3 -c "import base64; print(base64.b64decode('SGVsbG8='))"

# Base32 (uppercase + digits 2-7, padding =)
echo "JBSWY3DPEB3W64TMMQQQ====" | base32 -d

# Base58 (Bitcoin alphabet, no 0OIl)
python3 -c "import base58; print(base58.b58decode('StV1DL6CwTryKyV').decode())"

# Base85 (ASCII85)
python3 -c "import base64; print(base64.a85decode('<~87cURD]j7BEbo80~>'))"
# b85 variant
python3 -c "import base64; print(base64.b85decode('HelloWorld'))"

# Base91
python3 -c "import base91; print(base91.decode('HelloWorld'))"
# Or: pip install base91

# URL encoding
python3 -c "from urllib.parse import unquote; print(unquote('%48%65%6c%6c%6f'))"

# HTML entities
python3 -c "import html; print(html.unescape('&lt;script&gt;'))"

# Unicode escapes
python3 -c "print('\u0048\u0065\u006c\u006c\u006f')"

# ROT13
python3 -c "import codecs; print(codecs.encode('Hello', 'rot_13'))"

# ROT-n (any n)
python3 -c "
def rot_n(s, n):
    out = ''
    for c in s:
        if 'a' <= c <= 'z':
            out += chr((ord(c) - ord('a') + n) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            out += chr((ord(c) - ord('A') + n) % 26 + ord('A'))
        else:
            out += c
    return out
print(rot_n('Hello', 13))
"

# Morse code
python3 -c "
MORSE = {'.-': 'A', '-...': 'B', ...}
print(''.join(MORSE.get(w, '?') for w in '.... . .-.. .-.. ---'.split()))
"
# Or: pip install morse-audio-decoder

# Braille
python3 -c "
BRAILLE = {'100000': 'a', '101000': 'b', ...}
# Standard Braille: 6-dot, dots 1-6 mapped to bits
"

# Binary
python3 -c "print(bytes([int('01001000', 2)]))"
python3 -c "
def from_binary(s):
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))
print(from_binary('0100100001100101011011000110110001101111'))
"

# Octal
python3 -c "print(bytes([int('110', 8)]))"

# Decimal (each byte as decimal)
python3 -c "
def from_decimal(s):
    return bytes(int(x) for x in s.split())
print(from_decimal('72 101 108 108 111'))
"

# ASCII85 (different delimiter)
python3 -c "import base64; print(base64.a85decode(b'87cURD]j7BEbo80'))"
```

## 2. Multi-Layer Decoding

When the input has multiple layers, peel one at a time:

```python
def is_base64(s):
    import re
    return bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', s)) and len(s) % 4 == 0
def is_base32(s):
    import re
    return bool(re.match(r'^[A-Z2-7]*={0,6}$', s)) and len(s) % 8 == 0
def is_hex(s):
    import re
    return bool(re.match(r'^[0-9a-fA-F]+$', s)) and len(s) % 2 == 0

def auto_decode(s):
    import base64
    while True:
        s = s.strip()
        decoded = None
        if is_base64(s):
            try:
                decoded = base64.b64decode(s, validate=True)
            except: pass
        elif is_base32(s):
            try:
                decoded = base64.b32decode(s)
            except: pass
        elif is_hex(s):
            try:
                decoded = bytes.fromhex(s)
            except: pass
        if decoded is None:
            break
        s = decoded.decode('utf-8', errors='replace')
    return s

# Or just use CyberChef with the "Magic" operation
```

## 3. Esoteric Languages

CTF sometimes gives you source in an esoteric language. Common ones:

### Brainfuck
```python
def brainfuck(code, input_data=b''):
    # 8 commands: > < + - . , [ ]
    # Standard interpreter
    ...
```

### JSFuck
```js
// Source is just []()!+ characters
// Decode with: node -e "eval('[][(![]+[])[+[]]+...')" // too long, use:
// https://jsfuck.com (online decoder)
```

### Malbolge
```python
# Too obscure to hand-write; use https://malbolge.doleczek.pl/
```

### Other
- **Ook!** — `Ook. Ook? Ook!`
- **Whitespace** — uses space, tab, newline
- **Piet** — looks like abstract art; https://www.bertnase.de/piet/
- **Shakespeare** — source is a Shakespeare play
- **Chef** — source is a recipe
- **HQ9+** — `H` = hello, `Q` = quine, `9` = 99 bottles, `+` = increment
- **Befunge** — 2D code
- **Deadfish** — `i d s o` commands

## 4. QR / Barcode / Data Matrix

```bash
# QR code
pip install pyzbar pillow
python3 -c "
from PIL import Image
from pyzbar.pyzbar import decode
print(decode(Image.open('chall.png')))
"
# Or: zbarimg
zbarimg chall.png
# Or: zxing-cpp (more decoders)
```

```bash
# PDF417, Code128, DataMatrix
zbarimg --raw chall.png
```

## 5. Encodings You Didn't Know Existed

- **Braille** (6-dot and 8-dot)
- **NATO phonetic alphabet** ("Alpha Bravo Charlie" → ABC)
- **Semaphore** (flag positions)
- **Maritime signal flags** (colored flags)
- **Tap code** (5x5 grid, like Polybius)
- **Pigpen cipher** (Masonic)
- **Rosicrucian cipher** (variant of Pigpen)
- **ASCII art** (read the visual text)
- **Webdings / Wingdings** (Microsoft font)
- **Hexahue** (colored squares, 2 per character)
- **Baudot code** (5-bit, early telegraph)
- **EBCDIC** (IBM mainframe encoding)
- **Baudot / ITA2**
- **Atbash** (reverse alphabet: A→Z, B→Y, ...)
- **Affine cipher** (ax + b mod 26)
- **Vigenere** (Caesar with a key)

## 6. The "First-Bytes Decoder" Approach

```python
def first_bytes_guess(data: bytes) -> str:
    """Guess the encoding from the first 16 bytes."""
    if data.startswith(b'\x89PNG'): return 'PNG image'
    if data.startswith(b'\xff\xd8\xff'): return 'JPEG image'
    if data.startswith(b'GIF8'): return 'GIF image'
    if data.startswith(b'PK\x03\x04'): return 'ZIP archive'
    if data.startswith(b'\x1f\x8b'): return 'gzip'
    if data.startswith(b'BZh'): return 'bzip2'
    if data.startswith(b'\x7fELF'): return 'ELF executable'
    if data.startswith(b'MZ'): return 'PE executable'
    if data.startswith(b'%PDF'): return 'PDF'
    if data.startswith(b'\xca\xfe\xba\xbe'): return 'Java class'
    if data.startswith(b'Rar!'): return 'RAR archive'
    if data.startswith(b'7z\xbc\xaf\x27\x1c'): return '7z archive'
    if all(32 <= b < 127 for b in data[:64]): return 'likely text/encoded'
    return 'unknown'
```

## 7. Common Custom Encodings

### XOR with a single byte
```python
def xor_decrypt(data, key):
    return bytes(b ^ key for b in data)

# Brute
for key in range(256):
    candidate = xor_decrypt(data, key)
    if all(32 <= b < 127 or b in (9, 10, 13) for b in candidate[:20]):
        print(f"key=0x{key:02x}: {candidate}")
```

### XOR with a multi-byte key (xortool)
```bash
pip install xortool
xortool -c 00 -b 8 chall.bin
# -c 00: assume null bytes in the plaintext
# -b 8: max key length 8
```

### Caesar / Vigenere / Affine
```python
# Brute Caesar
for shift in range(26):
    candidate = ''.join(chr((ord(c) - ord('a') + shift) % 26 + ord('a')) if c.islower() else
                        chr((ord(c) - ord('A') + shift) % 26 + ord('A')) if c.isupper() else c
                        for c in text)
    # Score by English bigram frequency
```

### Substitution cipher
- **Frequency analysis** — most common letters in English: e, t, a, o, i, n
- **Bigrams** — th, he, in, er, an
- **Trigrams** — the, and, tha, ent
- `quipqiup` (web tool) does this automatically: https://quipqiup.com

## 8. CyberChef as a Code Library

For programmatic CyberChef-style chains, see the `cyberchef_helper` tool we're adding to `kael/tools/ctf_tools/`.

## 9. The "Decode Without Knowing the Encoding" Trick

If you don't recognize the encoding but the output looks "alphabetical":
1. **Try base64 first** (most common)
2. **Try base32** (uppercase + digits 2-7)
3. **Try hex** (only [0-9a-f])
4. **Try base58** (Bitcoin-style, no 0OIl)
5. **Try base85** (has many special chars: `<~>`)
6. **Try ROT13** (text passes through)
7. **Try base64 with URL-safe alphabet** (`-_` instead of `+/`)

The 5-second "Magic" detector:
```python
import base64, re
def magic(s):
    s = s.strip()
    if re.match(r'^[A-Za-z0-9+/]*={0,2}$', s): return 'base64'
    if re.match(r'^[A-Z2-7]*={0,6}$', s): return 'base32'
    if re.match(r'^[0-9a-fA-F]+$', s): return 'hex'
    if re.match(r'^[01\s]+$', s): return 'binary'
    if re.match(r'^\d+(\s\d+)*$', s): return 'decimal'
    if re.match(r'^[A-Za-z0-9_-]+$', s) and not s.endswith('='): return 'base58 or base64url'
    return 'unknown'
```

## 10. Multi-Layer CTF Examples

```
# Example 1
Input: "5ome7hing"
↓
Base64 decode → "e0a0c4f..."
↓
Hex decode → "Å ¬Ä ï..."
↓
ASCII → gibberish
↓
# Wrong: try ROT13 first

# Example 2
Input: ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
↓
Morse → "HELLO WORLD"
↓
Caesar shift 3 → "KHOOR ZRUOG"  -- wait, that doesn't help
↓
# Read the challenge description

# Example 3
Input: "01001000 01101001"
↓
Binary → "Hi"
```

## Common Pitfalls

- **Multi-byte base64 padding** — `b64decode` is strict; some encoders use fewer padding chars
- **URL-safe base64 vs standard** — `-_` vs `+/`; if you get the wrong one, decode fails
- **Base32 with `0` and `1`** — some "base32" implementations include 0/1; this is non-standard
- **ROT13 is its own inverse** — applying it twice gives the original
- **XOR with a string key** — the key cycles; the actual "key" length is the period
- **Wrong endianness** — a hex byte stream might be in the wrong order
- **String in UTF-16 not UTF-8** — `bytes.decode('utf-16')` reveals the content
- **Layer where the "decoding" is just reversing** — the encoded form is the input reversed; `s[::-1]`

## Tooling

```bash
# CyberChef (GUI, but CLI available)
# CyberChef MCP server (programmatic)
# https://github.com/bee-san/CyberChef-MCP

# xortool
pip install xortool

# quipqiup (substitution cipher)
# Web: https://quipqiup.com

# dcode.fr (multi-cipher identifier and decoder)
# Web: https://www.dcode.fr

# BaseXX Python libs
pip install base58 base91 base-n

# Maltrieve / osint-python
```

## Validation

A real misc encoding finding in CTF = **the flag string is the result of decoding the chain**. The chain (which encodings, in what order) is reported alongside.
