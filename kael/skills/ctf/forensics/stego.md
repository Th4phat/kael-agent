---
name: ctf-forensics-stego
description: Steganography in CTFs — image (LSB, stegsolve, steghide, zsteg), audio (Sonic Visualizer, Audacity, WavSteg), document (PDF, OLE), and protocol-level (DNS, IPID, ICMP) stego
---

# CTF Forensics — Steganography

The "I have a file, the flag is hidden in it" challenge. Stego can be in:
- **Pixel data** (LSB, MSB, palette order, channels swapped)
- **Frequency domain** (DCT, FFT of audio; transform of image)
- **File structure** (after the IEND, in an alternate ZIP, in PDF objects)
- **Metadata** (EXIF, IPTC, XMP)
- **Audio** (LSB, spectrogram, parity bits)
- **Network packets** (DNS, ICMP, IPID)
- **Whitespace** (zero-width characters, stegsnow)

## 1. The 5-Minute Stego Triage

```bash
file chall.bin
binwalk -e chall.bin
strings -n 8 chall.bin
exiftool chall.bin
xxd chall.bin | head -50
# Identify the type (image, audio, document, executable)
```

**Smell test:** if the file looks like a normal JPG/PNG/WAV, the flag is in the bytes. If it's a "data" or "DOS/MBR" type, the file is a custom container.

## 2. Image Stego

### PNG (lossless; LSB stego is the canonical CTF)

**zsteg** (the all-in-one):
```bash
gem install zsteg
zsteg chall.png
# Tries: LSB/MSB, all channel orders, all bit planes
# Output: <channel> <bit> <filename> ... <decoded>
```

**stegsolve** (Java GUI; the classic):
```bash
# Open the PNG, then iterate bit planes
# Bit 0 (LSB) of red, green, blue, alpha channels
# Anomalies often visible as a faint pattern

# Manual equivalent (Python)
from PIL import Image
img = Image.open('chall.png')
pixels = img.load()
# LSB of red channel, row-major
bits = ''
for y in range(img.height):
    for x in range(img.width):
        bits += str(pixels[x, y][0] & 1)
# Convert bits to bytes
text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
```

**StegOnline** (web): https://stegonline.georgeom.net/

**stegano** (Python):
```bash
pip install stegano
stegano-lsb reveal -i chall.png
```

**PNG chunks** (custom chunk types):
```bash
pngcheck -v chall.png
# Or:
python3 -c "
import struct
data = open('chall.png','rb').read()
i = 8  # skip signature
while i < len(data):
    length = struct.unpack('>I', data[i:i+4])[0]
    chunk_type = data[i+4:i+8].decode('latin1')
    chunk_data = data[i+8:i+8+length]
    if chunk_type not in ('IHDR','IDAT','IEND','PLTE','tRNS','gAMA','cHRM','sRGB','iCCP','bKGD','pHYs'):
        print(f'{chunk_type}: {chunk_data!r}')
    i += 8 + length + 4
"
```

### JPG (lossy; DCT stego is harder)

**steghide** (password-based):
```bash
steghide extract -sf chall.jpg
# If password-protected, brute with rockyou.txt:
stegcracker chall.jpg rockyou.txt
# Or: steghide extract -sf chall.jpg -p ""   # empty password
# Or: steghide info chall.jpg
```

**jsteg** (F5 stego, common in 2023-2024):
```bash
# Install
go install github.com/lukechampine/jsteg@latest
jsteg reveal chall.jpg > output.bin
# Or extract a hidden file
jsteg reveal chall.jpg -o output.bin
```

**outguess**:
```bash
apt install outguess
outguess -r chall.jpg output.bin
```

**F5** (the original F5 stego algorithm):
```bash
# https://github.com/matthewgao/F5-steganography
git clone https://github.com/matthewgao/F5-steganography
java Extract chall.jpg
```

**JPEG comment**:
```bash
exiftool chall.jpg | grep Comment
# Or:
python3 -c "
data = open('chall.jpg','rb').read()
# JPEG comments are markers 0xFFFE
i = 0
while i < len(data):
    if data[i] == 0xff and data[i+1] == 0xfe:
        length = (data[i+2] << 8) | data[i+3]
        print('Comment:', data[i+4:i+2+length].decode('utf-8', errors='replace'))
        i += 2 + length
    else:
        i += 1
"
```

### BMP / GIF

BMP: LSB stego with zsteg, or palette-order stego with `stegano`.
GIF: frame-by-frame, palette, or comment. `gifsicle -I chall.gif` shows frame info.

## 3. Audio Stego

### WavSteg / SilentEye / OpenPuff / DeepSound
```bash
# WavSteg — LSB in WAV
pip install wave-steganography
# Or: https://github.com/ragibson/WavSteg
python3 WavSteg.py -r -i chall.wav -o output.txt -n 1 -b 1000

# SilentEye (GUI)
# DeepSound (Windows)
```

### Spectogram
```bash
# Sonic Visualizer — see the spectrogram, often a flag is rendered as text
# Or: sox + ImageMagick
sox chall.wav -n spectrogram -o spectrogram.png
# Look for visible text in the frequency image
```

### Morse code in audio
```bash
# Often the audio is a Morse-coded flag
# https://morsecode.world/international/decoder/audio-decoder-adaptive.html
# Or use `morse2text` Python tool
```

### DTMF (touch tones)
```bash
# Multimon-ng
multimon-ng -t wav -a DTMF chall.wav
# Each tone = a digit/letter
```

### SSTV (slow-scan TV)
The audio is a TV image, encoded as audio. Decode with:
```bash
pip install pysstv
sstv -d chall.wav -o output.png
```

## 4. Document Stego

### PDF
```bash
# Embedded files
binwalk -e document.pdf
# Or:
pdftk document.pdf unpack_files /tmp/pdf_unpacked/
# Hidden text
pdftotext document.pdf -
# Annotations, JS, etc.
qpdf --qdf --object-streams=disable document.pdf deobf.pdf
# Then read deobf.pdf as text
```

### Office (OOXML)
```bash
# Office files are ZIPs; extract and look at custom XML parts
unzip -l document.docx
unzip -p document.docx word/document.xml
unzip -p document.docx word/settings.xml
unzip -p document.docx docProps/custom.xml
unzip -p document.docx docProps/app.xml
# Look for hidden text in white-on-white, 1pt font, off-screen
# Or VBA macros
unzip -p document.docx word/vbaProject.bin > vba.bin
olevba vba.bin
```

### OLE (legacy Office .doc)
```bash
# Use olevba, oledump
pip install oletools
olevba document.doc
oledump document.doc
```

## 5. Archive Stego

### ZIP
```bash
# ZIP comment
unzip -z archive.zip
# Or:
python3 -c "
import zipfile
print(zipfile.ZipFile('archive.zip').comment)
"
# Hidden files in zip (e.g. `\x00filename` or `../`)
unzip -l archive.zip
# Encrypted ZIP
fcrackzip -D -p rockyou.txt archive.zip
# Or: john zip2john + john
zip2john archive.zip > hash.txt
john hash.txt --wordlist=rockyou.txt
```

### Nested archives
A common CTF pattern: a ZIP inside a ZIP inside a RAR. Just keep extracting.
```bash
while [ -n "$(file chall.bin | grep -E 'archive|compressed')" ]; do
    mkdir extract && cd extract
    case "$(file ../chall.bin)" in
        *Zip*) unzip ../chall.bin ;;
        *gzip*) tar xzf ../chall.bin ;;
        *bzip2*) tar xjf ../chall.bin ;;
        *XZ*) tar xJf ../chall.bin ;;
        *7-zip*) 7z x ../chall.bin ;;
        *RAR*) unrar x ../chall.bin ;;
        *) break ;;
    esac
    cd .. && chall.bin=$(ls extract/ | head -1)
done
```

## 6. Network Stego (Covert Channels)

### ICMP payload
```bash
# Each ICMP echo has a data field; the flag can be in the payload
tshark -r capture.pcap -Y "icmp" -T fields -e data
# Or look at the original pcap in Wireshark
```

### DNS query names (exfil)
See `pcap.md`.

### IPID / TCP timestamp / TTL
- IPID can encode 16 bits of data
- TTL can encode 4 bits (low nibble)
- TCP timestamp can encode 32 bits per packet
```python
# Recover TTL covert channel
tshark -r capture.pcap -T fields -e ip.ttl
# First 4 packets have TTL = 65, 70, 65, 72 → ASCII 'A', 'F', 'A', 'H' (with offset)
```

## 7. Whitespace Stego

### stegsnow (snow + tabs and spaces)
```bash
stegsnow -C chall.txt   # extract hidden message
# Or: snow -C chall.txt
```

### Zero-width characters
```bash
# Some CTFs use Unicode zero-width characters (ZWS, ZWNJ, ZWJ, LRM/RLM)
# Paste into https://330k.github.io/misc_tools/unicode_steganography.html
```

## 8. The "Custom Stego" Challenge

When the standard tools don't find anything, the file uses a custom algorithm:
1. Open in a hex editor
2. Look for a magic number at the end (custom file format)
3. Look for repeating patterns (each 8 bytes = 1 char of the flag)
4. Read the challenge description carefully — the algorithm is usually described

## 9. Time-Based Stego

The flag is hidden in the file's modification time, the EXIF timestamp, or the ZIP entry's time. Compare to a reference (a similar file with known date).

## 10. The "Solver Cheat Sheet"

| File type | First try | Then | Then |
|---|---|---|---|
| PNG | `zsteg` | `stegano-lsb` | `pngcheck` (custom chunks) |
| JPG | `steghide extract` | `jsteg reveal` | `outguess -r` |
| BMP | `stegsolve` | LSB brute | `stegano-lsb` |
| GIF | `gifsicle` | comment + frame split | palette order |
| WAV | `sox ... spectrogram` | `WavSteg -r` | `multimon-ng` |
| MP3 | `sonic-visualizer` (spectrogram) | `mp3stego` | ID3 tags |
| PDF | `pdftotext` | `qpdf --qdf` | `binwalk` |
| DOCX | `unzip` + look at parts | `olevba` | macro |
| ZIP | `fcrackzip` | comment | nested |
| EXE | `strings` | `binwalk` | custom container |

## Tooling

```bash
# zsteg
gem install zsteg

# steghide
sudo apt install steghide

# outguess
sudo apt install outguess

# stegano
pip install stegano

# binwalk
pip install binwalk

# exiftool
sudo apt install libimage-exiftool-perl

# WavSteg
pip install wavsteg
# Or: https://github.com/ragibson/WavSteg

# sox (audio manipulation)
sudo apt install sox

# multimon-ng (DTMF, morse, etc.)
sudo apt install multimon-ng
```

## Common Pitfalls

- **Wrong file type** — `file` lies when the file's first bytes are magic from a different format. Always cross-check.
- **Steg needs a password** — try empty, the filename, the challenge name, common words from the challenge
- **PNG with RGBA** — sometimes only the alpha channel has the data; use the right `zsteg` filter
- **JPG and LSB doesn't work** — JPG is lossy; LSB in JPG is a different scheme (DCT-based, e.g. F5 / jsteg / outguess)
- **The flag is split across tools** — e.g. half in EXIF, half in the LSB. Combine findings.
- **Whitespace stego paste is corrupted** — copy-paste from a terminal can lose trailing spaces. Use a hex editor instead.

## Validation

A real stego finding in CTF = **the flag string is extracted by some tool**. The flag's exact location (LSB, comment, EXIF, custom chunk) is reported alongside.
