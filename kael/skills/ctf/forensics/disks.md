---
name: ctf-forensics-disks
description: Disk and filesystem forensics in CTF — file carving, NTFS/exFAT/ext4 alternate data streams, $MFT, deleted file recovery, forensic suite tools (Autopsy, Sleuth Kit, FTK Imager)
---

# CTF Forensics — Disk & Filesystem

The "I have a disk image, find the flag" challenge. Often the flag is hidden in:
- A deleted file (recover from slack space, MFT, or unallocated clusters)
- A file's alternate data stream (NTFS ADS)
- A partition table gap (between partitions)
- A file's metadata (EXIF, document properties, ZIP comment)
- A custom file format (the challenge file *is* the flag, with obfuscation)
- A filesystem journal / log
- An encrypted container (VeraCrypt, LUKS, BitLocker)

## 1. The 5-Minute Triage

```bash
file evidence.img                # what is this?
file -s /dev/sdb                 # if it's a raw device
binwalk evidence.img             # embedded files?
strings -n 8 evidence.img | head -50
fls -r evidence.img              # Sleuth Kit: list all files (recovers deleted too)
istat evidence.img <inode>       # Sleuth Kit: show inode info
mmls evidence.img                # Sleuth Kit: list partitions
fsstat evidence.img              # FS info
```

**Quick file format identification:**
- `file -i` for MIME type
- `xxd evidence.img | head -50` for hex view of header
- `binwalk -e` to extract anything binwalk recognizes
- `foremost -i evidence.img -o output/` for signature-based recovery

## 2. NTFS (the most common CTF disk type)

### Alternate Data Streams (ADS)
NTFS allows multiple "data streams" per file. `file:stream_name`.
```bash
# Mount the image
sudo mount -o ro,loop,ntfs3 evidence.img /mnt

# List ADS
fls -r evidence.img | grep -i "::"
# or
getfattr -R -d -m ".*" /mnt/ 2>/dev/null

# Extract an ADS
icat evidence.img <inode>:<stream_name> > stream_dump.bin
```

**ADS in PowerShell:**
```powershell
Get-Content -Path C:\path\file.txt:stream
Set-Content -Path C:\path\file.txt:hidden -Value "secret data"
```

### $MFT Recovery
The Master File Table is the heart of NTFS. Each file has an MFT entry. When a file is deleted, the MFT entry is marked free, but the data isn't immediately overwritten.
```bash
fls -r -d evidence.img          # `-d` shows deleted entries
# Find the inode of the flag file
istat evidence.img <inode>      # shows the data
icat evidence.img <inode>       # extract the data
```

### $LogFile, $UsnJrnl, $Bitmap
- `$LogFile` — NTFS journal; recent changes are here
- `$UsnJrnl:$J` — USN journal; change log per file
- `$Bitmap` — allocation bitmap; shows which clusters are in use
- `$Secure` — security descriptors
- `$I30` — directory index; can leak filenames of deleted files

```bash
# Parse the USN journal (requires Python)
python3 -c "
import struct
with open('UsnJrnl', 'rb') as f:
    data = f.read()
# Each record is at least 64 bytes; skip 64-byte header between records
# See: https://github.com/PoorBillionaire/Windows-Post-Exploitation
"
```

## 3. ext4 / Linux Filesystem

```bash
# Mount
sudo mount -o ro,loop evidence.img /mnt

# List deleted files
sudo debugfs -R "lsdel" /dev/loop0
# Recover a deleted file
sudo debugfs -R "dump <deleted_inode> /tmp/recovered_file" /dev/loop0

# extundelete (the all-in-one tool)
sudo extundelete evidence.img --restore-all
# or
sudo extundelete evidence.img --restore-file path/to/file
```

## 4. FAT / exFAT

```bash
# Sleuth Kit
fls -r evidence.img
istat evidence.img <inode>
icat evidence.img <inode>
# Testdisk / photorec (for unallocated space)
sudo photorec /d /tmp/recovered/ evidence.img
```

## 5. File Carving (no filesystem metadata)

When the filesystem is corrupt, the data is unallocated, or the disk is a flat dump:

```bash
# foremost: signature-based
foremost -i evidence.img -o /tmp/recovered/
# Configurable signature file at /etc/foremost.conf

# binwalk: embedded file detection + extraction
binwalk -e evidence.img
# Recursive (extract, then scan extracted for more)
binwalk -e --dd='.*' evidence.img

# photorec: 300+ file types, magic-based
photorec /d /tmp/recovered/ evidence.img
# Interactive; select partition and file types

# scalpel: faster than foremost, more configurable
scalpel -c /etc/scalpel/scalpel.conf -o /tmp/recovered/ evidence.img
```

## 6. Forensic Image Formats

### E01 (EnCase) — common in CTF
```bash
# Convert to raw with ewfexport or libewf
ewfinfo evidence.E01
ewfexport evidence.E01 -o evidence.raw
# Or use ewfmount (FUSE)
mkdir /mnt/ewf
ewfmount evidence.E01 /mnt/ewf
# The raw image is at /mnt/ewf/ewf1
```

### AFF4
```bash
# Use aff4imager
aff4imager extract evidence.aff4 /tmp/recovered/
```

### Memory dump (`.raw`, `.lime`, `.vmem`)
See `memory.md` for the full workflow.

## 7. The "Hidden in Plain Sight" Patterns

### ZIP inside a JPG (and vice versa)
```bash
binwalk -e image.jpg
# Or manually
unzip image.jpg                  # if it's a ZIP with the JPG as the local header
```

### Data appended after a file
```bash
# Carve at the end of a JPG
xxd image.jpg | tail
# The file ends with 0xff 0xd9
# Anything after is appended
dd if=image.jpg of=hidden.zip bs=1 skip=<end_of_jpg>
```

### Alternate ZIP / RAR archive
```bash
# A ZIP file can be prepended with arbitrary data
# Run unzip and see the start
unzip -l image.jpg     # sometimes works
```

### Base64 in EXIF
```bash
exiftool image.jpg
# Look for UserComment, ImageDescription, XP fields
exiftool -b -UserComment image.jpg | base64 -d
exiftool -b -ImageDescription image.jpg | base64 -d
```

### Steganography in PNG chunks
```bash
# Each PNG chunk is type:length:data:CRC
pngcheck -v image.png
# Or:
python3 -c "
import struct
data = open('image.png', 'rb').read()
i = 8
while i < len(data):
    length = struct.unpack('>I', data[i:i+4])[0]
    chunk_type = data[i+4:i+8].decode()
    chunk_data = data[i+8:i+8+length]
    if chunk_type not in ('IHDR', 'IDAT', 'IEND', 'PLTE', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'iCCP'):
        print(f'{chunk_type}: {chunk_data[:80]!r}')
    i += 8 + length + 4
"
```

## 8. Document Metadata

```bash
exiftool document.pdf
exiftool image.jpg
exiftool -a -u -G1 file.bin   # -a: all tags, -u: unknown tags, -G1: group by family

# Look for:
#   - Author
#   - Software (e.g. Adobe Acrobat 9.0)
#   - Comments
#   - Custom XMP fields
#   - Revision history
#   - Embedded files (PDF: /EmbeddedFiles, /Annots)
```

### PDF-specific
```bash
# qpdf
qpdf --qdf --object-streams=disable orig.pdf deobfuscated.pdf
# Now you can read the PDF objects directly
qpdf --show-object=1 --filtered-stream=1 orig.pdf
# Extract embedded files
binwalk -e document.pdf
# Or
python3 -c "
import zlib
# Parse PDF objects manually
"
```

### Office-specific
```bash
# Office files are ZIPs
unzip -l document.docx      # see the parts
# Custom XML parts often have the flag
unzip -p document.docx word/document.xml
unzip -p document.docx docProps/core.xml     # author, title
unzip -p document.docx docProps/custom.xml   # custom properties
```

## 9. The "Custom Container" Challenge

When `file` says it's a "data" or "DOS/MBR boot sector" with no obvious format, it's a custom container:
1. Read the header (first 32-64 bytes) in a hex editor
2. Look for magic, version, flags
3. Try `binwalk -e`, `foremost -i`
4. Common CTF custom formats: a ZIP with a custom local file header, an SQLite with a renamed table, a CSV with column shifts

## 10. The "Decrypt the Container" Challenge

```bash
# VeraCrypt
veracrypt evidence.tc /tmp/mnt -P <password>  # or --password=...

# LUKS
sudo cryptsetup luksOpen evidence.img encrypted
sudo mount /dev/mapper/encrypted /mnt

# BitLocker
sudo dislocker evidence.img -u<password> -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt
```

**Common CTF passwords:** `flag`, `password`, `123456`, `letmein`, the filename itself. Try `john --wordlist=rockyou.txt evidence.tc` with `veracrypt2john` and `john2hashcat`.

## Tooling

```bash
# Sleuth Kit (autopsy, fls, istat, icat, mmls, fsstat)
sudo apt install sleuthkit

# Autopsy GUI
sudo apt install autopsy

# Foremost, scalpel
sudo apt install foremost scalpel

# binwalk
pip install binwalk
# Or apt
sudo apt install binwalk

# TestDisk / PhotoRec
sudo apt install testdisk

# exiftool
sudo apt install libimage-exiftool-perl

# VeraCrypt, cryptsetup, dislocker
sudo apt install veracrypt cryptsetup dislocker

# ewfmount (libewf)
sudo apt install ewf-tools
```

## Common Pitfalls

- **Mounting read-write** — never mount forensic evidence RW; always `-o ro,loop` or copy first
- **Forgetting to check both partitions** — the challenge image may have multiple partitions; use `mmls` first
- **Skipping deleted files** — `fls -d` shows deleted inodes. The flag is often in a "deleted" file that can be recovered.
- **ADS hidden in `$i30`** — the directory index can leak alternate data stream names
- **EXIF thumbnail != full image** — the thumbnail is a separate JPEG; can contain different metadata
- **Custom format = read the spec** — many CTF custom formats are well-documented in the challenge's source

## Validation

A real forensic finding in CTF = **the flag string appears in the extracted data** (as a file's content, a comment, a metadata field, or a recovered deleted file).
