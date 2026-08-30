---
name: ctf-osint-methodology
description: OSINT methodology for CTFs — geolocation, image OSINT, social media pivots, breach data, username enumeration, infrastructure mapping, and ethical considerations
---

# CTF OSINT Methodology

The "go find information in the wild" challenge. OSINT in CTFs covers:
- **Geolocation** — a photo, the flag is the address or city
- **Image OSINT** — reverse image search, EXIF, sun/moon/star analysis
- **Username / email OSINT** — find the same person on other platforms
- **Infrastructure OSINT** — DNS, certificates, ASN, BGP, historical data
- **Code & commit OSINT** — git history, leaked keys, exposed repos
- **Document OSINT** — open-source documents, PDFs, scans
- **Social media** — Twitter/X, Reddit, LinkedIn, niche platforms

## 1. The 5-Minute OSINT Triage

Before any tool:
1. **Read the challenge carefully** — every word is a hint. Names, dates, locations, references are often leads.
2. **Identify the question** — is the flag a place, a username, a person, a domain, a hash, a string?
3. **Run the cheap tools first** — reverse image search, `whois`, `dig`, `view-source`
4. **Pivot early** — the answer to one question is the input to the next

## 2. Geolocation

### The "Five Senses" Method
- **Sight** — what landmarks, signs, languages, license plates, power lines, road markings are visible?
- **Date / Time** — EXIF timestamp + sun position (suncalc.org) narrows location
- **Sound** — if audio: languages, accents, traffic
- **Side channels** — weather (snow in winter?), vegetation (cacti vs pines), architecture

### EXIF
```bash
exiftool image.jpg
# Look for:
#   - GPS Latitude / GPS Longitude
#   - GPS Altitude
#   - Date/Time Original
#   - Camera model (regional firmware, language)
#   - Software (sometimes leaks language)
#   - Make of camera (e.g. Xiaomi in China, Canon in Japan)
```

### Sun position
```bash
# Use the EXIF timestamp + a guess of the location
# Check suncalc.org or:
python3 -c "
import ephem
# observer at the EXIF timestamp; sun position depends on location
# Trial: try several locations, see which one matches the shadow direction
"
```

### Reverse image search
- Google Lens (web, mobile)
- TinEye (web)
- Yandex Images (best for Russia / Eastern Europe / CIS)
- Bing Visual Search

### Street View verification
- Google Street View (most countries)
- Mapillary (open-source)
- KartaView (open-source)

### License plate / signage
- License plate format narrows the country
- Road sign shape narrows the country
- Power line spacing / style (US: 3 wires, EU: 4)

## 3. Image OSINT

### Metadata deep-dive
```bash
exiftool -a -u -G1 -api RequestAll=3 image.jpg
# -a: all tags
# -u: include unknown tags
# -G1: group by family
# -api RequestAll=3: read all sub-IFDs

# XMP data (often overlooked)
exiftool -xmp:all image.jpg

# IPTC data
exiftool -iptc:all image.jpg

# Thumbnail (often different from the main image — used to "leak" original)
exiftool -b -ThumbnailImage image.jpg > thumb.jpg
exiftool thumb.jpg
```

### Editing software
- Photoshop → "Adobe Photoshop CC 2019 (Macintosh)"
- Lightroom → "Adobe Lightroom Classic"
- GIMP → "GNU Image Manipulation Program"
- Pixelmator / Affinity Photo → macOS tools
- Localized (Russian/Chinese) Photoshop → narrows the country

### Hidden data in the image
- Steganography (see stego skill)
- LSB patterns
- QR codes or barcodes in the image
- Subliminal text in the lowest RGB values

## 4. Username / Email OSINT

### Username enumeration
```bash
# Check a username across many platforms
# sherlock
pip install sherlock-project
sherlock username
# Or: https://whatsmyname.app (web)
# Or: maigret
pip install maigret
maigret username
```

### Email OSINT
```bash
# Holehe
pip install holehe
holehe email@example.com
# Checks 120+ platforms for account existence (no password)
```

### Gravatar
```bash
# Email → Gravatar hash → look up
python3 -c "
import hashlib
email = 'test@example.com'.strip().lower()
print('https://www.gravatar.com/avatar/' + hashlib.md5(email.encode()).hexdigest())
"
```

### HIBP / breach data
```bash
# HaveIBeenPwned (API)
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/email" -H "hibp-api-key: $API_KEY"
# Dehashed (paid)
# IntelligenceX (paid)
```

## 5. Infrastructure OSINT

### DNS
```bash
dig target.com ANY
dig target.com MX
dig target.com NS
dig target.com TXT
dig -x 1.2.3.4    # reverse
# Subdomains
amass enum -d target.com -passive
subfinder -d target.com -silent
# Certificate transparency
curl "https://crt.sh/?q=%25.target.com&output=json" | jq
```

### ASN / IP
```bash
whois -h whois.radb.net 1.2.3.4
# Or:
curl "https://stat.ripe.net/data/whois/data.json?resource=1.2.3.4"
# ASN lookup
curl "https://stat.ripe.net/data/as-overview/data.json?resource=AS12345"
```

### BGP / routing
```bash
# Hurricane Electric BGP
# https://bgp.he.net/ip/1.2.3.4
# Shows the ASN, prefix, peers
```

### Historical data
- **Wayback Machine** (web.archive.org) — past versions of a site
- **viewdns.info/iphistory** — historical DNS
- **SecurityTrails** — historical DNS / WHOIS
- **Censys / Shodan** — historical certificates and banners

### Cloud buckets
```bash
# AWS S3
curl -s "https://target.s3.amazonaws.com/" | head
curl -s "https://target.s3.amazonaws.com/?list-type=2" | head
# Azure
curl -s "https://target.blob.core.windows.net/?comp=list"
# GCP
curl -s "https://storage.googleapis.com/storage/v1/b/target/o"
```

## 6. Code & Commit OSINT

### GitHub search
```bash
# GitHub dorks
site:github.com "target.com" "password"
site:github.com "target.com" "api_key"
# Or use GitHub search UI
```

### Git history
```bash
# If a repo is leaked:
git log --all
git log -p --all | grep -i "flag\|password\|secret"
# Look for accidental commits (then reset)
git reflog
# Look for branches
git branch -a
# Look for stash
git stash list
# Look for tags
git tag
```

### Sourcegraph
- `https://sourcegraph.com/search?q=context:global+%22target.com%22+password&patternType=keyword`
- Indexes public GitHub / GitLab / Bitbucket

### Code search engines
- `publicwww.com` — find pages with a given string
- `searchcode.com` — code search
- `grep.app` — code search over public repos

## 7. Social Media OSINT

### Twitter / X
- Advanced search: `from:user since:2024-01-01 until:2024-12-31`
- The `media` tab shows all images / videos
- Look at replies and quote tweets (often leak more than the original)
- Look at the Liked / Liked tweets

### Reddit
- Search by user, subreddit, time range
- User's posts / comments history

### LinkedIn
- Employee enumeration (target company)
- Job posts leak tech stack
- `Google cache:` for deleted profiles

### Specific platforms
- Telegram (channels, public groups)
- Discord (user IDs, server IDs, message links)
- Mastodon (instance-specific search)
- TikTok / Instagram (creator's other content)

## 8. Document OSINT

### File types
- PDF (often metadata-leaky)
- Office documents (author, comments, revision history)
- OpenDocument
- Images (EXIF)

### Tools
```bash
# PDF metadata
exiftool document.pdf
pdftotext document.pdf -
pdfinfo document.pdf
# Office
olevba document.doc
python3 -c "
import zipfile
z = zipfile.ZipFile('document.docx')
print(z.namelist())
for name in z.namelist():
    if 'custom' in name or 'core' in name:
        print(name, z.read(name))
"
```

## 9. The "Hidden Page" Trick

Some challenges hide a page in a public web property:
- `robots.txt` (often the challenge's hint)
- `sitemap.xml`
- `/.well-known/security.txt`
- Old version of the site (Wayback)
- A specific URL pattern (`/admin`, `/flag`, `/secret`, `/v1/flag`)

```bash
# Wayback
curl "http://web.archive.org/web/2024*/target.com/*"
# Or use waybackurls
go install github.com/tomnomnom/waybackurls@latest
echo "target.com" | waybackurls | grep -iE "flag|secret|admin"
```

## 10. Common CTF OSINT Patterns

| Pattern | Approach |
|---|---|
| Photo of a place | EXIF → lat/long; or sun position + landmarks |
| Photo of a person | Reverse image; social media pivot |
| Username on a platform | `sherlock` / `maigret` |
| Email on a platform | `holehe`; LinkedIn; GitHub |
| Domain's subdomains | `crt.sh`; `subfinder` |
| Old site version | `web.archive.org` |
| Hidden page on a site | `robots.txt`; `sitemap.xml`; Wayback |
| Git history leak | `git log -p`; commit hashes in error pages |
| Wireless / Bluetooth | `https://wigle.net` (Wi-Fi networks) |
| Aircraft / ships | FlightRadar24, MarineTraffic |

## 11. The "Bellingcat-style" Investigation

CTF OSINT increasingly mimics real investigations:
- Satellite imagery (Google Earth Pro, Maxar, Sentinel Hub, Planet)
- Flight tracking (FlightRadar24, ADS-B Exchange)
- Ship tracking (MarineTraffic, AIS)
- Vehicle registration (regional, often requires API)
- CCTV footage (open-source cameras; Earthcam)
- Phone number (Twilio lookup, regional carriers)

## 12. CTF-Specific Ethics

OSINT in CTFs is meant to be **public data only**. Don't:
- Login to anyone's account (even if you found the creds)
- Exploit any vulnerability to get the data
- Doxx real people (challenge authors are real people)
- Use private APIs without permission
- Pivot to non-public systems (e.g. try the leaked password on a public mail server)

If a challenge requires the password, the expected flow is:
1. Find the leak (e.g. on a public paste)
2. Decrypt / crack the password hash
3. **Use the password only in the CTF context**, not on a real system

## Tooling

```bash
# sherlock / maigret
pip install sherlock-project
pip install maigret

# holehe
pip install holehe

# theHarvester (email/subdomain OSINT)
sudo apt install theharvester

# recon-ng (framework)
sudo apt install recon-ng

# maltego (GUI; commercial)

# subfinder, amass
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v3/...@latest

# ExifTool
sudo apt install libimage-exiftool-perl

# ViewDNS.info / crt.sh are web-only

# waybackurls
go install github.com/tomnomnom/waybackurls@latest

# h8mail (email OSINT)
pip install h8mail
```

## Common Pitfalls

- **Wrong country** — license plate format is the fastest disambiguator
- **Old image** — Wayback shows the old version; the site may have changed
- **Private API** — many "OSINT" tools hit rate-limited APIs. Use your own key.
- **Time zone mismatch** — EXIF timestamp is often UTC; the location's local time differs
- **Public record = OSINT** — but commercial records (Spokeo, Pipl) are paid; CTF authors don't pay for these
- **Stale data** — `crt.sh` shows old certs; the live subdomain may be different

## Validation

A real OSINT finding in CTF = **the flag is the answer** (a city, a username, a domain, a string). The reasoning chain (which sources you used, how you pivoted) is reported alongside.
