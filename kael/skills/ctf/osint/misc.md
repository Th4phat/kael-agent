---
name: ctf-misc-misc
description: Catch-all CTF miscellaneous challenges — network protocols (SMTP, IMAP, IRC, XMPP), unique protocols (modbus, sigfox, BLE), blockchain/smart contracts, AI/ML adversarial, hardware/firmware (UART, JTAG, SPI flash)
---

# CTF Misc — Catch-all

The "this challenge doesn't fit anywhere else" category. Often the most fun.

## 1. Wireless & RF (the hardware-adjacent CTFs)

### Wi-Fi
```bash
# WPA handshake capture + crack
sudo airmon-ng start wlan0
sudo airodump-ng -c <channel> --bssid <bssid> -w /tmp/cap wlan0mon
# Once you see a handshake in the top right, run:
aircrack-ng -w rockyou.txt -b <bssid> /tmp/cap-01.cap
# Or with hashcat
hcxpcapngtool -o hash.hc22000 /tmp/cap-01.cap
hashcat -m 22000 hash.hc22000 rockyou.txt
```

### Bluetooth Low Energy (BLE)
```bash
# Scan
sudo hcitool lescan
# Capture with gatttool / bluetoothctl
# Or: bettercap
sudo bettercap -eval "ble.recon on"
# Decrypt with a known LTK
```

### SDR (Software Defined Radio)
```bash
# rtl_fm
rtl_fm -f 433.92M -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE
# Or: gqrx (GUI)
# Decode OOK (the common 433MHz remote control signal)
# Universal Radio Hacker (URH)
urh
```

### ADS-B (aircraft)
```bash
# 1090 MHz
dump1090 --interactive
# Or: readsb / VirtualRadarServer
```

### AIS (ships)
```bash
# 162 MHz
# Use a SDR + AIS decoder
# https://github.com/pieterjanb/javascript-ais-decoder
```

### SigFox, LoRa, Zigbee
- Each has a specific decoder
- The flag is often in the device's metadata or in a specific field of the packet

## 2. Smart Contracts / Blockchain

### Ethereum
```bash
# Get the bytecode
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getCode","params":["<address>","latest"],"id":1}' https://eth.llamarpc.com
# Disassemble
pip install pyevmasm
python3 -c "
from pyevmasm import disassemble_hex
print(disassemble_hex('<bytecode>'))
"
# Or use evmone, manticore, mythril for symbolic execution
```

### Solidity
```bash
# Decompile (heuristics)
# https://contract-library.com (verified source)
# Otherwise: use Etherscan verified source if available
# If not: decompile with heimdall-rs
pip install heimdall
heimdall decompile <bytecode>
```

### Solana
- BPF (Berkeley Packet Filter) bytecode
- Disassemble with `solana-bpf-tools` or `bpf-disasm`

### Bitcoin
- Script disassembly
- Custom puzzle in the script (`OP_DUP` etc.)

## 3. AI / ML Challenges

### Adversarial input
- Add a small noise to bypass an image classifier
- The flag is often in the adversarial image (or the noise is the flag)

### Model extraction
- Query the model to recover the weights
- Side-channel: timing, GPU utilization

### Data poisoning / prompt injection
- Some challenges are "get the LLM to reveal the secret"
- Use a system prompt that includes the flag; the agent must exfiltrate it

## 4. Hardware (firmware, UART, JTAG)

### UART
```bash
# Connect a UART-to-USB bridge (e.g. CP2102) to the target
# Find the baud rate (commonly 115200, 9600)
sudo miniterm.py /dev/ttyUSB0 115200
# Or:
sudo screen /dev/ttyUSB0 115200
# Or:
sudo picocom -b 115200 /dev/ttyUSB0
```

### SPI Flash
```bash
# Use a CH341A programmer or FT2232H + flashrom
sudo flashrom -p ch341a_spi -r firmware.bin
# Or: rtl-sdr
# Then analyze the firmware with binwalk
binwalk -e firmware.bin
```

### JTAG
- Use OpenOCD + a JTAG adapter
- `openocd -f interface/<adapter>.cfg -f target/<chip>.cfg`

### Logic Analyzer
- Saleae, sigrok / PulseView
- Decode SPI / I2C / UART

### Firmware
```bash
# Extract
binwalk -e firmware.bin
# Emulate
qemu-system-arm -M ... firmware.elf
# Or: ghidra decompile the firmware
```

## 5. Network Protocol Challenges

### SMTP / IMAP
```bash
# Read the raw SMTP/IMAP traffic from a PCAP
tshark -r capture.pcap -Y "smtp" -T fields -e tcp.payload
# Or connect to a live server
openssl s_client -starttls smtp -crlf -connect mail.target.com:587
```

### IRC
```bash
# Connect and read the channel
nc target.com 6667
NICK attacker
USER attacker 0 * :attacker
JOIN #secret
```

### XMPP / Jabber
```bash
# Use pidgin, gajim, or a Python xmpp client
# The flag is in a chat message
```

### MQTT
```bash
# Subscribe to a topic
mosquitto_sub -h target.com -t '#' -v
# Common CTF: flag is in a specific topic
```

### CoAP
```bash
# CoAP client
pip install aiocoap
python3 -c "
import asyncio, aiocoap
async def main():
    protocol = await aiocoap.Context.create_client_context()
    request = aiocoap.Message(code=aiocoap.GET, uri='coap://target.com/flag')
    response = await protocol.request(request).response
    print(response.payload)
asyncio.run(main())
"
```

## 6. Game Hacking

### Save file editing
```bash
# hex edit the save file
hexedit save.dat
# Find the value (search for a known number, e.g. "score = 1000")
# Modify to "score = 999999"
```

### Memory editing
```bash
# Use gameconqueror / scanmem
# Find the value, scan, change
```

### Server-side game
- WebSocket-based game: intercept the messages
- Reverse the protocol; send "I won" message

## 7. Mobile (Android / iOS)

### Android (APK)
```bash
# Decompile
apktool d app.apk
# Look at smali code (Android bytecode)
cat smali/com/example/app/MainActivity.smali
# Or use jadx for Java
jadx app.apk
# Or jadx-gui
```

### iOS (IPA)
- Decrypt with bagbak or frida-ios-dump
- Decompile with Hopper, IDA, Ghidra
- Look at plist files (Info.plist, embedded.mobileprovision)

## 8. Esoteric Hardware (the 2024+ trend)

### NFC / RFID
```bash
# Read with proxmark3
proxmark3 /dev/ttyACM0
# Commands: hf mf rdbl, hf 14a read
# Crack Mifare Classic with mfoc / mfcuk
mfoc -O output.mfd -k mykey
```

### 1-wire
- DS18B20 temperature sensor
- Read with a bus pirate

### CAN bus (car)
- `candump can0` (SocketCAN)
- Replay attack

## 9. Custom-Protocol CTF

A "network service" running on port X with a custom protocol. The first byte is a command code, the rest is data. Approach:
```bash
# 1. Capture traffic (if the protocol is documented)
# 2. Disassemble the binary (gdb, ghidra)
# 3. Reimplement the protocol
# 4. Send the right message
```

## 10. "Find the Bug in This Simple Code" Challenge

```python
# Often the challenge is a tiny script
import os
flag = os.environ.get('FLAG', 'no flag here')
# Or: flag = 'CTF{...}'
key = b'\x13\x37\x42\x69'
cipher = bytes(c ^ k for c, k in zip(flag.encode(), key * 10))
print(cipher.hex())
# Or the cipher is an image of the encrypted flag
```

The fix: read the code, find the bug, exploit it. Usually trivial.

## 11. The "Open-Source Library CVE" Challenge

The challenge is a vulnerable version of a popular library. The flag is gained by:
1. Identifying the library (look at the binary's symbols)
2. Finding the CVE that matches the version
3. Running the public PoC

```bash
# Identify
ldd chall    # which libc
strings chall | grep -iE "openssl|gmp|libpng"
# Check versions
# Run the CVE's PoC
```

## 12. Programming Language Puzzles

### Esolangs
- See `encodings.md` for Brainfuck, JSFuck, etc.

### Turing-tarpit puzzles
- Cyclone (a C variant with one-letter variables)
- Subleq (one instruction)
- Malbolge

### Regex golf
- The flag is a string that matches a specific regex but fails all "smaller" patterns
- Use regex101 to visualize

## 13. Quantum / Post-Quantum

Some 2024 CTFs include post-quantum crypto:
- Lattice (NTRU, Kyber)
- Code-based (McEliece)
- Hash-based (XMSS, LMS)
- Multivariate (Rainbow, MAYO)

These typically just need you to identify the scheme and use a known attack (e.g. lattice reduction for NTRU).

## 14. The "Mystery Box" — General Workflow

When the challenge is just a file with no hint:
```bash
file mystery.bin
binwalk -e mystery.bin
# If that fails, examine the hex
xxd mystery.bin | head -30
# Look for: header magic, version, sizes, padding
# Try each offset
dd if=mystery.bin of=part1.bin bs=1 skip=0 count=<size1>
dd if=mystery.bin of=part2.bin bs=1 skip=<offset2>
file part1.bin
file part2.bin
# Repeat
```

## Common Pitfalls

- **Wrong baud rate** — try 9600, 19200, 38400, 57600, 115200, 230400, 921600
- **Firmware encryption** — many modern firmwares are encrypted (AES / RSA). Look for the decryption stub or the OEM's keys.
- **Mobile apps with safety net / SSL pinning** — disable pinning with `objection` or `frida`
- **BLE pairing required** — without the pairing info, you can't decrypt
- **MQTT broker requires auth** — try anonymous, then `admin:admin`, then the topic name as password
- **LoRa / SigFox have rolling codes** — replay won't work; you need to predict

## Tooling

```bash
# aircrack-ng, hcxdumptool, hcxpcapngtool
sudo apt install aircrack-ng hcxtools
# hashcat
sudo apt install hashcat
# miniterm (UART)
sudo apt install python3-serial
# sigrok / PulseView
sudo apt install sigrok
# OpenOCD (JTAG)
sudo apt install openocd
# flashrom (SPI flash)
sudo apt install flashrom
# qemu-system
sudo apt install qemu-system-arm qemu-system-mips
# apktool (Android)
sudo apt install apktool
# jadx
sudo apt install jadx
# And many more
```

## Validation

A real misc finding in CTF = **the flag string is the result of the chain of actions** (decoding, soldering, protocol replay, or exploit). The chain of reasoning and the specific tool/command used is reported alongside.
