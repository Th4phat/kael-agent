# Kael YARA Rules Bundle

This directory contains YARA rules bundled with Kael for malware reverse engineering.

## Directory Structure

- `malware_families/` - Rules for specific malware families (Cobalt Strike, Meterpreter, Emotet, etc.)
- `techniques/` - Rules for detection techniques (anti-debug, anti-VM, persistence, etc.)
- `crypto/` - Rules for cryptographic constants (AES, RSA, Base64, XOR, RC4)
- `packers/` - Rules for common packers (UPX, MPRESS, Themida, VMProtect, etc.)

## Usage

These rules are automatically loaded by the `yara_scan` tool when `use_bundled_rules=True` (default).

```python
result = await yara_scan(
    sample_path="/workspace/sample.exe",
    use_bundled_rules=True
)
```

## Custom Rules

You can add your own rules to these directories. YARA rules should have `.yar` or `.yara` extensions.

## Rule Sources

Rules are based on common malware detection patterns and open-source research. They are designed for:
- Initial triage and classification
- Technique identification
- Packer detection
- C2 beacon identification

## Severity Levels

- `critical` - Known malware families or active exploitation
- `high` - Strong indicators of malicious behavior
- `medium` - Suspicious techniques or patterns
- `low` - Generic indicators that need context
- `info` - Informational findings (crypto constants, packers)

## Contributing

To add new rules:
1. Place them in the appropriate category directory
2. Include proper metadata (description, author, severity)
3. Test with known samples
4. Rebuild the Docker container to include them

## References

- YARA Documentation: https://yara.readthedocs.io/
- YARA Rules Repository: https://github.com/Yara-Rules/rules
- Signature Base: https://github.com/Neo23x0/signature-base
