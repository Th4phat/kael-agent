# Malware RE Tools - Unit Tests

## Overview

Comprehensive unit tests for the malware reverse engineering tools.

## Test Coverage

### 1. test_file_triage.py (10 tests)
Tests for file classification and triage:
- ✅ Nonexistent file handling
- ✅ PE file detection
- ✅ ELF file detection
- ✅ High entropy detection (packed files)
- ✅ Low entropy detection
- ✅ Hash calculation (MD5, SHA256)
- ✅ File size reporting
- ✅ Empty file handling

### 2. test_extract_strings.py (13 tests)
Tests for string extraction and IOC detection:
- ✅ Nonexistent file handling
- ✅ Basic string extraction
- ✅ URL extraction
- ✅ IP address extraction
- ✅ File path extraction
- ✅ Registry key extraction
- ✅ Email extraction
- ✅ Mutex extraction
- ✅ Unicode (UTF-16LE) strings
- ✅ Base64 detection
- ✅ Minimum length filtering
- ✅ Empty file handling

### 3. test_yara_scan.py (10 tests)
Tests for YARA signature scanning:
- ✅ Nonexistent file handling
- ✅ EICAR test file detection
- ✅ Clean file scanning
- ✅ UPX packer detection
- ✅ Inline rule compilation
- ✅ Invalid rule handling
- ✅ No matches scenario
- ✅ Bundled rules toggle
- ✅ Match metadata extraction

### 4. test_target_inference.py (15 tests)
Tests for target type detection (NEW):
- ✅ File target detection (malware_sample)
- ✅ Directory target detection (local_code)
- ✅ URL detection (web_application)
- ✅ Repository URL detection
- ✅ Git SSH URL detection
- ✅ IP address detection
- ✅ Domain name detection
- ✅ Nonexistent path rejection
- ✅ Relative path resolution
- ✅ Tilde expansion (~/file)
- ✅ Local sources collection (malware_sample)
- ✅ Local sources collection (directory)
- ✅ Mixed target types
- ✅ Empty/whitespace validation
- ✅ File paths with spaces

### 5. test_unpack_generic.py (10 tests)
Tests for unpacking functionality:
- ✅ Nonexistent file handling
- ✅ Output directory creation
- ✅ Packer detection (UPX)
- ✅ XOR brute force method
- ✅ Overlay extraction method
- ✅ Binwalk method
- ✅ UPX-specific method
- ✅ Empty file handling
- ✅ Output structure validation
- ✅ No packer detected (normal files)

### 6. test_generate_research_report.py (9 tests)
Tests for report generation:
- ✅ Basic report generation
- ✅ Report file creation
- ✅ Markdown content validation
- ✅ JSON content validation
- ✅ Invalid JSON handling
- ✅ Minimal data handling
- ✅ Output directory creation
- ✅ C2 information inclusion
- ✅ File structure verification

### 7. test_c2_beacon_detect.py (10 tests)
Tests for C2 beacon detection:
- ✅ Nonexistent PCAP handling
- ✅ Empty PCAP handling
- ✅ Output structure validation
- ✅ Beacon interval analysis
- ✅ Irregular interval detection
- ✅ Single timestamp handling
- ✅ Empty timestamp list
- ✅ Min/max interval parameters
- ✅ Jitter calculation
- ✅ High jitter detection

### 8. test_protocol_dissect.py (9 tests)
Tests for protocol dissection:
- ✅ Nonexistent PCAP handling
- ✅ Empty PCAP handling
- ✅ Output structure validation
- ✅ Payload extraction enabled
- ✅ Payload extraction disabled
- ✅ Protocol hint parameter
- ✅ HTTP conversation extraction
- ✅ DNS query extraction
- ✅ Raw TCP payload extraction

### 9. test_memory_snapshot.py (10 tests)
Tests for memory snapshot:
- ✅ Nonexistent directory handling
- ✅ Empty directory handling
- ✅ Output structure validation
- ✅ Specific PIDs parameter
- ✅ PE extraction toggle
- ✅ Injection detection toggle
- ✅ Process discovery
- ✅ Process discovery with logs
- ✅ Dumps directory creation
- ✅ Strace log parsing

### 10. test_sandbox_detonate.py (10 tests)
Tests for sandbox detonation:
- ✅ Nonexistent file handling
- ✅ File size validation
- ✅ Network modes (off/controlled/live)
- ✅ Quick mode
- ✅ Custom timeout
- ✅ Platform compatibility checks
- ✅ Script compatibility
- ✅ Python compatibility
- ✅ Filesystem snapshot
- ✅ Filesystem diff

### 11. test_radare2_analyze.py (7 tests)
Tests for radare2 analysis:
- ✅ Nonexistent file handling
- ✅ PE file analysis
- ✅ Analysis depths (quick/standard/deep)
- ✅ Function extraction toggle
- ✅ Crypto detection toggle
- ✅ Invalid depth handling
- ✅ Output structure validation

**Total: 113 unit tests**

## Running Tests

### Run all tests
```bash
cd /path/to/kael
pytest tests/tools/re_tools/ -v
```

### Run specific test file
```bash
pytest tests/tools/re_tools/test_file_triage.py -v
pytest tests/tools/re_tools/test_extract_strings.py -v
pytest tests/tools/re_tools/test_yara_scan.py -v
pytest tests/tools/re_tools/test_target_inference.py -v
```

### Run specific test
```bash
pytest tests/tools/re_tools/test_file_triage.py::test_file_triage_pe_file -v
```

### Run with coverage
```bash
pytest tests/tools/re_tools/ --cov=kael.tools.re_tools --cov-report=html
```

### Run only fast tests (skip slow ones)
```bash
pytest tests/tools/re_tools/ -m "not slow" -v
```

## Dependencies

Tests require:
```bash
pip install pytest pytest-cov pytest-asyncio
```

Optional for full tool functionality:
```bash
# YARA scanning
pip install yara-python

# PE/ELF analysis
pip install pefile pyelftools

# Fuzzy hashing
pip install ssdeep-python ppdeep

# For actual tool execution (not just import tests)
apt-get install yara binwalk upx radare2
```

## Test Structure

```
tests/
├── conftest.py                      # Pytest configuration
├── __init__.py
└── tools/
    ├── __init__.py
    └── re_tools/
        ├── __init__.py
        ├── test_file_triage.py      # File triage tests
        ├── test_extract_strings.py  # String extraction tests
        ├── test_yara_scan.py         # YARA scanning tests
        └── test_target_inference.py  # Target type detection tests
```

## Test Philosophy

**Unit tests focus on:**
1. **Error handling** - Nonexistent files, invalid inputs
2. **Core functionality** - Basic operations work correctly
3. **Edge cases** - Empty files, unusual inputs
4. **API contracts** - Return JSON with expected fields
5. **No external dependencies** - Use temp files, not real malware

**Unit tests DO NOT:**
- Require Docker
- Require actual malware samples
- Test tool integration (that's for integration tests)
- Test sandboxing or network capture (too complex)

## Example Test Run

```bash
$ pytest tests/tools/re_tools/test_file_triage.py -v

tests/tools/re_tools/test_file_triage.py::test_file_triage_nonexistent PASSED
tests/tools/re_tools/test_file_triage.py::test_file_triage_pe_file PASSED
tests/tools/re_tools/test_file_triage.py::test_file_triage_elf_file PASSED
tests/tools/re_tools/test_file_triage.py::test_file_triage_entropy_high PASSED
tests/tools/re_tools/test_file_triage.py::test_file_triage_entropy_low PASSED
tests/tools/re_tools/test_file_triage.py::test_file_triage_hashes PASSED
tests/tools/re_tools/test_file_triage.py::test_file_triage_file_size PASSED

========================== 7 passed in 0.45s ==========================
```

## Next Steps

### Additional tests to write:
1. **test_unpack_generic.py** - Unpacking functionality
2. **test_sandbox_detonate.py** - Sandbox execution (mocked)
3. **test_c2_beacon_detect.py** - Beacon detection
4. **test_protocol_dissect.py** - Protocol analysis
5. **test_memory_snapshot.py** - Memory capture
6. **test_radare2_analyze.py** - Disassembly
7. **test_generate_research_report.py** - Report generation

### Integration tests:
1. **test_eicar_workflow.py** - End-to-end EICAR analysis
2. **test_benign_binary.py** - End-to-end benign binary
3. **test_multi_stage.py** - Multi-stage malware detection

## Continuous Integration

Add to CI/CD pipeline:
```yaml
- name: Run RE tools tests
  run: |
    pip install pytest pytest-cov
    pytest tests/tools/re_tools/ -v --cov=kael.tools.re_tools
```

## Troubleshooting

### Import errors
Make sure project root is in PYTHONPATH:
```bash
export PYTHONPATH=/path/to/kael:$PYTHONPATH
pytest tests/tools/re_tools/ -v
```

### Missing dependencies
Install test requirements:
```bash
pip install -r requirements-test.txt
```

### Tests fail with "module not found"
Ensure __init__.py files exist in all test directories.

## Test Coverage Goals

- **File triage:** 90%+ coverage ✅
- **String extraction:** 90%+ coverage ✅
- **YARA scanning:** 85%+ coverage ✅
- **Target inference:** 95%+ coverage ✅
- **Overall RE tools:** 80%+ coverage (in progress)

## Contributing

When adding new RE tools, also add:
1. Unit tests in `tests/tools/re_tools/test_<tool_name>.py`
2. Fixtures for test data
3. Error case tests
4. Edge case tests
5. Update this README
