"""Reverse engineering and malware analysis tools."""

from .c2_beacon_detect import c2_beacon_detect
from .extract_strings import extract_strings
from .file_triage import file_triage
from .generate_research_report import generate_research_report
from .import_analyzer import import_analyzer
from .memory_snapshot import memory_snapshot
from .protocol_dissect import protocol_dissect
from .radare2_analyze import radare2_analyze
from .resource_analyzer import resource_analyzer
from .sandbox_detonate import sandbox_detonate
from .string_deobfuscator import string_deobfuscator
from .unpack_generic import unpack_generic
from .yara_scan import yara_scan


ALL_RE_TOOLS = [
    file_triage,
    extract_strings,
    yara_scan,
    radare2_analyze,
    sandbox_detonate,
    memory_snapshot,
    c2_beacon_detect,
    protocol_dissect,
    unpack_generic,
    generate_research_report,
    import_analyzer,
    resource_analyzer,
    string_deobfuscator,
]


__all__ = [
    "ALL_RE_TOOLS",
    "c2_beacon_detect",
    "extract_strings",
    "file_triage",
    "generate_research_report",
    "import_analyzer",
    "memory_snapshot",
    "protocol_dissect",
    "radare2_analyze",
    "resource_analyzer",
    "sandbox_detonate",
    "string_deobfuscator",
    "unpack_generic",
    "yara_scan",
]
