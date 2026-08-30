"""Centralized result-size limits for tool outputs.

Ponytail: these were previously magic numbers scattered across 8+ tool
files. Migrate new tools to import from here so truncation policy is in
one place.
"""

MAX_RESULT_CHARS = 20_000
MAX_REFERENCES = 25
MAX_LIST_RESULTS = 50
MAX_BODY_CHARS = 8_192
MAX_TITLE_CHARS = 300
MAX_RAW_CONTENT_CHARS = 10_000
MAX_CONTENT_CHARS = 2_000
MAX_SUMMARY_CHARS = 2_000
MAX_CONTENT_PREVIEW_CHARS = 280
RELATED_LIMIT = 30
