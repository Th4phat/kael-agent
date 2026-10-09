"""Kael application settings.

Public surface:

- :class:`Settings` — composite model. Get via :func:`load_settings`.
- :class:`LlmSettings`, :class:`RuntimeSettings`,
  :class:`IntegrationSettings` — sub-models, attribute-accessed off
  ``Settings``.
- :func:`load_settings` — memoized resolve (JSON file > env > defaults).
- :func:`apply_config_override` — switch the JSON source to a custom path.
- :func:`persist_current` — write explicitly configured settings to the active file.
"""

from kael.config.loader import (
    apply_config_override,
    config_path,
    load_settings,
    persist_current,
)
from kael.config.settings import (
    IntegrationSettings,
    LlmSettings,
    RuntimeSettings,
    Settings,
)


__all__ = [
    "IntegrationSettings",
    "LlmSettings",
    "RuntimeSettings",
    "Settings",
    "apply_config_override",
    "config_path",
    "load_settings",
    "persist_current",
]
