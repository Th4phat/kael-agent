"""Settings loader, override switch, and disk persistence."""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from pydantic import BaseModel

from kael.config.settings import Settings
from kael.config.settings import _aliases_for as _aliases_for


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".kael" / "cli-config.json"
_override: Path | None = None
_cached: Settings | None = None
_config_environment: dict[str, tuple[str | None, str]] = {}


def config_path() -> Path:
    return (_override or _DEFAULT_PATH).expanduser()


def format_setting(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (bool, dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def read_config(path: Path | None = None) -> dict[str, Any]:
    target = path or config_path()
    if not target.exists():
        return {"env": {}}
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in config file {target}.") from None
    return _validate_config(data, target)


def _validate_config(data: Any, target: Path) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("env", {}), dict):
        raise ValueError(f"Config file {target} must contain an 'env' object.")
    data.setdefault("env", {})
    for name, value in data["env"].items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) or "\x00" in format_setting(value):
            raise ValueError(f"Invalid environment variable in config file {target}.")
    return data


def write_config(data: dict[str, Any]) -> None:
    """Replace the active config atomically, retaining owner-only permissions."""
    target = config_path().resolve()
    _validate_config(data, target)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent, prefix=".kael-config-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        temporary.chmod(0o600)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _restore_config_environment() -> None:
    for name, (original, published) in _config_environment.items():
        if os.environ.get(name) == published:
            if original is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = original
    _config_environment.clear()


def publish_config_environment(env_block: dict[str, Any], settings: Settings) -> None:
    """Expose saved settings to SDKs and tools that read process variables."""
    updates = {name: format_setting(value) for name, value in env_block.items()}
    configured_names = {name.upper() for name in env_block}
    for section in type(settings).model_fields:
        model = getattr(settings, section)
        for field, info in type(model).model_fields.items():
            aliases = _aliases_for(info)
            if configured_names.intersection(aliases):
                updates.update(dict.fromkeys(aliases, format_setting(getattr(model, field))))
    _restore_config_environment()
    for name, value in updates.items():
        _config_environment[name] = (os.environ.get(name), value)
        os.environ[name] = value


def load_settings() -> Settings:
    """Resolve config file > process environment > defaults. Memoized."""
    global _cached  # noqa: PLW0603
    if _cached is None:
        source_path = config_path()
        data = read_config()
        legacy: dict[str, Any] = {}
        if not source_path.exists():
            legacy = {
                name: value
                for name, value in dotenv_values(".env", interpolate=False).items()
                if value is not None
            }
            data["env"].update(legacy)
        _restore_config_environment()
        init_kwargs: dict[str, Any] = _nested_overrides(data["env"])
        settings = Settings(**init_kwargs)
        if legacy:
            write_config(data)
        publish_config_environment(data["env"], settings)
        _cached = settings
        logger.debug(
            "load_settings: resolved (override=%s, file_used=%s, json_keys=%d)",
            _override is not None,
            source_path.exists(),
            sum(len(v) for v in init_kwargs.values()),
        )
    return _cached


def apply_config_override(path: Path) -> None:
    """Switch the JSON source to ``path`` and invalidate the cache."""
    global _override, _cached  # noqa: PLW0603
    _restore_config_environment()
    _override = path
    _cached = None
    logger.info("config override applied: %s", path)


def persist_current() -> None:
    """Persist explicitly configured values, retaining custom keys and metadata."""
    s = load_settings()
    data = read_config()
    env_block = data["env"]
    for sub_name in type(s).model_fields:
        sub_model = getattr(s, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        values = sub_model.model_dump(mode="json")
        for field, info in type(sub_model).model_fields.items():
            aliases = _aliases_for(info)
            if aliases and field in sub_model.model_fields_set:
                env_block[aliases[0]] = values[field]
                for key in list(env_block):
                    if key.upper() in aliases:
                        env_block[key] = values[field]
    write_config(data)


def _read_json_overrides(path: Path) -> dict[str, dict[str, Any]]:
    return _nested_overrides(read_config(path)["env"])


def _nested_overrides(env_block: dict[str, Any]) -> dict[str, dict[str, Any]]:
    env_block_upper = {str(k).upper(): v for k, v in env_block.items()}

    nested: dict[str, dict[str, Any]] = {}
    for sub_name, sub_finfo in Settings.model_fields.items():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        sub_data: dict[str, Any] = {}
        for finfo in sub_cls.model_fields.values():
            aliases = _aliases_for(finfo)
            for alias in aliases:
                key = alias.upper()
                if key in env_block_upper:
                    sub_data[aliases[0]] = env_block_upper[key]
                    break
        if sub_data:
            nested[sub_name] = sub_data
    return nested
