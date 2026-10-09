"""Schema-backed editing of the active JSON config for the TUI."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, get_args, get_origin

from pydantic import TypeAdapter, ValidationError

from kael.config import loader
from kael.config.loader import _aliases_for, format_setting, load_settings, read_config
from kael.config.settings import LlmSettings


if TYPE_CHECKING:
    from collections.abc import Mapping

    from pydantic.fields import FieldInfo


@dataclass(frozen=True)
class EditableSetting:
    name: str
    section: str = "environment"
    field: str | None = None
    info: FieldInfo | None = None

    @property
    def secret(self) -> bool:
        return any(
            part in self.name.upper()
            for part in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
        )

    @property
    def aliases(self) -> list[str]:
        return _aliases_for(self.info) if self.info else [self.name]

    @property
    def label(self) -> str:
        if self.field is None:
            return self.name
        title = self.info.title if self.info else None
        return f"{title or self.field.replace('_', ' ').capitalize()} · {self.name}"

    @property
    def description(self) -> str:
        if self.info is None:
            return "Environment variable. Saved for the next launch; running services keep their settings."
        text = (
            self.info.description or f"{(self.field or self.name).replace('_', ' ').capitalize()}."
        )
        if get_origin(self.info.annotation) is not None:
            choices = get_args(self.info.annotation)
            if choices and all(isinstance(value, str) for value in choices):
                text += " Choices: " + ", ".join(choices) + "."
        if len(self.aliases) > 1:
            text += " Aliases for this setting: " + ", ".join(self.aliases) + "."
        if self.section == "memory" and self.field == "scope":
            text += " Used on a new run."
        elif (
            self.section in {"llm", "integrations", "memory"}
            or self.field == "parallel_tool_calls_mode"
        ):
            text += " Used on the next request or tool call. Changing API/tool format requires a new run."
        else:
            text += " Used on a new run."
        return text

    def value(self) -> str:
        if self.field is not None:
            return format_setting(getattr(getattr(load_settings(), self.section), self.field))
        return format_setting(read_config()["env"].get(self.name, os.environ.get(self.name, "")))

    def default(self) -> str:
        return format_setting(self.info.get_default(call_default_factory=True)) if self.info else ""

    def parse(self, value: str) -> Any:
        if "\x00" in value:
            raise ValueError("Values cannot contain a null character.")
        if self.info is None:
            return value
        if self.section == "llm" and self.field == "openrouter_provider":
            return LlmSettings.parse_openrouter_provider(value)
        annotation = self.info.annotation
        if type(None) in get_args(annotation):
            if not value.strip():
                return None
            annotation = next(arg for arg in get_args(annotation) if arg is not type(None))
        parsed: Any = value
        if get_origin(annotation) in {list, dict}:
            parsed = json.loads(value)
        return TypeAdapter(self.info.rebuild_annotation()).validate_python(parsed)


def editable_settings() -> dict[str, EditableSetting]:
    settings = load_settings()
    entries: dict[str, EditableSetting] = {}
    for section in type(settings).model_fields:
        model = getattr(settings, section)
        for field, info in type(model).model_fields.items():
            names = _aliases_for(info)
            if not names:
                continue
            for name in names:
                entries[name] = EditableSetting(name, section, field, info)
    for name in read_config()["env"]:
        if name not in entries:
            known = entries.get(name.upper())
            entries[name] = (
                EditableSetting(name, known.section, known.field, known.info)
                if known
                else EditableSetting(name)
            )
    return entries


def save_settings(changes: Mapping[str, str]) -> None:
    """Validate everything before replacing the config or changing live settings."""
    entries = editable_settings()
    parsed: dict[tuple[str, str], Any] = {}
    data = read_config()
    existing = data["env"]
    updates: dict[str, Any] = {}
    changed_environment: set[str] = set()
    for name, raw_value in changes.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name):
            raise ValueError("Use letters, digits, and underscores for variable names.")
        entry = entries.get(name) or entries.get(name.upper()) or EditableSetting(name)
        try:
            value = entry.parse(raw_value)
        except ValidationError as exc:
            messages = "; ".join(error["msg"] for error in exc.errors(include_input=False))
            raise ValueError(f"{name}: {messages}") from None
        except ValueError as exc:
            raise ValueError(f"{name}: {exc}") from None
        if entry.field is not None:
            field_key = (entry.section, entry.field)
            if field_key in parsed and parsed[field_key] != value:
                raise ValueError(
                    f"Conflicting aliases for {entry.aliases[0]}; enter the same value."
                )
            parsed[field_key] = value
        updates[name] = value
        if entry.field is not None:
            updates[entry.aliases[0]] = value
            for key in existing:
                if key.upper() in entry.aliases:
                    updates[key] = value
            changed_environment.update(entry.aliases)
        else:
            changed_environment.add(name)
    if not updates:
        return

    settings = load_settings().model_copy(deep=True)
    for (section, field), value in parsed.items():
        setattr(getattr(settings, section), field, value)

    values = settings.model_dump(mode="json")
    for name in updates:
        saved_entry = entries.get(name) or entries.get(name.upper())
        if saved_entry and saved_entry.field is not None:
            updates[name] = values[saved_entry.section][saved_entry.field]
    existing.update(updates)
    loader.write_config(data)
    loader.publish_config_environment(existing, settings)
    from kael.config.models import _mirrored_api_keys

    for name in changed_environment:
        _mirrored_api_keys.pop(name, None)
    loader._cached = settings
