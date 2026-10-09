"""Searchable editor for the application config file."""

from __future__ import annotations

import re
from typing import ClassVar

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList
from textual.widgets.option_list import Option

from kael.config.editor import EditableSetting, editable_settings, save_settings
from kael.config.loader import config_path


class SettingsScreen(ModalScreen[set[str] | None]):
    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "dismiss", "Cancel", priority=True),
        Binding("ctrl+s", "save", "Save", priority=True),
        Binding("ctrl+f", "focus_search", "Search", priority=True),
    ]

    def __init__(self, initial_key: str | None = None) -> None:
        super().__init__()
        self.entries = editable_settings()
        self.initial = {name: entry.value() for name, entry in self.entries.items()}
        self.changes: dict[str, str] = {}
        self.new_names: set[str] = set()
        self.selected_key = initial_key or next(iter(self.entries))
        self.focus_value = initial_key is not None
        self.destination = config_path()

    def compose(self) -> ComposeResult:
        with Vertical(id="settings_dialog"):
            yield Label("Settings", id="settings_title")
            yield Label(Text(str(self.destination)), id="settings_path")
            yield Input(
                placeholder="Search settings or enter a new variable name", id="settings_filter"
            )
            yield OptionList(id="settings_list")
            with VerticalScroll(id="settings_editor"):
                yield Label("", id="setting_name")
                yield Input(id="setting_value")
                yield Label("", id="setting_description")
            yield Label("", id="settings_error")
            yield Label("No unsaved changes", id="settings_pending")
            with Horizontal(classes="settings_actions"):
                yield Button("Reset default", id="setting_reset")
                yield Button("Add variable", id="setting_add")
            with Horizontal(classes="settings_actions"):
                yield Button("Save", id="settings_save")
                yield Button("Cancel", id="settings_cancel")
            yield Label(
                "Ctrl+S saves config · Esc cancels",
                id="settings_destination",
            )

    def on_mount(self) -> None:
        self.set_class(self.size.height < 26, "compact")
        self.query_one("#settings_path").tooltip = str(self.destination)
        self.query_one("#settings_error").display = False
        self._filter_options("")
        self._select(self.selected_key)
        self.query_one("#setting_value" if self.focus_value else "#settings_filter", Input).focus()

    def on_resize(self) -> None:
        self.set_class(self.size.height < 26, "compact")

    def _filter_options(self, query: str) -> None:
        options = self.query_one("#settings_list", OptionList)
        names = [
            name
            for name, entry in self.entries.items()
            if query.casefold() in f"{entry.label} {entry.section} {entry.field or ''}".casefold()
        ]
        options.clear_options()
        options.add_options(
            Option(Text(f"{self.entries[name].label} ({self.entries[name].section})"), id=name)
            for name in names
        )
        if names:
            options.highlighted = (
                names.index(self.selected_key) if self.selected_key in names else 0
            )
        else:
            options.add_option(Option("No matches. Use Add variable.", disabled=True))

    def _select(self, name: str) -> None:
        self.selected_key = name
        entry = self.entries[name]
        self.query_one("#setting_name", Label).update(Text(entry.label))
        field = self.query_one("#setting_value", Input)
        value = self.changes.get(name, self.initial[name])
        if entry.field is not None:
            for key, raw in self.changes.items():
                other = self.entries[key]
                if (other.section, other.field) == (entry.section, entry.field):
                    value = raw
        with field.prevent(Input.Changed):
            field.password = entry.secret
            field.value = value
        self.query_one("#setting_description", Label).update(Text(entry.description))

    @on(Input.Changed, "#settings_filter")
    def filter_changed(self, event: Input.Changed) -> None:
        event.stop()
        self._filter_options(event.value.strip())

    @on(Input.Submitted, "#settings_filter")
    def filter_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.query_one("#settings_list", OptionList).action_select()

    @on(OptionList.OptionSelected, "#settings_list")
    def setting_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        if event.option.id in self.entries:
            self._select(event.option.id)
            self.query_one("#setting_value", Input).focus()

    @on(Input.Changed, "#setting_value")
    def value_changed(self, event: Input.Changed) -> None:
        event.stop()
        self._remember_value(event.value)

    def _remember_value(self, value: str) -> None:
        name = self.selected_key
        entry = self.entries[name]
        if entry.field is not None:
            for key in list(self.changes):
                other = self.entries[key]
                if (other.section, other.field) == (entry.section, entry.field):
                    self.changes.pop(key)
        if value != self.initial[name] or name in self.new_names:
            self.changes[name] = value
        else:
            self.changes.pop(name, None)
        self._update_pending()

    @on(Input.Submitted, "#setting_value")
    def value_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_save()

    def _update_pending(self) -> None:
        count = len(self.changes)
        self.query_one("#settings_pending", Label).update(
            f"{count} unsaved setting{'s' if count != 1 else ''}" if count else "No unsaved changes"
        )

    def _error(self, message: str) -> None:
        label = self.query_one("#settings_error", Label)
        label.update(Text(message))
        label.display = True
        label.scroll_visible(animate=False)

    def action_focus_search(self) -> None:
        self.query_one("#settings_filter", Input).focus()

    @on(Button.Pressed)
    def button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        match event.button.id:
            case "settings_save":
                self.action_save()
            case "settings_cancel":
                self.dismiss(None)
            case "setting_reset":
                self.query_one("#setting_value", Input).value = self.entries[
                    self.selected_key
                ].default()
                self.query_one("#setting_value", Input).focus()
            case "setting_add":
                name = self.query_one("#settings_filter", Input).value.strip()
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name):
                    self._error(
                        "Enter a variable name using letters, digits, and underscores in Search."
                    )
                    return
                if name not in self.entries:
                    self.entries[name] = self.entries.get(name.upper(), EditableSetting(name))
                    self.initial[name] = self.entries[name].value()
                    self.new_names.add(name)
                    self.changes[name] = self.initial[name]
                self._filter_options(name)
                self._select(name)
                self._update_pending()
                self.query_one("#setting_value", Input).focus()

    def action_save(self) -> None:
        self._remember_value(self.query_one("#setting_value", Input).value)
        try:
            save_settings(self.changes)
        except (ValueError, OSError) as exc:
            name = str(exc).split(":", 1)[0]
            if name in self.entries:
                self._select(name)
            self._error(f"Could not save: {exc}")
            self.query_one("#setting_value", Input).focus()
            return
        self.dismiss(set(self.changes))
