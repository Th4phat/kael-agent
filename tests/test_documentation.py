"""Publication checks for documentation structure and code-facing claims."""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import AliasChoices, BaseModel

from kael.config.settings import Settings


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]*]\(([^)]+)\)")
SITE_HREF = re.compile(r'href="(/[^"]+)"')
ENV_NAME = re.compile(r"`([A-Z][A-Z0-9_]+)`")


def _docs_route_exists(route: str) -> bool:
    route_path = route.split("#", 1)[0].strip("/")
    if not route_path:
        return True
    return (DOCS / f"{route_path}.mdx").is_file() or (DOCS / route_path / "index.mdx").is_file()


def test_documentation_navigation_pages_exist() -> None:
    config = json.loads((DOCS / "docs.json").read_text(encoding="utf-8"))
    missing: list[str] = []
    for tab in config["navigation"]["tabs"]:
        for group in tab["groups"]:
            for page in group["pages"]:
                if not _docs_route_exists(page):
                    missing.append(page)
    assert not missing, f"docs.json references missing pages: {missing}"


def test_local_documentation_links_resolve() -> None:
    sources = [*ROOT.glob("*.md"), *DOCS.rglob("*.md"), *DOCS.rglob("*.mdx")]
    broken: list[str] = []
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK.findall(text):
            target = raw_target.strip().strip("<>").split("#", 1)[0]
            if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
                continue
            if target.startswith("/"):
                exists = source.is_relative_to(DOCS) and _docs_route_exists(target)
            else:
                exists = (source.parent / target).resolve().exists()
            if not exists:
                broken.append(f"{source.relative_to(ROOT)} -> {raw_target}")

        if source.is_relative_to(DOCS):
            for route in SITE_HREF.findall(text):
                if not _docs_route_exists(route):
                    broken.append(f"{source.relative_to(ROOT)} -> {route}")

    assert not broken, "broken local documentation links:\n" + "\n".join(broken)


def test_configuration_docs_cover_every_application_setting() -> None:
    documented = set(
        ENV_NAME.findall((DOCS / "advanced/configuration.mdx").read_text(encoding="utf-8"))
    )
    expected: set[str] = set()
    for settings_field in Settings.model_fields.values():
        settings_class = settings_field.annotation
        if not isinstance(settings_class, type) or not issubclass(settings_class, BaseModel):
            continue
        for field in settings_class.model_fields.values():
            if field.alias:
                expected.add(field.alias)
            if isinstance(field.validation_alias, AliasChoices):
                expected.update(
                    choice for choice in field.validation_alias.choices if isinstance(choice, str)
                )
            elif isinstance(field.validation_alias, str):
                expected.add(field.validation_alias)

    missing = sorted(expected - documented)
    assert not missing, f"configuration docs omit supported variables: {missing}"


def test_public_docs_do_not_use_removed_cli_or_proxy_terms() -> None:
    usage = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((DOCS / "usage").glob("*.mdx"))
    )
    for removed in ("kael --target", "--scan-mode", "--instruction ", "--instruction-file"):
        assert removed not in usage, f"usage docs contain removed CLI syntax: {removed}"

    all_docs = "\n".join(path.read_text(encoding="utf-8") for path in sorted(DOCS.rglob("*.mdx")))
    assert "Caido" not in all_docs
    assert "caido_api" not in all_docs
