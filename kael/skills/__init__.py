import logging
import re
from collections.abc import Iterator

from kael.utils.resource_paths import get_kael_resource_path


logger = logging.getLogger(__name__)

_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)

_INTERNAL_SKILL_CATEGORIES: frozenset[str] = frozenset({"scan_modes", "coordination"})


def _derive_var_name(skill_name: str, rel_path: str) -> str:
    """Pick a stable, human-readable key for the loaded skill.

    Backward-compatible: the historical behaviour is to use the last
    ``/``-segment (``"vulnerabilities/sql_injection"`` →
    ``"sql_injection"``). Nested skills also resolve to the bare file
    stem (``"ctf/web/sqli"`` → ``"sqli"``) so existing callers
    continue to work. Callers that need disambiguation can use
    ``rel_path`` instead.
    """
    return skill_name.rsplit("/", 1)[-1] if "/" in skill_name else skill_name


def _iter_user_skill_files() -> Iterator[tuple[str, str]]:
    """Yield ``(category_name, skill_name)`` for every user-selectable skill.

    Discovers ``.md`` files in two layouts:

    - Flat:    ``skills/<category>/<name>.md``  → ``(category, name)``
    - Nested:  ``skills/<category>/<sub>/<name>.md``  → ``(category, "<sub>/<name>")``

    Nested skills are namespaced with a ``/`` so callers can use the
    full ``category/sub/name`` path or the canonical short name
    ``sub/name`` interchangeably.
    """
    skills_dir = get_kael_resource_path("skills")
    if not skills_dir.exists():
        return
    for category_dir in sorted(skills_dir.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        if category_dir.name in _INTERNAL_SKILL_CATEGORIES:
            continue
        for file_path in sorted(category_dir.glob("*.md")):
            yield category_dir.name, file_path.stem
        for sub_dir in sorted(category_dir.iterdir()):
            if not sub_dir.is_dir() or sub_dir.name.startswith("__"):
                continue
            for file_path in sorted(sub_dir.glob("*.md")):
                yield category_dir.name, f"{sub_dir.name}/{file_path.stem}"


def get_all_skill_names() -> set[str]:
    """Return every user-selectable skill name (bare, no category prefix).

    For nested skills, the returned name is ``"<sub>/<name>"`` so it is
    disambiguated within a category.
    """
    return {name for _, name in _iter_user_skill_files()}


def get_available_skills() -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for category, name in _iter_user_skill_files():
        grouped.setdefault(category, []).append(name)
    return grouped


def validate_requested_skills(skill_list: list[str], max_skills: int = 5) -> str | None:
    """Validate a list of user-passed skill names.

    Returns ``None`` on success, or a model-readable error message
    describing what was wrong (count exceeded, unknown names).

    Accepts the same forms :func:`load_skills` does:
    - bare short name (``"xss"``)
    - ``"sub/name"`` for nested skills (``"web/sqli"``)
    - ``"category/name"`` (``"vulnerabilities/xss"``)
    - ``"category/sub/name"`` (``"vulnerabilities/web/xss"``)
    """
    if len(skill_list) > max_skills:
        return (
            f"Cannot specify more than {max_skills} skills per agent; "
            f"got {len(skill_list)}. Aim for 1-3 related skills per specialist."
        )
    if not skill_list:
        return None
    available = get_all_skill_names()
    unresolved = [s for s in skill_list if not _name_resolves(s, available)]
    if unresolved:
        return f"Invalid skill name(s): {unresolved}. Available skills: {sorted(available)}"
    return None


def _name_resolves(name: str, available: set[str]) -> bool:
    """Return True if ``name`` matches any form :func:`load_skills` accepts."""
    if name in available:
        return True
    parts = name.split("/")
    if len(parts) == 3:
        return f"{parts[1]}/{parts[2]}" in available
    if len(parts) == 2:
        return parts[1] in available or f"{parts[0]}/{parts[1]}" in available
    return False


def load_skills(skill_names: list[str]) -> dict[str, str]:
    """Load skill markdown bodies (frontmatter stripped) by name.

    Skill files live at ``kael/skills/<category>/<name>.md`` (flat)
    or ``kael/skills/<category>/<sub>/<name>.md`` (nested). Names
    can be:

    - bare short name (``"sqli"`` — first match wins)
    - ``"sub/name"`` for nested skills
    - ``"category/name"`` (flat)
    - ``"category/sub/name"`` (nested, full path)

    Missing skills are logged and skipped.
    """
    skills_dir = get_kael_resource_path("skills")
    if not skills_dir.exists():
        return {}

    by_short: dict[str, str] = {}
    by_path: dict[str, str] = {}
    for category_dir in skills_dir.iterdir():
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        for file_path in category_dir.glob("*.md"):
            rel = f"{category_dir.name}/{file_path.stem}.md"
            by_path[rel] = rel
            by_path[file_path.stem] = rel
            by_path[f"{file_path.stem}.md"] = rel
            by_short.setdefault(file_path.stem, rel)
        for sub_dir in category_dir.iterdir():
            if not sub_dir.is_dir() or sub_dir.name.startswith("__"):
                continue
            for file_path in sorted(sub_dir.glob("*.md")):
                rel = f"{category_dir.name}/{sub_dir.name}/{file_path.stem}.md"
                by_path[rel] = rel
                short = f"{sub_dir.name}/{file_path.stem}"
                by_path[short] = rel
                by_path[f"{short}.md"] = rel
                by_short.setdefault(short, rel)
                by_short.setdefault(file_path.stem, rel)

    skill_content: dict[str, str] = {}
    for skill_name in skill_names:
        rel_path: str | None
        if skill_name in by_path:
            rel_path = by_path[skill_name]
        elif "/" in skill_name:
            rel_path = f"{skill_name}.md"
        elif skill_name in by_short:
            rel_path = by_short[skill_name]
        elif (skills_dir / f"{skill_name}.md").exists():
            rel_path = f"{skill_name}.md"
        else:
            rel_path = None

        if rel_path is None or not (skills_dir / rel_path).exists():
            logger.warning("Skill not found: %s", skill_name)
            continue

        try:
            content = (skills_dir / rel_path).read_text(encoding="utf-8")
        except (OSError, ValueError) as e:
            logger.warning("Failed to load skill %s: %s", skill_name, e)
            continue

        var_name = _derive_var_name(skill_name, rel_path)
        skill_content[var_name] = _FRONTMATTER_PATTERN.sub("", content).lstrip()
        logger.debug("Loaded skill: %s -> %s (file=%s)", skill_name, var_name, rel_path)

    logger.debug("load_skills: %d skill(s) resolved", len(skill_content))
    return skill_content
