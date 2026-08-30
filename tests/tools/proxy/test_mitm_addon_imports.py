"""Test that the mitm addon can be imported in both the host (package)
and the in-container (flat-script) contexts.

The flat context is the one that broke twice in PR 1:

1. mitmdump puts the addon's directory on ``sys.path[0]`` but the
   ``kael`` package is not installed in the container, so the addon
   must fall back to ``from scope_store import ...`` for the sibling
   file shipped at ``/opt/kael-python/scope_store.py``.

2. mitmproxy's script loader (mitmproxy/addons/script.py, line 37-38)
   uses ``importlib.util.module_from_spec`` + ``loader.exec_module``
   but does NOT register the module in ``sys.modules``. The
   ``@dataclass`` decorator then crashes with ``AttributeError:
   'NoneType' object has no attribute '__dict__'`` when it tries to
   resolve the class's module namespace. The addon must therefore
   avoid ``@dataclass`` entirely.

3. The addon uses ``from __future__ import annotations`` so every
   annotation is a string. mitmproxy introspects method signatures
   with ``inspect.get_annotations(..., eval_str=True)`` at startup,
   which evaluates those strings against the module globals. Any name
   used in an annotation that is only imported under ``TYPE_CHECKING``
   (e.g. ``Sequence``) is undefined at runtime and crashes startup
   with ``NameError``. Such names must be imported at runtime.
"""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
ADDON_PATH = REPO_ROOT / "kael/tools/proxy/mitm_addon.py"
SCOPE_STORE_PATH = REPO_ROOT / "kael/tools/proxy/scope_store.py"


def test_addon_source_does_not_use_dataclass() -> None:
    """Regression guard for the PR 1 dataclass crash.

    mitmproxy's script loader does not register the addon module in
    ``sys.modules`` before exec, which makes any ``@dataclass`` (or
    any decorator that introspects ``cls.__module__``) raise
    ``AttributeError: 'NoneType' object has no attribute '__dict__'``
    at import time. Until mitmproxy fixes its loader, the addon must
    not use ``@dataclass`` anywhere.
    """
    import ast

    tree = ast.parse(ADDON_PATH.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "dataclass":
                offenders.append(f"line {node.lineno}: @{decorator.id} on {node.name}")
            elif isinstance(decorator, ast.Attribute) and decorator.attr == "dataclass":
                offenders.append(f"line {node.lineno}: @{ast.unparse(decorator)} on {node.name}")
    assert not offenders, (
        "mitm_addon.py uses @dataclass on one or more classes; "
        "mitmproxy's script loader does not register the module in "
        "sys.modules, so dataclass crashes at import time. Offenders:\n" + "\n".join(offenders)
    )
    # Belt-and-braces: also reject any `from dataclasses import` or
    # `import dataclasses` since the addon has no use for it.
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "dataclasses":
            pytest.fail(
                f"mitm_addon.py imports from dataclasses at line {node.lineno}; "
                "this is not allowed until mitmproxy's script loader is fixed."
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "dataclasses":
                    pytest.fail(f"mitm_addon.py imports dataclasses at line {node.lineno}.")


def test_addon_imports_under_mitmproxy_loader_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate exactly what mitmproxy's ``load_script`` does:

    1. Build a ``SourceFileLoader`` for the script.
    2. ``importlib.util.spec_from_loader(fullname, loader=loader)``.
    3. ``importlib.util.module_from_spec(spec)``.
    4. ``loader.exec_module(m)``.

    Critically, the module is NOT added to ``sys.modules`` at any
    point. If the addon uses ``@dataclass`` (or any other decorator
    that introspects the class's module namespace), this step will
    raise ``AttributeError: 'NoneType' object has no attribute
    '__dict__'``.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        shutil.copy(SCOPE_STORE_PATH, tmp_path / "scope_store.py")
        shutil.copy(ADDON_PATH, tmp_path / "mitm_addon.py")

        # Drop any cached imports from earlier test files so we
        # genuinely re-execute the addon.
        for mod in list(sys.modules):
            if mod == "kael" or mod.startswith("kael."):
                monkeypatch.delitem(sys.modules, mod, raising=False)
        for mod in ("mitm_addon", "scope_store"):
            monkeypatch.delitem(sys.modules, mod, raising=False)

        with monkeypatch.context() as m:
            m.syspath_prepend(str(tmp_path))
            fullname = "__mitmproxy_script__.mitm_addon"
            monkeypatch.delitem(sys.modules, fullname, raising=False)
            loader = importlib.machinery.SourceFileLoader(fullname, str(tmp_path / "mitm_addon.py"))
            spec = importlib.util.spec_from_loader(fullname, loader=loader)
            assert spec is not None
            module = importlib.util.module_from_spec(spec)
            try:
                loader.exec_module(module)
            except AttributeError as exc:
                if "'NoneType' object has no attribute '__dict__'" in str(exc):
                    pytest.fail(
                        "mitm_addon.py raised the mitmproxy script-loader "
                        "dataclass bug. Most likely a @dataclass decorator "
                        "was reintroduced; remove it and use a plain class."
                    )
                raise
            assert module.KaelAddon is not None
            assert isinstance(module.addons, list)
            assert len(module.addons) == 1
            assert isinstance(module.addons[0], module.KaelAddon)
            # mitmproxy reads `.name` to know which module to attach.
            # Our addon doesn't set it, so mitmproxy falls back to
            # the path (see mitmproxy/addons/script.py line 40). No
            # assertion needed here; the import succeeding is the
            # contract.


def test_addon_imports_under_host_package_context() -> None:
    """Sanity check the other path: the host SDK imports the addon
    via ``kael.tools.proxy.mitm_addon``. Already exercised by
    ``test_sitemap`` and ``test_mitm_control`` modules, but explicit
    here so the dual-import contract is documented in one place.
    """
    from kael.tools.proxy import mitm_addon

    assert mitm_addon.KaelAddon is not None
    assert mitm_addon.addons


def test_addon_method_annotations_resolve_at_runtime() -> None:
    """Regression guard for the PR 1 ``eval_str`` crash.

    The addon uses ``from __future__ import annotations``, so every
    annotation is a string. mitmproxy's ``@command.command`` decorator
    (and parts of the addon manager) introspect method signatures with
    ``inspect.get_annotations(..., eval_str=True)``, which evaluates
    those strings against the module globals. Any name used in an
    annotation that is only imported under ``TYPE_CHECKING`` (e.g.
    ``Sequence``) is undefined at runtime and crashes startup with
    ``NameError: name '...' is not defined``.

    This test mirrors that introspection across every public method of
    the addon and the handler classes, failing if any annotation can't
    be evaluated.
    """
    import inspect

    from kael.tools.proxy import mitm_addon

    failures: list[str] = []
    for cls_name in ("KaelAddon",):
        cls = getattr(mitm_addon, cls_name)
        for name, member in inspect.getmembers(cls, predicate=inspect.isfunction):
            try:
                inspect.signature(member, eval_str=True)
            except NameError as exc:
                failures.append(f"{cls_name}.{name}: {exc}")

    assert not failures, (
        "One or more addon method annotations cannot be evaluated at "
        "runtime (likely a name imported only under TYPE_CHECKING used "
        "in a runtime-introspected signature). mitmproxy evaluates these "
        "with eval_str=True at startup. Failures:\n" + "\n".join(failures)
    )
