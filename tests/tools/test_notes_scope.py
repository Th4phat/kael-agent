"""Agent-private notes and explicit session or target sharing."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from agents import Agent

from kael.config import load_settings
from kael.core.paths import target_slug
from kael.tools.notes import tools as notes


async def test_default_notes_are_private_to_each_agent_and_survive_resume(tmp_path: Path) -> None:
    store = notes.hydrate_notes_from_disk(tmp_path / "first")
    contexts = [
        SimpleNamespace(
            context={"notes_store": store, "agent_id": agent_id},
            tool_name="create_note",
            tool_call_id=agent_id,
        )
        for agent_id in ("parent", "child", "sibling")
    ]
    created = []
    for ctx in contexts:
        agent_id = ctx.context["agent_id"]
        result = json.loads(
            await notes.create_note.on_invoke_tool(  # type: ignore[arg-type]
                ctx, json.dumps({"title": agent_id, "content": f"{agent_id} secret"})
            )
        )
        assert result["success"] and result["total_count"] == 1
        learning = json.loads(
            await notes.add_learning.on_invoke_tool(  # type: ignore[arg-type]
                ctx,
                json.dumps(
                    {"technique": agent_id, "context": f"{agent_id} learning", "outcome": "unknown"}
                ),
            )
        )
        assert learning["success"] and learning["total_count"] == 2
        created.append(result)

    for index, ctx in enumerate(contexts):
        own_store = notes.notes_store_from_context(ctx.context)
        assert own_store is not None
        before = own_store.path.read_bytes()
        listed = json.loads(
            await notes.list_notes.on_invoke_tool(ctx, '{"include_content": true}')  # type: ignore[arg-type]
        )
        assert listed["total_count"] == listed["filtered_count"] == 2
        assert all(note["title"] == ctx.context["agent_id"] for note in listed["notes"])
        for other_index, other in enumerate(created):
            if other_index == index:
                continue
            for tool, payload in (
                (notes.get_note, {"note_id": other["note_id"]}),
                (
                    notes.update_note,
                    {"note_id": other["note_id"], "content": "overwrite", "force": True},
                ),
                (notes.delete_note, {"note_id": other["note_id"]}),
            ):
                result = json.loads(await tool.on_invoke_tool(ctx, json.dumps(payload)))  # type: ignore[arg-type]
                assert not result["success"]
                assert "not found" in result["error"]
        assert own_store.path.read_bytes() == before

    resumed = notes.hydrate_notes_from_disk(tmp_path / "first")
    for ctx, note in zip(contexts, created, strict=True):
        ctx.context["notes_store"] = resumed
        own = json.loads(
            await notes.get_note.on_invoke_tool(  # type: ignore[arg-type]
                ctx, json.dumps({"note_id": note["note_id"]})
            )
        )
        assert own["note"]["content"] == f"{ctx.context['agent_id']} secret"
    other_context = SimpleNamespace(
        context={
            "notes_store": notes.hydrate_notes_from_disk(tmp_path / "second"),
            "agent_id": "parent",
        },
        tool_name="get_note",
        tool_call_id="other-session",
    )
    other_session = json.loads(
        await notes.get_note.on_invoke_tool(  # type: ignore[arg-type]
            other_context, json.dumps({"note_id": created[0]["note_id"]})
        )
    )
    assert not other_session["success"]
    updated = json.loads(
        await notes.update_note.on_invoke_tool(  # type: ignore[arg-type]
            contexts[0], json.dumps({"note_id": created[0]["note_id"], "content": "updated"})
        )
    )
    assert updated["success"] and updated["total_count"] == 2
    deleted = json.loads(
        await notes.delete_note.on_invoke_tool(  # type: ignore[arg-type]
            contexts[0], json.dumps({"note_id": created[0]["note_id"]})
        )
    )
    assert deleted["success"] and deleted["total_count"] == 1


@pytest.mark.parametrize("agent_id", [None, "", "../parent", "/tmp/parent"])
async def test_default_notes_require_a_valid_agent_identity(
    tmp_path: Path, agent_id: str | None
) -> None:
    store = notes.hydrate_notes_from_disk(tmp_path)
    ctx = SimpleNamespace(
        context={"notes_store": store, "agent_id": agent_id},
        tool_name="create_note",
        tool_call_id="invalid-agent",
    )
    for tool, payload in (
        (notes.list_notes, {}),
        (notes.get_note, {"note_id": "foreign"}),
        (notes.create_note, {"title": "new", "content": "private"}),
        (notes.add_learning, {"technique": "new", "context": "private", "outcome": "unknown"}),
        (notes.update_note, {"note_id": "foreign", "content": "overwrite"}),
        (notes.delete_note, {"note_id": "foreign"}),
    ):
        result = json.loads(await tool.on_invoke_tool(ctx, json.dumps(payload)))  # type: ignore[arg-type]
        assert not result["success"]
    assert not store.path.exists()


def test_real_scan_targets_have_distinct_memory_keys() -> None:
    first = [{"type": "malware_sample", "details": {"target_file": "/tmp/first.zip"}}]
    second = [{"type": "malware_sample", "details": {"target_file": "/tmp/second.zip"}}]

    assert target_slug(first) != target_slug(second)


@pytest.mark.parametrize(
    ("kind", "key", "value"),
    [
        ("repository", "target_repo", "https://git.example.com/org/repo"),
        ("local_code", "target_path", "/tmp/source"),
        ("malware_sample", "target_file", "/tmp/sample.zip"),
        ("web_application", "target_url", "https://example.com/app"),
        ("ip_address", "target_ip", "192.0.2.1"),
    ],
)
def test_memory_keys_use_target_details(kind: str, key: str, value: str) -> None:
    target = {"type": kind, "details": {key: value, "workspace_subdir": "shared-label"}}
    key_from_details = target_slug([target])
    assert key_from_details is not None
    assert key_from_details == target_slug([{"type": kind, "value": value}])
    assert key_from_details != target_slug([{"type": kind, "details": {key: value + "other"}}])


def test_memory_keys_do_not_merge_case_punctuation_long_names_or_target_sets() -> None:
    def target(value: str) -> dict:
        return {"type": "malware_sample", "details": {"target_file": value}}

    for first, second in (
        ("/tmp/Case.zip", "/tmp/case.zip"),
        ("/tmp/a-b.zip", "/tmp/a/b.zip"),
        ("/tmp/" + "long" * 30 + "a.zip", "/tmp/" + "long" * 30 + "b.zip"),
    ):
        assert target_slug([target(first)]) != target_slug([target(second)])
    first, second = target("/tmp/one.zip"), target("/tmp/two.zip")
    assert target_slug([first, second]) == target_slug([second, first, first])
    assert target_slug([first, second]) != target_slug([first])


def test_default_scope_ignores_legacy_shared_notes_memory_and_other_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    memory_root = tmp_path / "memory"
    legacy = memory_root / "default"
    legacy.mkdir(parents=True)
    legacy_file = legacy / "learnings.json"
    legacy_file.write_text(json.dumps({"foreign": {"category": "learnings", "content": "secret"}}))
    legacy_contents = legacy_file.read_bytes()
    monkeypatch.setattr(notes, "memory_dir_for", lambda slug: memory_root / slug)
    targets = [{"type": "malware_sample", "details": {"target_file": "/tmp/sample.zip"}}]
    assert load_settings().memory.scope == "agent"

    first_dir = tmp_path / "first"
    first_dir.mkdir()
    shared_file = first_dir / "notes.json"
    shared_file.write_text(json.dumps({"legacy": {"title": "other agent", "content": "secret"}}))
    shared_contents = shared_file.read_bytes()

    first = notes.hydrate_notes_from_disk(first_dir, targets=targets)
    assert first.notes == {}
    private = notes.notes_store_from_context({"notes_store": first, "agent_id": "owner"})
    assert private is not None and private.notes == {}
    result = notes._create_note_impl("first task", "first secret", "learnings", store=private)
    assert result["success"]
    assert first.memory_path is None
    second = notes.hydrate_notes_from_disk(tmp_path / "second", targets=targets)
    assert second.notes == {}
    assert second.memory_path is None
    assert shared_file.read_bytes() == shared_contents
    assert legacy_file.read_bytes() == legacy_contents
    assert list(memory_root.iterdir()) == [legacy]


def test_target_scope_only_shares_learnings_for_the_same_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(notes, "memory_dir_for", lambda slug: tmp_path / "memory" / slug)
    targets = [{"type": "malware_sample", "details": {"target_file": "/tmp/sample.zip"}}]
    other_targets = [{"type": "malware_sample", "details": {"target_file": "/tmp/other.zip"}}]
    first = notes.hydrate_notes_from_disk(tmp_path / "first", targets=targets, scope="target")
    learning = notes._create_note_impl("technique", "target secret", "learnings", store=first)
    general = notes._create_note_impl("local note", "session secret", store=first)

    same_target = notes.hydrate_notes_from_disk(tmp_path / "same", targets=targets, scope="target")
    assert learning["note_id"] in same_target.notes
    assert general["note_id"] not in same_target.notes
    other_target = notes.hydrate_notes_from_disk(
        tmp_path / "other", targets=other_targets, scope="target"
    )
    assert other_target.notes == {}
    default_session = notes.hydrate_notes_from_disk(tmp_path / "session", targets=targets)
    assert default_session.notes == {}

    deleted = notes._delete_note_impl(learning["note_id"], store=same_target)
    assert deleted["success"]
    later = notes.hydrate_notes_from_disk(tmp_path / "later", targets=targets, scope="target")
    assert later.notes == {}


@pytest.mark.parametrize("targets", [[], [{"type": "malware_sample", "details": {}}]])
def test_target_scope_without_an_identity_stays_session_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, targets: list[dict]
) -> None:
    memory_root = tmp_path / "memory"
    monkeypatch.setattr(notes, "memory_dir_for", lambda slug: memory_root / slug)
    prior = notes.hydrate_notes_from_disk(
        tmp_path / "prior",
        targets=[{"type": "web_application", "details": {"target_url": "https://example.com"}}],
        scope="target",
    )
    notes._create_note_impl("prior", "target secret", "learnings", store=prior)
    assert prior.memory_path is not None
    prior_contents = prior.memory_path.read_bytes()

    current = notes.hydrate_notes_from_disk(tmp_path / "current", targets=targets, scope="target")
    assert target_slug(targets) is None
    assert current.notes == {}
    assert current.memory_path is None
    notes._create_note_impl("current", "session secret", "learnings", store=current)
    assert prior.memory_path.read_bytes() == prior_contents


async def test_tools_without_session_context_cannot_use_another_store(tmp_path: Path) -> None:
    store = notes.hydrate_notes_from_disk(tmp_path)
    created = notes._create_note_impl("private", "session secret", store=store)
    before = store.path.read_bytes()
    ctx = SimpleNamespace(context={}, tool_name="list_notes", tool_call_id="missing-session")
    for tool, payload in (
        (notes.list_notes, {}),
        (notes.get_note, {"note_id": created["note_id"]}),
        (notes.create_note, {"title": "new", "content": "wrong store"}),
        (notes.add_learning, {"technique": "new", "context": "wrong store", "outcome": "unknown"}),
        (notes.update_note, {"note_id": created["note_id"], "content": "overwrite"}),
        (notes.delete_note, {"note_id": created["note_id"]}),
    ):
        result = await tool.on_invoke_tool(ctx, json.dumps(payload))  # type: ignore[arg-type]
        assert not json.loads(result)["success"]
        assert "session secret" not in result
    assert store.path.read_bytes() == before


@pytest.mark.parametrize("scope", ["agent", "session"])
async def test_tools_keep_their_session_when_another_session_is_loaded(
    tmp_path: Path, scope: str
) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_store = notes.hydrate_notes_from_disk(first_dir, scope=scope)  # type: ignore[arg-type]
    second_store = notes.hydrate_notes_from_disk(second_dir, scope=scope)  # type: ignore[arg-type]
    first_context = SimpleNamespace(
        context={"notes_store": first_store, "agent_id": "same-agent"},
        tool_name="add_learning",
        tool_call_id="first",
    )
    second_context = SimpleNamespace(
        context={"notes_store": second_store, "agent_id": "same-agent"},
        tool_name="create_note",
        tool_call_id="second",
    )

    first = json.loads(
        await notes.add_learning.on_invoke_tool(  # type: ignore[arg-type]
            first_context,
            json.dumps(
                {"technique": "first task", "context": "first secret", "outcome": "unknown"}
            ),
        )
    )
    second = json.loads(
        await notes.create_note.on_invoke_tool(  # type: ignore[arg-type]
            second_context, json.dumps({"title": "second task", "content": "second secret"})
        )
    )

    assert first["success"] and second["success"]
    first_notes = notes.notes_store_from_context(first_context.context)
    second_notes = notes.notes_store_from_context(second_context.context)
    assert first_notes is not None and second_notes is not None
    assert "first secret" in first_notes.path.read_text()
    assert "second secret" not in first_notes.path.read_text()
    assert "first secret" not in second_notes.path.read_text()

    listed = json.loads(await notes.list_notes.on_invoke_tool(second_context, "{}"))  # type: ignore[arg-type]
    assert listed["total_count"] == 1
    assert listed["notes"][0]["note_id"] == second["note_id"]
    for tool, payload in (
        (notes.get_note, {"note_id": first["note_id"]}),
        (notes.update_note, {"note_id": first["note_id"], "content": "overwrite"}),
        (notes.delete_note, {"note_id": first["note_id"]}),
    ):
        result = json.loads(await tool.on_invoke_tool(second_context, json.dumps(payload)))  # type: ignore[arg-type]
        assert not result["success"]
    assert "first secret" in first_notes.path.read_text()

    resumed = notes.hydrate_notes_from_disk(first_dir, scope=scope)  # type: ignore[arg-type]
    first_context.context["notes_store"] = resumed
    result = json.loads(
        await notes.get_note.on_invoke_tool(  # type: ignore[arg-type]
            first_context, json.dumps({"note_id": first["note_id"]})
        )
    )
    assert result["note"]["content"] == "first secret"


@pytest.mark.parametrize("scope", ["agent", "session"])
async def test_scan_runner_applies_notes_scope_to_children_and_isolates_other_runs(
    monkeypatch: pytest.MonkeyPatch, scope: str
) -> None:
    from kael.core import execution, runner

    load_settings().llm.model = "openrouter/example-model"
    load_settings().memory.scope = scope  # type: ignore[assignment]
    monkeypatch.setattr(
        runner.session_manager,
        "create_or_reuse",
        AsyncMock(
            return_value={"client": MagicMock(), "session": MagicMock(), "mitm_client": MagicMock()}
        ),
    )
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda settings: None)
    monkeypatch.setattr(runner, "build_kael_agent", lambda **kwargs: Agent(name="test"))
    monkeypatch.setattr(
        runner, "make_child_factory", lambda **kwargs: lambda **child: Agent(name="child")
    )
    stores = []

    async def loop(**kwargs):
        context = kwargs["context"]
        if context["parent_id"] is None:
            stores.append(context["notes_store"])
            assert context["notes_store"].notes == {}
            spawned = await context["spawn_child_agent"](
                parent_ctx=context, name="child", task="write a note", skills=[], parent_history=[]
            )
            await context["coordinator"].runtimes[spawned["agent_id"]].task
            own = notes.notes_store_from_context(context)
            assert own is not None
            assert len(own.notes) == (0 if scope == "agent" else 1)
            child = notes.notes_store_from_context(
                {"notes_store": context["notes_store"], "agent_id": spawned["agent_id"]}
            )
            assert child is not None and len(child.notes) == 1
            assert (own is child) == (scope == "session")
        else:
            assert context["notes_store"] is stores[-1]
            ctx = SimpleNamespace(context=context, tool_name="create_note", tool_call_id="child")
            result = json.loads(
                await notes.create_note.on_invoke_tool(  # type: ignore[arg-type]
                    ctx, json.dumps({"title": "child progress", "content": "this session only"})
                )
            )
            assert result["success"]
            await context["coordinator"].set_status(context["agent_id"], "completed")
        return SimpleNamespace(final_output={"scan_completed": True})

    monkeypatch.setattr(runner, "run_agent_loop", loop)
    monkeypatch.setattr(execution, "run_agent_loop", loop)
    for run_name in ("first", "second"):
        await runner.run_kael_scan(
            scan_config={}, scan_id=run_name, image="test-image", cleanup_on_exit=False
        )
    assert stores[0] is not stores[1]
    assert stores[0].path != stores[1].path
