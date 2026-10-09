"""OpenRouter provider selection across settings sources and model calls."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from litellm import ModelResponse
from pydantic import ValidationError

from kael.config import apply_config_override, load_settings, persist_current
from kael.config.settings import LlmSettings
from kael.core.inputs import make_model_settings


@pytest.mark.parametrize("source", ["env", "dotenv", "config"])
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" deepinfra ", {"only": ["deepinfra"]}),
        (
            '{"order":["deepinfra","together"],"allow_fallbacks":false}',
            {"order": ["deepinfra", "together"], "allow_fallbacks": False},
        ),
    ],
)
def test_provider_settings_sources(
    source: str, raw: str, expected: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    if source == "env":
        monkeypatch.setenv("KAEL_OPENROUTER_PROVIDER", raw)
    elif source == "dotenv":
        Path(".env").write_text(f"KAEL_OPENROUTER_PROVIDER='{raw}'\n", encoding="utf-8")
    else:
        config = Path("config.json")
        config.write_text(json.dumps({"env": {"KAEL_OPENROUTER_PROVIDER": raw}}), encoding="utf-8")
        apply_config_override(config)

    assert load_settings().llm.openrouter_provider == expected


def test_provider_setting_persists(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Path("config.json")
    apply_config_override(config)
    monkeypatch.setenv("KAEL_OPENROUTER_PROVIDER", "deepinfra")
    persist_current()
    monkeypatch.delenv("KAEL_OPENROUTER_PROVIDER")
    apply_config_override(config)
    assert load_settings().llm.openrouter_provider == {"only": ["deepinfra"]}


@pytest.mark.parametrize("raw", ["", "  ", "null"])
def test_empty_provider_disables_routing(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAEL_OPENROUTER_PROVIDER", raw)
    assert load_settings().llm.openrouter_provider is None


@pytest.mark.parametrize("raw", ['{"only":', '["deepinfra"]'])
def test_invalid_provider_json_is_rejected(raw: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAEL_OPENROUTER_PROVIDER", raw)
    with pytest.raises(ValidationError):
        load_settings()


@pytest.mark.parametrize(
    ("model", "api_base", "routed"),
    [
        ("openrouter/meta-llama/llama-3.3-70b-instruct", None, True),
        ("litellm/openrouter/meta-llama/llama-3.3-70b-instruct", None, True),
        ("any-llm/openrouter/meta-llama/llama-3.3-70b-instruct", None, True),
        ("openai/meta-llama/llama-3.3-70b-instruct", "https://openrouter.ai/api/v1", True),
        ("gpt-4o", "https://openrouter.ai/api/v1/", True),
        ("openai/gpt-4o", None, False),
        ("openai/my-openrouter-model", "http://localhost:8000/v1", False),
        ("gpt-4o", "https://openrouter.ai.example.com/api/v1", False),
    ],
)
def test_provider_routing(model: str, api_base: str | None, routed: bool) -> None:
    settings = LlmSettings(openrouter_provider={"only": ["deepinfra"]})
    model_settings = make_model_settings(
        None,
        model_name=model,
        openrouter_provider=settings.openrouter_provider,
        api_base=api_base,
    )
    assert model_settings.extra_body == ({"provider": {"only": ["deepinfra"]}} if routed else None)


@pytest.mark.parametrize("operation", ["warmup", "dedupe", "vision"])
async def test_auxiliary_requests_select_provider(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kael.interface.main import warm_up_llm
    from kael.report.dedupe import check_duplicate
    from kael.tools.view_image.tool import _analyze_image

    monkeypatch.setenv("KAEL_LLM", "openrouter/meta-llama/llama-3.3-70b-instruct")
    monkeypatch.setenv("KAEL_OPENROUTER_PROVIDER", "deepinfra")
    response = ModelResponse(
        choices=[
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": '{"is_duplicate":false}'},
            }
        ],
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    )
    with (
        patch("kael.config.models.configure_sdk_model_defaults"),
        patch("kael.report.dedupe.configure_sdk_model_defaults"),
        patch("kael.tools.view_image.tool.configure_sdk_model_defaults"),
        patch("kael.report.dedupe.get_global_report_state", return_value=None),
        patch("kael.tools.view_image.tool.get_global_report_state", return_value=None),
        patch("litellm.acompletion", new_callable=AsyncMock, return_value=response) as completion,
    ):
        if operation == "warmup":
            await warm_up_llm()
        elif operation == "dedupe":
            await check_duplicate({"title": "candidate"}, [{"id": "vuln-1"}])
        else:
            await _analyze_image(
                data_url="data:image/png;base64,aGVsbG8=",
                prompt="Describe",
                display_path="image.png",
            )

    completion.assert_awaited_once()
    assert completion.await_args is not None
    assert completion.await_args.kwargs["extra_body"] == {"provider": {"only": ["deepinfra"]}}


@pytest.mark.parametrize(
    ("vision_base", "routed"),
    [(None, True), ("https://openrouter.ai/api/v1", True), ("http://localhost:8000/v1", False)],
)
async def test_vision_routing_uses_its_own_endpoint(
    vision_base: str | None, routed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kael.tools.view_image.tool import _analyze_image

    monkeypatch.setenv("KAEL_LLM", "openrouter/meta-llama/llama-3.3-70b-instruct")
    monkeypatch.setenv("LLM_API_BASE", "https://openrouter.ai/api/v1")
    monkeypatch.setenv("KAEL_VISION_LLM", "qwen2.5vl-7b")
    monkeypatch.setenv("KAEL_OPENROUTER_PROVIDER", "deepinfra")
    if vision_base:
        monkeypatch.setenv("VISION_LLM_API_BASE", vision_base)
    get_response = AsyncMock(return_value=SimpleNamespace(output=[]))
    with (
        patch("kael.tools.view_image.tool.configure_sdk_model_defaults"),
        patch(
            "kael.tools.view_image.tool._build_vision_model",
            return_value=SimpleNamespace(get_response=get_response),
        ),
        patch("kael.tools.view_image.tool.get_global_report_state", return_value=None),
    ):
        await _analyze_image(
            data_url="data:image/png;base64,aGVsbG8=", prompt="Describe", display_path="image.png"
        )

    get_response.assert_awaited_once()
    assert get_response.await_args is not None
    assert get_response.await_args.kwargs["model_settings"].extra_body == (
        {"provider": {"only": ["deepinfra"]}} if routed else None
    )
