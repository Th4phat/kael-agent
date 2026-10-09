"""view_image — vision sub-agent.

Instead of returning the image into the main agent's context (where it gets
mangled by chat-completions translation, history compaction, and the
"vision not supported" image-stripping recovery in
``kael.core.sessions.strip_all_images_from_session``), this tool spawns a
dedicated vision LLM call, asks it about the image, and returns plain text.

Plain text survives every downstream transform and matches what the user
sees in a chat web app: the model gets the image once, at high detail, with
no history pollution.

OpenAI-compatible: the call goes through ``KaelProvider`` → SDK model
layer → litellm/openai, using the Responses-API ``input_image`` content
type which the SDK translates to the chat-completions ``image_url`` part
for any provider that needs it. Honors ``KAEL_LLM`` / ``LLM_API_KEY`` /
``LLM_API_BASE`` / ``KAEL_OPENROUTER_PROVIDER`` like the main agent.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from agents.extensions.models.litellm_model import LitellmModel
from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.sandbox.capabilities.tools.view_image import (
    ViewImageArgs as _SdkViewImageArgs,
)
from agents.sandbox.capabilities.tools.view_image import (
    ViewImageTool as _SdkViewImageTool,
)
from agents.sandbox.capabilities.tools.view_image import (
    _coerce_payload_bytes,
    _detect_image_mime_type,
    _encode_data_url,
)
from agents.sandbox.errors import WorkspaceReadNotFoundError
from openai import AsyncOpenAI
from openai.types.responses import ResponseOutputMessage
from pydantic import Field

from kael.config import load_settings
from kael.config.models import (
    DEFAULT_MODEL_RETRY,
    KaelProvider,
    configure_sdk_model_defaults,
    openrouter_extra_body,
)
from kael.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents.items import ModelResponse
    from agents.tool import ToolOutputImage


logger = logging.getLogger(__name__)


_MAX_IMAGE_BYTES = 10 * 1024 * 1024
_MAX_IMAGE_SIZE_LABEL = "10MB"

_DEFAULT_PROMPT = (
    "Describe this image in detail. Transcribe any text exactly as it "
    "appears. Note layout, colors, UI elements, error messages, code, "
    "URLs, and anything security-relevant. Be precise; do not guess."
)

_VISION_SYSTEM_PROMPT = (
    "You are a vision analyst supporting a security testing agent. "
    "Look at the provided image and answer the user's question with "
    "high fidelity. Transcribe text verbatim. Report what is visible — "
    "do not invent details, do not summarize away specifics."
)


class ViewImageArgs(_SdkViewImageArgs):
    prompt: str = Field(
        default=_DEFAULT_PROMPT,
        description=(
            "Question or instruction for the vision sub-agent. Ask for a "
            "transcription, identification, or anything else you need."
        ),
    )


class ViewImageTool(_SdkViewImageTool):
    """Drop-in replacement for the SDK ViewImageTool.

    Reuses the upstream file-read + path-policy logic, then forwards the
    image to a vision LLM and returns its textual answer instead of the
    raw image.
    """

    tool_name: ClassVar[str] = "view_image"
    args_model: ClassVar[type[ViewImageArgs]] = ViewImageArgs  # type: ignore[assignment]
    tool_description: ClassVar[str] = (
        "Load an image from the sandbox workspace, send it to a dedicated "
        "vision model, and return the analysis as text. Optionally pass a "
        "`prompt` to ask a specific question about the image (default: full "
        "detailed description with verbatim text transcription)."
    )

    async def run(self, args: ViewImageArgs) -> ToolOutputImage | str:  # type: ignore[override]  # noqa: PLR0911
        input_path = Path(args.path)
        path_policy = self.session._workspace_path_policy()
        resolved_path = path_policy.absolute_workspace_path(input_path)
        display_path = path_policy.relative_path(input_path).as_posix()

        try:
            file_obj = await self.session.read(resolved_path, user=self.user)
        except (FileNotFoundError, WorkspaceReadNotFoundError):
            return f"image path `{display_path}` was not found"
        except Exception as exc:  # noqa: BLE001 - return as tool error string
            return f"unable to read image at `{display_path}`: {type(exc).__name__}"

        try:
            payload = file_obj.read(_MAX_IMAGE_BYTES + 1)
        finally:
            with contextlib.suppress(Exception):
                file_obj.close()

        try:
            payload = _coerce_payload_bytes(payload)
        except TypeError as exc:
            return f"unable to read image at `{display_path}`: {exc}"
        if len(payload) > _MAX_IMAGE_BYTES:
            return (
                f"image path `{display_path}` exceeded the allowed size of "
                f"{_MAX_IMAGE_SIZE_LABEL}; resize or compress the image and try again"
            )

        mime_type = _detect_image_mime_type(resolved_path, payload)
        if mime_type is None:
            return f"image path `{display_path}` is not a supported image file"

        data_url = _encode_data_url(mime_type, payload)
        try:
            return await _analyze_image(
                data_url=data_url,
                prompt=args.prompt,
                display_path=display_path,
            )
        except Exception as exc:
            logger.exception("view_image vision call failed for %s", display_path)
            return f"vision analysis of `{display_path}` failed: {type(exc).__name__}: {exc}"


async def _analyze_image(*, data_url: str, prompt: str, display_path: str) -> str:
    settings = load_settings()
    main_model = (settings.llm.model or "").strip()
    vision_model = (settings.llm.vision_model or "").strip()
    model_name = vision_model or main_model
    if not model_name:
        return (
            f"vision analysis of `{display_path}` skipped: neither "
            "KAEL_VISION_LLM nor KAEL_LLM is configured"
        )

    configure_sdk_model_defaults(settings)
    if vision_model:
        model = _build_vision_model(settings, vision_model)
    else:
        model = KaelProvider().get_model(model_name)

    api_base = (
        settings.llm.vision_api_base or settings.llm.api_base
        if vision_model
        else settings.llm.api_base
    )
    extra_body = openrouter_extra_body(model_name, settings.llm.openrouter_provider, api_base)

    input_items: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": [
                {"type": "input_text", "text": prompt},
                {
                    "type": "input_image",
                    "image_url": data_url,
                    "detail": "high",
                },
            ],
        }
    ]

    response = await model.get_response(
        system_instructions=_VISION_SYSTEM_PROMPT,
        input=input_items,
        model_settings=ModelSettings(
            retry=DEFAULT_MODEL_RETRY,
            include_usage=True,
            extra_body=extra_body,
        ),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )

    report_state = get_global_report_state()
    if report_state is not None:
        report_state.record_sdk_usage(
            agent_id="view_image",
            agent_name="view_image",
            model=model_name,
            usage=response.usage,
        )

    text = _extract_text(response)
    if not text:
        return f"vision model returned an empty response for `{display_path}`"
    return text


def _build_vision_model(
    settings: Any, vision_model: str
) -> LitellmModel | OpenAIChatCompletionsModel:
    """Build a model bound to vision-specific credentials.

    Two routes, picked by the model spelling:

    - **Provider-prefixed** (``openai/gpt-4o``,
      ``openrouter/anthropic/claude-3.5-sonnet``, ...): use
      ``LitellmModel`` so litellm handles routing, retries, and
      cost callbacks like the main agent.
    - **Bare model name** (``gpt-4o``, ``qwen2.5vl-7b``, ...): use a
      raw OpenAI client pointed at ``VISION_LLM_API_BASE``. This is the
      one-stop path for OpenAI-compatible endpoints — vLLM, Ollama,
      LM Studio, LiteLLM Proxy, any in-house gateway — without making
      the user learn litellm's provider-prefix conventions.

    Both paths bypass ``KaelProvider`` so the dedicated vision
    endpoint never has to share module-level litellm defaults with the
    main agent.
    """
    api_key = settings.llm.vision_api_key or settings.llm.api_key
    base_url = settings.llm.vision_api_base or settings.llm.api_base

    if "/" not in vision_model:
        client = AsyncOpenAI(api_key=api_key or "missing", base_url=base_url)
        return OpenAIChatCompletionsModel(model=vision_model, openai_client=client)

    return LitellmModel(model=vision_model, api_key=api_key, base_url=base_url)


def _extract_text(response: ModelResponse) -> str:
    parts: list[str] = []
    for item in response.output:
        if not isinstance(item, ResponseOutputMessage):
            continue
        for chunk in item.content:
            text = getattr(chunk, "text", None)
            if text:
                parts.append(text)
    return "".join(parts)
