# view_image

Kael vision sub-agent: loads an image from the sandbox workspace,
sends it to a dedicated vision LLM call (high detail), and returns
the analysis as **text**. The main agent never receives the raw image
bytes — this sidesteps chat-completions translation quirks,
history-compaction loss, and the image-stripping fallback in
`kael.core.sessions.strip_all_images_from_session`.

## Why this design

Routing images through the main agent's tool-call loop has two failure
modes we've seen in the wild:

1. **Provider translation downgrade.** When the LLM runs through a
   non-OpenAI route (litellm → OpenRouter, Anthropic, etc.), the SDK's
   `ToolOutputImage` is translated to a chat-completions `image_url`
   part. Some providers silently downgrade detail level or strip
   metadata, producing the same model giving worse answers in-agent
   than in a chat web app on the same image.
2. **Image-strip recovery.** If the SDK reports vision-not-supported,
   `strip_all_images_from_session` purges every image from history.
   Subsequent reasoning over the image is then guessing.

Returning text fixes both: text survives every transform, and the main
agent reasons over a precise transcription/description.

## Arguments

- `path` (string, required): image path inside `/workspace`. Absolute
  and relative paths both work.
- `prompt` (string, optional): question or instruction for the vision
  sub-agent. Default: full detailed description with verbatim text
  transcription.

## Configuration

`KAEL_VISION_LLM` is **optional**. If your main `KAEL_LLM` already
supports vision (e.g. `openai/gpt-5`, `openrouter/anthropic/claude-3.5-sonnet`),
do nothing — `view_image` reuses it. Set `KAEL_VISION_LLM` only when
your main model is text-only and you want to route image analysis to a
different vision-capable model.

- **Vision model:** `KAEL_VISION_LLM` — dedicated vision model.
  Falls back to `KAEL_LLM` when unset. When set, the main `KAEL_LLM`
  is treated as text-only.
- **Vision credentials:** `VISION_LLM_API_KEY`, `VISION_LLM_API_BASE`
  — optional; fall back to `LLM_API_KEY` / `LLM_API_BASE`.
- **Routing is picked by the model spelling:**
  - **Provider-prefixed** (`openai/gpt-4o`, `openrouter/...`,
    `anthropic/...`) → routed through litellm exactly like the main
    agent. OpenRouter provider routing
    (`KAEL_OPENROUTER_PROVIDER`) is honored.
  - **Bare model name** (`gpt-4o`, `qwen2.5vl-7b`, `llava`) → routed
    through a raw OpenAI-compatible client pointed at
    `VISION_LLM_API_BASE`. Use this for vLLM, Ollama, LM Studio,
    LiteLLM Proxy, an in-house gateway — anything that speaks the
    OpenAI Chat Completions API.

### Example A: vision-capable main (most users)

```bash
export KAEL_LLM="openai/gpt-5"   # already has vision
export LLM_API_KEY="sk-..."
# KAEL_VISION_LLM is unset — view_image just reuses KAEL_LLM.
```

### Example B: text-only main + dedicated vision via litellm

```bash
export KAEL_LLM="anthropic/claude-3-haiku"   # text-only, cheap
export LLM_API_KEY="sk-ant-..."

export KAEL_VISION_LLM="openai/gpt-4o"        # vision specialist
export VISION_LLM_API_KEY="sk-openai-..."
```

### Example C: custom OpenAI-compatible vision endpoint

```bash
export KAEL_LLM="openai/gpt-5"                # main can stay anywhere
export LLM_API_KEY="sk-..."

# Bare model name → raw OpenAI client → custom base URL
export KAEL_VISION_LLM="qwen2.5vl-7b"
export VISION_LLM_API_BASE="http://localhost:11434/v1"   # Ollama
export VISION_LLM_API_KEY="ollama"                       # any non-empty string
```

## Limits

- Max image size: 10 MB (set by the upstream SDK helpers we reuse).
- Supported types: PNG, JPEG, GIF, WebP, BMP, TIFF, SVG, plus anything
  `mimetypes` recognizes as `image/*`.
- Cost is recorded against the run via `ReportState.record_sdk_usage`
  under the synthetic agent id `view_image`.

## Implementation

- **Module:** `kael/tools/view_image/tool.py` —
  `ViewImageTool` subclasses the upstream SDK
  `agents.sandbox.capabilities.tools.view_image.ViewImageTool`
  so it inherits file-read, path-policy, mime-sniff, and size-limit
  logic. Only `run()` is overridden to add the vision call.
- **Wired in:** `kael/agents/factory.py` —
  `_swap_view_image(toolset)` replaces the SDK tool inside the
  `Filesystem` capability's configurator (runs for both
  chat-completions and Responses-API backends).
- **Skill:** screenshot workflow lives in
  `kael/skills/tooling/agent_browser.md`.
- **Tests:** `tests/tools/test_view_image.py`.
