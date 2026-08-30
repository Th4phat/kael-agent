---
name: agent_browser_vercel_sandbox
description: Run agent-browser inside Vercel Sandbox microVMs. Load this skill when BROWSER_BACKEND=vercel-sandbox — it replaces direct shell invocation with @vercel/sandbox SDK calls that spin up an ephemeral Linux VM, run agent-browser commands inside it, and shut down.
---

# agent-browser via Vercel Sandbox

When `BROWSER_BACKEND=vercel-sandbox`, do **not** invoke `agent-browser` directly via
`exec_command`. Instead use the `@vercel/sandbox` SDK from server-side TypeScript/JavaScript.
The agent-browser CLI runs inside an ephemeral Vercel microVM; commands are identical — only
the invocation mechanism changes.

## Setup

```bash
pnpm add @vercel/sandbox
```

Environment variables:

| Variable | Required | Description |
|---|---|---|
| `BROWSER_BACKEND` | — | Set to `vercel-sandbox` to activate this backend |
| `AGENT_BROWSER_SNAPSHOT_ID` | Recommended | Pre-built snapshot ID — sub-second startup |
| `VERCEL_TOKEN` | Local dev only | Personal access token (OIDC is automatic on Vercel) |
| `VERCEL_TEAM_ID` | Local dev only | Vercel team ID |
| `VERCEL_PROJECT_ID` | Local dev only | Vercel project ID |

## Core helper

```ts
import { Sandbox } from "@vercel/sandbox";

const CHROMIUM_DEPS = [
  "nss", "nspr", "libxkbcommon", "atk", "at-spi2-atk", "at-spi2-core",
  "libXcomposite", "libXdamage", "libXrandr", "libXfixes", "libXcursor",
  "libXi", "libXtst", "libXScrnSaver", "libXext", "mesa-libgbm", "libdrm",
  "mesa-libGL", "mesa-libEGL", "cups-libs", "alsa-lib", "pango", "cairo",
  "gtk3", "dbus-libs",
];

async function withBrowser<T>(
  fn: (sandbox: InstanceType<typeof Sandbox>) => Promise<T>,
): Promise<T> {
  const snapshotId = process.env.AGENT_BROWSER_SNAPSHOT_ID;
  const creds = {
    token: process.env.VERCEL_TOKEN,
    teamId: process.env.VERCEL_TEAM_ID,
    projectId: process.env.VERCEL_PROJECT_ID,
  };

  const sandbox = snapshotId
    ? await Sandbox.create({ ...creds, source: { type: "snapshot", snapshotId }, timeout: 120_000 })
    : await Sandbox.create({ ...creds, runtime: "node24", timeout: 120_000 });

  if (!snapshotId) {
    await sandbox.runCommand("sh", ["-c",
      `sudo dnf install -y --skip-broken ${CHROMIUM_DEPS.join(" ")} 2>&1 && sudo ldconfig`]);
    await sandbox.runCommand("npm", ["install", "-g", "agent-browser"]);
    await sandbox.runCommand("npx", ["agent-browser", "install"]);
  }

  try {
    return await fn(sandbox);
  } finally {
    await sandbox.stop();
  }
}
```

## Command invocation

All `agent-browser` subcommands translate directly — pass them as argument arrays to
`sandbox.runCommand`:

```ts
// exec_command("agent-browser open https://example.com")  →
await sandbox.runCommand("agent-browser", ["open", "https://example.com"]);

// exec_command("agent-browser snapshot -i")  →
const snap = await sandbox.runCommand("agent-browser", ["snapshot", "-i"]);
const tree = await snap.stdout();

// exec_command("agent-browser screenshot --json")  →
const ss = await sandbox.runCommand("agent-browser", ["screenshot", "--json"]);
const { data: { path } } = JSON.parse(await ss.stdout());
const b64 = await (await sandbox.runCommand("base64", ["-w", "0", path])).stdout();
```

## Full workflow example

```ts
export async function scrapeWithSnapshot(url: string) {
  return withBrowser(async (sandbox) => {
    await sandbox.runCommand("agent-browser", ["open", url]);

    const snapResult = await sandbox.runCommand("agent-browser", ["snapshot", "-i", "-c"]);
    const snapshot = await snapResult.stdout();

    const titleResult = await sandbox.runCommand("agent-browser", ["get", "title", "--json"]);
    const title = JSON.parse(await titleResult.stdout())?.data?.title ?? url;

    await sandbox.runCommand("agent-browser", ["close"]);
    return { title, snapshot };
  });
}
```

## Creating a snapshot (run once, saves ~30s per invocation)

```ts
import { Sandbox } from "@vercel/sandbox";

const sandbox = await Sandbox.create({ runtime: "node24", timeout: 300_000 });
await sandbox.runCommand("sh", ["-c",
  `sudo dnf install -y --skip-broken ${CHROMIUM_DEPS.join(" ")} && sudo ldconfig`]);
await sandbox.runCommand("npm", ["install", "-g", "agent-browser"]);
await sandbox.runCommand("npx", ["agent-browser", "install"]);
const { snapshotId } = await sandbox.snapshot();
console.log("AGENT_BROWSER_SNAPSHOT_ID=" + snapshotId);
await sandbox.stop();
```

## All agent-browser commands work unchanged

The CLI interface is identical to direct invocation — refer to the `tooling/agent_browser`
skill for the full command reference (snapshot, click, fill, wait, tabs, eval, etc.).
The only difference is the transport: `sandbox.runCommand("agent-browser", [...args])` instead
of `exec_command("agent-browser ...")`.
