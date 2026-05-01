# @rrf/mcp — Robot Registry Foundation MCP server

> **Status: spike (0.1.0-spike).** Read-only tools wrapping the public RRF
> endpoints. Write tools (register, submit signed artifacts, submit Score
> JSONs) are deferred until the apikey-bound trust surface is designed.

Connect Claude — via any of the four Anthropic surfaces — directly to the
Robot Registry Foundation: lookup robots by RRN, list the registry,
fetch the spatial-eval spec metadata + RRF public key, poll counter-signed
spatial-eval submissions, and fetch stored FRIA documents.

## Tools

| Tool | Endpoint | Auth |
|---|---|---|
| `rrf_lookup_robot(rrn)` | `GET /v2/robots/{rrn}` | public |
| `rrf_list_registry(type?, limit?)` | `GET /v2/registry` | public |
| `rrf_fetch_spatial_eval_spec(version)` | `GET /v1/spatial-eval/spec/{version}` | public |
| `rrf_fetch_spatial_eval_run(submission_id)` | `GET /v1/spatial-eval/runs/{id}` | Bearer |
| `rrf_fetch_fria(rrn)` | `GET /v2/robots/{rrn}/fria` | Bearer |

For Bearer-gated tools, pass an apikey via `RRF_API_KEY` env var.

## Quick start

```sh
git clone https://github.com/craigm26/RobotRegistryFoundation
cd RobotRegistryFoundation/mcp
npm install
npm run build
node dist/server.js   # speaks MCP over stdio
```

For local development against `wrangler pages dev`:

```sh
RRF_BASE=http://localhost:8788 node dist/server.js
```

## Connecting from each Anthropic surface

### 1. Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "rrf": {
      "command": "node",
      "args": ["/absolute/path/to/RobotRegistryFoundation/mcp/dist/server.js"],
      "env": { "RRF_API_KEY": "your-bearer-here-if-needed" }
    }
  }
}
```

Restart Claude Desktop. The five `rrf_*` tools appear in the tools menu.

### 2. Claude Code

Use the `claude mcp add` CLI:

```sh
claude mcp add rrf -- node /absolute/path/to/RobotRegistryFoundation/mcp/dist/server.js
```

Or in `.claude/settings.json` per-project:

```json
{
  "mcpServers": {
    "rrf": {
      "type": "stdio",
      "command": "node",
      "args": ["./mcp/dist/server.js"]
    }
  }
}
```

### 3. claude.ai (web — Connectors)

claude.ai supports MCP via the **Custom Connector** flow under Settings →
Connectors. Custom connectors expect HTTP/SSE transports rather than
stdio. Spike v0.1 ships stdio only — graduating to claude.ai requires
adding the `StreamableHTTPServerTransport` from `@modelcontextprotocol/sdk`
and exposing the server behind a public URL.

This is a one-evening follow-up; the tool surface stays identical.

### 4. Claude Agent SDK

Python:

```py
from anthropic.beta.mcp import StdioMCPServer

rrf = StdioMCPServer(
    command="node",
    args=["/abs/path/RobotRegistryFoundation/mcp/dist/server.js"],
    env={"RRF_API_KEY": "..."},  # optional
)
# pass into your Agent's mcp_servers=[rrf]
```

TypeScript:

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "node",
  args: ["/abs/path/RobotRegistryFoundation/mcp/dist/server.js"],
});
const client = new Client({ name: "agent", version: "1.0" }, { capabilities: {} });
await client.connect(transport);
const tools = await client.listTools();
```

## Manual smoke

After `npm run build`, in another terminal:

```sh
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | node dist/server.js
```

Should emit a JSON-RPC response listing the five tools. (For interactive
exercise, use Claude Desktop with the config above and ask: *"What robots
are in the RRF registry?"*)

## Configuration

| Env | Default | Purpose |
|---|---|---|
| `RRF_BASE` | `https://robotregistryfoundation.org` | Base URL — point at `localhost:8788` for `wrangler pages dev`. |
| `RRF_API_KEY` | (unset) | Bearer apikey for `rrf_fetch_spatial_eval_run` and `rrf_fetch_fria`. Public tools work without it. |

## Tests

```sh
npx vitest run --config vitest.config.ts
```

10 tests cover tool definitions, endpoint mapping, Bearer header
propagation, and graceful error envelopes on 404.

## Open questions for graduation

- **Own repo or stay nested?** Currently lives in `mcp/` of the website
  repo. Lower friction during the spike; gets noisy if it grows. Decision
  point: when we add write tools (which need apikey-bound trust + a small
  config UX), promote to `RobotRegistryFoundation/rrf-mcp`.
- **Streamable HTTP transport** for claude.ai Custom Connector support.
- **Caching** for `rrf_fetch_spatial_eval_spec` (pubkey changes only on
  minor version bump — could cache aggressively).
- **Write tools** with apikey-bound auth: register, submit-fria,
  submit-ifu, submit-incident-report, submit-score, etc. Each is a
  parallel of the public-side `robot-md` CLI command.
