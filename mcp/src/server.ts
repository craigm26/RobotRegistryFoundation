#!/usr/bin/env node
/**
 * @rrf/mcp — MCP server for the Robot Registry Foundation.
 *
 * Spike scope: read-only tools wrapping the public RRF endpoints. stdio
 * transport (the surface Claude Desktop, Claude Code, claude.ai
 * connectors, and the Claude Agent SDK all consume natively).
 *
 * Configurable via env:
 *   RRF_BASE     — base URL (default https://robotregistryfoundation.org)
 *   RRF_API_KEY  — Bearer apikey for the two Bearer-gated tools
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { RrfClient } from "./client.js";
import { TOOL_DEFS, callTool } from "./tools.js";

export function buildServer(client: RrfClient = new RrfClient()): Server {
  const server = new Server(
    { name: "rrf-mcp", version: "0.1.0-spike" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;
    const result = await callTool(client, name, args ?? {});
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  });

  return server;
}

async function main(): Promise<void> {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Stay alive on stdio. Errors from Server propagate up.
}

// Run if invoked directly (not when imported by tests).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("rrf-mcp fatal:", err);
    process.exit(1);
  });
}
