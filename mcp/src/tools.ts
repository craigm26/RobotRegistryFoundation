/**
 * MCP tool definitions wrapping RrfClient methods. One tool per endpoint.
 *
 * Tools are read-only in this spike. Write surfaces (register, submit
 * artifacts, submit scores) need apikey-bound trust which is its own
 * design surface and gets a follow-up.
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { RrfClient, RrfHttpError } from "./client.js";

const RRN_RE = "^RRN-[0-9]{12}$";
const SPEC_VERSION_RE = "^[0-9]+\\.[0-9]+\\.[0-9]+$";
const SUBMISSION_ID_RE = "^sub_[A-Za-z0-9-]+$";

export const TOOL_DEFS: Tool[] = [
  {
    name: "rrf_lookup_robot",
    description:
      "Look up a single robot's registry record by its RRN. Returns the registered RCAN identity, manufacturer, firmware version, registered_at, and verification tier.",
    inputSchema: {
      type: "object",
      properties: {
        rrn: { type: "string", pattern: RRN_RE, description: "RRN-XXXXXXXXXXXX" },
      },
      required: ["rrn"],
    },
  },
  {
    name: "rrf_list_registry",
    description:
      "List entries from the unified registry (robots, components, models, harnesses) — sorted by registration date, newest first. Optional type filter and result limit.",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: ["robot", "component", "model", "harness"],
          description: "Filter to one entity type. Omit for unified listing.",
        },
        limit: { type: "integer", minimum: 1, maximum: 500 },
      },
    },
  },
  {
    name: "rrf_fetch_spatial_eval_spec",
    description:
      "Fetch the canonical spatial-eval spec metadata for a version, including the RRF ML-DSA public key used to verify counter-signatures.",
    inputSchema: {
      type: "object",
      properties: {
        version: {
          type: "string",
          pattern: SPEC_VERSION_RE,
          description: "Semantic version, e.g. 1.0.0",
        },
      },
      required: ["version"],
    },
  },
  {
    name: "rrf_fetch_spatial_eval_run",
    description:
      "Poll a spatial-eval submission by its submission_id. Returns one of {pending, counter_signed, rejected}; counter_signed responses include the RRF-counter-signed Score JSON. Requires a Bearer apikey.",
    inputSchema: {
      type: "object",
      properties: {
        submission_id: {
          type: "string",
          pattern: SUBMISSION_ID_RE,
          description: "RRF-issued sub_<opaque> id from POST /v1/spatial-eval/runs",
        },
      },
      required: ["submission_id"],
    },
  },
  {
    name: "rrf_fetch_fria",
    description:
      "Fetch a robot's stored Fundamental Rights Impact Assessment (RCAN §22). Requires a Bearer apikey.",
    inputSchema: {
      type: "object",
      properties: {
        rrn: { type: "string", pattern: RRN_RE, description: "RRN-XXXXXXXXXXXX" },
      },
      required: ["rrn"],
    },
  },
];

type Args = Record<string, unknown>;

export async function callTool(
  client: RrfClient,
  name: string,
  args: Args,
): Promise<unknown> {
  try {
    switch (name) {
      case "rrf_lookup_robot":
        return await client.lookupRobot(String(args.rrn));
      case "rrf_list_registry":
        return await client.listRegistry(
          args.type ? String(args.type) : undefined,
          typeof args.limit === "number" ? args.limit : undefined,
        );
      case "rrf_fetch_spatial_eval_spec":
        return await client.fetchSpatialEvalSpec(String(args.version));
      case "rrf_fetch_spatial_eval_run":
        return await client.fetchSpatialEvalRun(String(args.submission_id));
      case "rrf_fetch_fria":
        return await client.fetchFria(String(args.rrn));
      default:
        throw new Error(`unknown tool: ${name}`);
    }
  } catch (e) {
    if (e instanceof RrfHttpError) {
      return { error: e.message, status: e.status, url: e.url, body: e.body };
    }
    return { error: (e as Error).message };
  }
}
