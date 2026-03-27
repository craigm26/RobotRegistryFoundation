/**
 * POST /v2/harnesses/register
 * RCAN v2.2 §21 — Register an AI harness and receive an RHN.
 *
 * Body: { name, version, harness_type, rcan_version, description?,
 *         model_ids?, compatible_robots?, open_source?, repo_url?,
 *         license?, owner_uid? }
 *
 * Returns: { rhn, registered_at, record_url }
 */

import { nextId, isValidId } from "../_lib/id.js";
import type { HarnessRecord, HarnessType } from "../_lib/types.js";

export interface Env { RRF_KV: KVNamespace }

const VALID_TYPES: HarnessType[] = [
  "vla", "llm_planner", "multimodal", "hybrid",
  "specialist", "safety_monitor", "orchestrator", "other",
];

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: Record<string, unknown>;
  try { body = await request.json() as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  const { name, version, harness_type, rcan_version } = body as Record<string, string>;

  if (!name || !version || !harness_type || !rcan_version) {
    return err("Required: name, version, harness_type, rcan_version", 400);
  }

  if (!VALID_TYPES.includes(harness_type as HarnessType)) {
    return err(`Invalid harness_type. Must be one of: ${VALID_TYPES.join(", ")}`, 400);
  }

  // Validate any model_ids/compatible_robots are well-formed
  const model_ids = body.model_ids as string[] | undefined;
  if (model_ids) {
    for (const rmn of model_ids) {
      if (!isValidId(rmn, "RMN")) {
        return err(`Invalid model_id format: ${rmn} (expected RMN-XXXXXXXXXXXX)`, 400);
      }
    }
  }

  const compatible_robots = body.compatible_robots as string[] | undefined;
  if (compatible_robots) {
    for (const rrn of compatible_robots) {
      if (!isValidId(rrn, "RRN")) {
        return err(`Invalid compatible_robot format: ${rrn} (expected RRN-XXXXXXXXXXXX)`, 400);
      }
    }
  }

  const rhn = await nextId(env.RRF_KV, "RHN");

  const record: HarnessRecord = {
    rhn,
    name,
    version,
    harness_type:      harness_type as HarnessType,
    rcan_version,
    description:       body.description as string | undefined,
    model_ids,
    compatible_robots,
    open_source:       body.open_source === true,
    repo_url:          body.repo_url as string | undefined,
    license:           body.license as string | undefined,
    owner_uid:         body.owner_uid as string | undefined,
    registered_at:     new Date().toISOString(),
  };

  await env.RRF_KV.put(`harness:${rhn}`, JSON.stringify(record), {
    expirationTtl: 365 * 24 * 3600 * 10,
  });

  return ok({ rhn, registered_at: record.registered_at,
    record_url: `https://robot-registry-foundation.pages.dev/v2/harnesses/${rhn}` }, 201);
};

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  const list = await env.RRF_KV.list({ prefix: "harness:", limit: 100 });
  const harnesses = await Promise.all(
    list.keys.map(async (k) => {
      const val = await env.RRF_KV.get(k.name, "text");
      return val ? JSON.parse(val) : null;
    })
  );
  return ok({ harnesses: harnesses.filter(Boolean), total: harnesses.length });
};

function ok(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
function err(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), { status, headers: { "Content-Type": "application/json" } });
}
