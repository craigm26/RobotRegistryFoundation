/**
 * POST /v2/harnesses/register
 * RCAN 3.0 §21 + §2.2 — Register an AI harness, receive an RHN.
 *
 * v1.9.0: unsigned registration is rejected per RCAN 3.0 §2.2. Body MUST
 * include pq_signing_pub, pq_kid, and sig{ml_dsa, ed25519, ed25519_pub}
 * over the canonical signed-fields block (all provided fields except sig).
 *
 * Body: { name, version, harness_type, rcan_version, description?,
 *         model_ids?, compatible_robots?, open_source?, repo_url?,
 *         license?, owner_uid?, pq_signing_pub, pq_kid, sig }
 *
 * Returns: { rhn, registered_at, record_url }
 */

import { nextId, isValidId } from "../_lib/id.js";
import type { HarnessRecord, HarnessType } from "../_lib/types.js";
import { verifyBody } from "rcan-ts";

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

  // v1.9.0: RCAN 3.0 §2.2 — signatures mandatory, unsigned rejected.
  const { pq_signing_pub, pq_kid, sig } = body as Record<string, any>;
  if (!pq_signing_pub || !pq_kid
      || !sig?.ml_dsa || !sig?.ed25519 || !sig?.ed25519_pub) {
    return err("Unsigned registration not permitted (RCAN 3.0 §2.2)", 400);
  }

  const signedFields: Record<string, unknown> = {
    name, version, harness_type, rcan_version,
    pq_signing_pub, pq_kid,
  };
  if (body.description)       signedFields.description       = body.description;
  if (model_ids)              signedFields.model_ids         = model_ids;
  if (compatible_robots)      signedFields.compatible_robots = compatible_robots;
  if (body.open_source !== undefined) signedFields.open_source = body.open_source;
  if (body.repo_url)          signedFields.repo_url          = body.repo_url;
  if (body.license)           signedFields.license           = body.license;
  if (body.owner_uid)         signedFields.owner_uid         = body.owner_uid;

  let verified = false;
  try {
    const pqPub = Uint8Array.from(atob(pq_signing_pub), c => c.charCodeAt(0));
    verified = await verifyBody({ ...signedFields, sig }, pqPub);
  } catch { /* verified stays false */ }
  if (!verified) return err("Signature verification failed", 400);

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
    pq_signing_pub,
    pq_kid,
    registered_at:     new Date().toISOString(),
  };

  await env.RRF_KV.put(`harness:${rhn}`, JSON.stringify(record), {
    expirationTtl: 365 * 24 * 3600 * 10,
  });

  return ok({ rhn, registered_at: record.registered_at,
    record_url: `https://robotregistryfoundation.org/v2/harnesses/${rhn}` }, 201);
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
