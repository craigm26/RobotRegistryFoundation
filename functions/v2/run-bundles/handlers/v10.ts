/**
 * Schema v1.0 handler for /v2/run-bundles POST.
 *
 * Flow (per spec §5):
 *   1+2. Required-field presence check (14 fields).
 *   3.   run_id format validation.
 *   4.   Recompute run_id; 400 if mismatch.
 *   5-7. Hybrid sig verify via verifyRunBundleHybrid (RAN lookup + key match + sig check).
 *   8.   Advisory rrn/rpn soft-checks (no-op: crypto-verified by gateway).
 *   9.   Idempotency: 409 if run-bundle:{run_id} already in KV.
 *   10.  Counter increment (GET counter:run-bundle-log → +1).
 *   11.  Build transparency-log entry.
 *   12.  Sign entry with rrf-log-sign.
 *   13.  KV writes (counter FIRST per spec §5.1):
 *          counter:run-bundle-log
 *          run-bundle-log:{padded12}
 *          run-bundle:{run_id}  (wrapper: {record, transparency_log_index, logged_at, rrf_log_signature})
 *          run-bundles-by-gateway-ran:{gatewayRan}  (always)
 *          run-bundles-by-rrn:{rrn}  (if rrn matches RRN-\d{12})
 *          run-bundles-by-rpn:{rpn}  (if rpn matches RPN-\d{12})
 *   14.  Return 201 {run_id, transparency_log_index, logged_at}.
 */

import { computeRunId } from "../../_lib/canonical-run-id.js";
import { verifyRunBundleHybrid } from "../../_lib/verify-run-bundle-hybrid.js";
import { signLogEntry } from "../../_lib/rrf-log-sign.js";

export interface Env {
  RRF_KV: KVNamespace;
}

const REQUIRED_FIELDS = [
  "schema_version", "run_id", "gateway_ran",
  "started_at", "finished_at", "outcome_kind", "outcome_detail",
  "skill_manifest_sha256", "actuator_name", "tier",
  "pq_signing_pub", "pq_kid", "ed25519_pub", "sig",
] as const;

const RUN_ID_RE = /^runbundle_[0-9a-f]{12}$/;

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function handleV10(
  body: Record<string, unknown>,
  env: Env,
): Promise<Response> {
  // 1+2. Required-field presence check.
  for (const k of REQUIRED_FIELDS) {
    if (!(k in body)) {
      return json({ error: `Required field missing: ${k}` }, 400);
    }
  }

  // 3. run_id format validation.
  const runId = body.run_id;
  if (typeof runId !== "string" || !RUN_ID_RE.test(runId)) {
    return json({ error: "run_id missing or malformed (expected runbundle_<12hex>)" }, 400);
  }

  // 4. Recompute run_id and confirm match (content-addressable ID).
  const expectedRunId = await computeRunId(body);
  if (runId !== expectedRunId) {
    return json({ error: `run_id mismatch: body claims ${runId}, content hashes to ${expectedRunId}` }, 400);
  }

  // 5-7. Resolve RAN, key match, hybrid sig verify (composite helper).
  const verifyResult = await verifyRunBundleHybrid(env, body);
  if (!verifyResult.ok) {
    return json({ error: verifyResult.error }, verifyResult.status);
  }
  const gatewayRan = verifyResult.ran;

  // 8. Advisory rrn/rpn soft-checks (logged by gateway; no-op here).

  // 9. Idempotency: reject duplicate run_id.
  const existing = await env.RRF_KV.get(`run-bundle:${runId}`, "text");
  if (existing) {
    return json({ error: `run_id ${runId} already exists in transparency log` }, 409);
  }

  // 10. Counter increment. NOTE: get→put races under concurrent POSTs (spec D6
  //     accepts this; orphaned indices are preferable to incoherent records).
  const counterStr = await env.RRF_KV.get("counter:run-bundle-log", "text");
  const next = (counterStr ? parseInt(counterStr, 10) : 0) + 1;

  // 11. Build the transparency-log entry.
  const loggedAt = new Date().toISOString();
  const entry = {
    run_id: runId,
    gateway_ran: gatewayRan,
    rrn: body.rrn,
    rpn: body.rpn,
    schema_version: body.schema_version,
    started_at: body.started_at,
    finished_at: body.finished_at,
    outcome_kind: body.outcome_kind,
    actuator_name: body.actuator_name,
    skill_manifest_sha256: body.skill_manifest_sha256,
    tier: body.tier,
    transparency_log_index: next,
    logged_at: loggedAt,
  };

  // 12. Sign the entry.
  const rrfLogSig = await signLogEntry(env, entry);

  // 13. KV writes — counter FIRST so partial-write failures produce orphaned
  //     (wasted-index) records rather than incoherent (lying) records.
  await env.RRF_KV.put("counter:run-bundle-log", String(next));
  await env.RRF_KV.put(
    `run-bundle-log:${String(next).padStart(12, "0")}`,
    JSON.stringify({ ...entry, rrf_log_signature: rrfLogSig }),
    { expirationTtl: 365 * 24 * 3600 * 10 },
  );
  // Wrapper shape: record is the original body (sig intact, no log fields appended).
  await env.RRF_KV.put(
    `run-bundle:${runId}`,
    JSON.stringify({
      record: body,
      transparency_log_index: next,
      logged_at: loggedAt,
      rrf_log_signature: rrfLogSig,
    }),
    { expirationTtl: 365 * 24 * 3600 * 10 },
  );

  // Always-on back-ref: by-gateway-ran.
  await appendBackRef(env, `run-bundles-by-gateway-ran:${gatewayRan}`, runId);

  // Conditional back-refs: by-rrn (only if rrn present and well-formed).
  if (typeof body.rrn === "string" && /^RRN-\d{12}$/.test(body.rrn)) {
    await appendBackRef(env, `run-bundles-by-rrn:${body.rrn}`, runId);
  }

  // Conditional back-refs: by-rpn (only if rpn present and well-formed).
  if (typeof body.rpn === "string" && /^RPN-\d{12}$/.test(body.rpn)) {
    await appendBackRef(env, `run-bundles-by-rpn:${body.rpn}`, runId);
  }

  // 14. Return 201.
  return json({ run_id: runId, transparency_log_index: next, logged_at: loggedAt }, 201);
}

async function appendBackRef(env: Env, key: string, runId: string): Promise<void> {
  const existing = await env.RRF_KV.get(key, "text");
  const newValue = existing ? `${existing}\n${runId}` : runId;
  await env.RRF_KV.put(key, newValue);
}
