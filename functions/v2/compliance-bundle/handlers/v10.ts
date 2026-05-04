/**
 * Schema v1.0 handler for /v2/compliance-bundle POST.
 *
 * Flow:
 *   1. Verify hybrid bundle_signature via verifyBundleHybrid (Task 8).
 *   2. Resolve aggregator RAN -> RRN scope via assertAggregatorScopedFor (Task 5).
 *   3. Idempotency: 409 if compliance-bundle:<bundle_id> already in KV.
 *   4. Increment counter:compliance-bundle-log -> N.
 *   5. Compute logged_at + artifact_types, build entry.
 *   6. Sign entry with rrf-log-sign (Task 7).
 *   7. Write counter, log-index key, full payload key (3 KV writes).
 *   8. Return {bundle_id, rrn, transparency_log_index}.
 */

import type { ComplianceBundleEntry } from "../../_lib/types.js";
import { verifyBundleHybrid } from "../../_lib/verify-bundle-hybrid.js";
import { assertAggregatorScopedFor } from "../../_lib/aggregator-scope.js";
import { signLogEntry } from "../../_lib/rrf-log-sign.js";

export interface Env {
  RRF_KV: KVNamespace;
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function handleV10(
  payload: Record<string, unknown>,
  env: Env,
): Promise<Response> {
  const bundleId = payload["bundle_id"];
  const rrn = payload["rrn"];
  if (typeof bundleId !== "string" || !bundleId.startsWith("bundle_")) {
    return json({ error: "bundle_id missing or malformed" }, 400);
  }
  if (typeof rrn !== "string" || !/^RRN-\d{12}$/.test(rrn)) {
    return json({ error: "rrn missing or malformed" }, 400);
  }
  if (typeof payload["robot_md_sha256"] !== "string") {
    return json({ error: "robot_md_sha256 missing or not a string" }, 400);
  }
  if (typeof payload["schema_version"] !== "string") {
    return json({ error: "schema_version missing or not a string" }, 400);
  }
  if (typeof payload["signed_at"] !== "string") {
    return json({ error: "signed_at missing or not a string" }, 400);
  }

  // 1. Verify hybrid bundle_signature.
  const verifyResult = await verifyBundleHybrid(env, payload);
  if (!verifyResult.ok) {
    return json({ error: verifyResult.error }, verifyResult.status);
  }
  const aggregatorRan = verifyResult.ran;

  // 2. Aggregator -> RRN scope.
  const scopeResult = await assertAggregatorScopedFor(env, aggregatorRan, rrn as `RRN-${string}`);
  if (!scopeResult.ok) {
    return json({ error: scopeResult.error }, scopeResult.status);
  }

  // 3. Idempotency.
  const existing = await env.RRF_KV.get(`compliance-bundle:${bundleId}`, "text");
  if (existing) {
    return json({ error: `bundle_id ${bundleId} already exists in transparency log` }, 409);
  }

  // 4. Counter increment. NOTE: get→put races under concurrent POSTs (spec D6
  // accepts this; matches authorities/register.ts pattern).
  const counterStr = await env.RRF_KV.get("counter:compliance-bundle-log", "text");
  const next = (counterStr ? parseInt(counterStr, 10) : 0) + 1;

  // 5. Build the log entry. Defensive: artifacts may be malformed even when
  // the hybrid sig is valid (the verifier checks crypto, not artifact shape).
  const artifactsRaw = payload["artifacts"];
  const artifacts: Array<{ artifact_type?: unknown }> = Array.isArray(artifactsRaw) ? artifactsRaw : [];
  const artifactTypes = Array.from(new Set(
    artifacts.map(a => a.artifact_type).filter((t): t is string => typeof t === "string")
  )).sort();
  const loggedAt = new Date().toISOString();
  const entry: Omit<ComplianceBundleEntry, "rrf_log_signature"> = {
    bundle_id: bundleId,
    rrn: rrn as `RRN-${string}`,
    schema_version: payload["schema_version"] as string,
    signed_at: payload["signed_at"] as string,
    robot_md_sha256: payload["robot_md_sha256"] as string,
    matrix_version: payload["matrix_version"] as string | undefined,
    artifact_types: artifactTypes,
    transparency_log_index: next,
    logged_at: loggedAt,
    bundle_signature: payload["bundle_signature"] as ComplianceBundleEntry["bundle_signature"],
  };

  // 6. Sign the entry.
  const rrfLogSig = await signLogEntry(env, entry);
  const fullEntry: ComplianceBundleEntry = { ...entry, rrf_log_signature: rrfLogSig };

  // 7. Three KV writes — counter FIRST so partial-write failures produce
  // orphaned (wasted-index) records rather than incoherent (lying) records.
  await env.RRF_KV.put("counter:compliance-bundle-log", String(next));
  await env.RRF_KV.put(
    `compliance-bundle-log:${String(next).padStart(12, "0")}`,
    JSON.stringify(fullEntry),
    { expirationTtl: 365 * 24 * 3600 * 10 },
  );
  await env.RRF_KV.put(
    `compliance-bundle:${bundleId}`,
    JSON.stringify({ ...payload, transparency_log_index: next, logged_at: loggedAt, rrf_log_signature: rrfLogSig }),
    { expirationTtl: 365 * 24 * 3600 * 10 },
  );

  return json({ bundle_id: bundleId, rrn, transparency_log_index: next }, 201);
}
