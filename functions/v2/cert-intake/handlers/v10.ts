/**
 * Schema v1.0 handler for /v2/cert-intake POST.
 *
 * Flow:
 *   1. Validate required fields (property_id, ran_at, iterations, all_pass).
 *   2. Verify rig + witness sigs via verifyHilEvidence (Task 4).
 *   3. Derive cert_id = "cert_" + sha256(canonical_json(body - {rig_signature, witness_signature}))[:32].
 *   4. Idempotency check (cert-intake:<cert_id>).
 *   5. Counter increment (counter:cert-log).
 *   6. Build CertIntakeEntry with rrn from rig record.
 *   7. RRF-root sign via signLogEntry (Plan 4 _lib/rrf-log-sign.ts).
 *   8. KV writes in counter -> log-index -> payload order (partial-write coherence).
 *   9. Return 201 JSON.
 *
 * Augments stored payload with server-resolved rrn so GET-by-id can JWT-scope-check
 * without re-doing kid resolution.
 */

import { canonicalJson } from "rcan-ts";
import type { CertIntakeEntry } from "../../_lib/types.js";
import { verifyHilEvidence } from "../../_lib/verify-hil-evidence.js";
import { signLogEntry } from "../../_lib/rrf-log-sign.js";

export interface Env { RRF_KV: KVNamespace }

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function deriveCertId(payload: Record<string, unknown>): Promise<string> {
  const core: Record<string, unknown> = { ...payload };
  delete core["rig_signature"];
  delete core["witness_signature"];
  const bytes = new TextEncoder().encode(canonicalJson(core));
  const hash = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `cert_${hex.slice(0, 32)}`;
}

function pad12(n: number): string { return String(n).padStart(12, "0"); }

export async function handleV10(payload: Record<string, unknown>, env: Env): Promise<Response> {
  const propertyId = payload["property_id"];
  if (typeof propertyId !== "string" || propertyId.length === 0) {
    return json({ error: "property_id missing or not a string" }, 400);
  }
  if (typeof payload["schema_version"] !== "string") {
    return json({ error: "schema_version missing or not a string" }, 400);
  }
  if (typeof payload["ran_at"] !== "number") {
    return json({ error: "ran_at missing or not a number" }, 400);
  }
  if (typeof payload["iterations"] !== "number") {
    return json({ error: "iterations missing or not a number" }, 400);
  }
  if (typeof payload["all_pass"] !== "boolean") {
    return json({ error: "all_pass missing or not a boolean" }, 400);
  }

  const verifyResult = await verifyHilEvidence(env, payload);
  if (!verifyResult.ok) {
    return json({ error: verifyResult.error }, verifyResult.status);
  }

  const certId = await deriveCertId(payload);

  const existing = await env.RRF_KV.get(`cert-intake:${certId}`, "text");
  if (existing) {
    return json({ error: `cert_id ${certId} already exists in transparency log`, cert_id: certId }, 409);
  }

  // Counter increment. NOTE: get→put races under concurrent POSTs (Plan 4 spec D6
  // posture accepted this; matches compliance-bundle/handlers/v10.ts pattern).
  const counterStr = await env.RRF_KV.get("counter:cert-log", "text");
  const next = (counterStr ? parseInt(counterStr, 10) : 0) + 1;

  const loggedAt = new Date().toISOString();
  const rigSig = payload["rig_signature"] as CertIntakeEntry["rig_signature"];
  const witnessSig = payload["witness_signature"] as CertIntakeEntry["witness_signature"];
  const entry: Omit<CertIntakeEntry, "rrf_log_signature"> = {
    cert_id: certId,
    rrn: verifyResult.rig.rrn,
    property_id: propertyId,
    schema_version: payload["schema_version"] as string,
    rig_id: verifyResult.rig.rig_id,
    ran_at: payload["ran_at"] as number,
    all_pass: payload["all_pass"] as boolean,
    iterations: payload["iterations"] as number,
    transparency_log_index: next,
    logged_at: loggedAt,
    rig_signature: rigSig,
    witness_signature: witnessSig,
  };

  const rrfLogSig = await signLogEntry(env, entry);
  const fullEntry: CertIntakeEntry = { ...entry, rrf_log_signature: rrfLogSig };

  // Counter -> log-index -> payload order (Plan 4 partial-write coherence).
  // Payload is augmented with the server-resolved rrn so GET-by-id can
  // JWT-scope-check without re-doing the kid resolution.
  const storedPayload = { ...payload, rrn: verifyResult.rig.rrn };
  await env.RRF_KV.put("counter:cert-log", String(next));
  await env.RRF_KV.put(`cert-intake-log:${pad12(next)}`, JSON.stringify(fullEntry), { expirationTtl: 365 * 24 * 3600 * 10 });
  await env.RRF_KV.put(`cert-intake:${certId}`, JSON.stringify(storedPayload), { expirationTtl: 365 * 24 * 3600 * 10 });

  return json({
    cert_id: certId,
    rrn: verifyResult.rig.rrn,
    transparency_log_index: next,
    logged_at: loggedAt,
    proof_url: `/v2/cert-intake/${certId}/proof`,
  }, 201);
}
