/**
 * Shared auth helper for RCAN §22-26 compliance intake endpoints.
 *
 * Loads the entity (robot or model) record from KV, extracts the registered
 * ML-DSA-65 public key (`pq_signing_pub`), and calls `verifyBody` from rcan-ts
 * against the signed compliance document.
 *
 * On success, returns the document stripped of `sig` + `pq_kid` + `pq_signing_pub`
 * (envelope fields), ready for schema and rrn/rmn validation by the caller.
 */

import { verifyBody } from "rcan-ts";
import { isRevoked } from "./revocation.js";

export interface VerifiedSubmission {
  ok: true;
  document: Record<string, unknown>;
}

export interface VerifyError {
  ok: false;
  status: number;
  error: string;
}

export type VerifyResult = VerifiedSubmission | VerifyError;

export async function verifyComplianceSubmission(
  request: Request,
  env: { RRF_KV: KVNamespace },
  entityKey: string,
): Promise<VerifyResult> {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return { ok: false, status: 400, error: "Invalid JSON body" };
  }
  return verifyComplianceBody(body, env, entityKey);
}

/**
 * Same as verifyComplianceSubmission but accepts a pre-parsed body. Use when the
 * caller needs to inspect the body before picking the entity key (e.g. to derive
 * the submitter RRN from a signed field instead of a client-supplied header).
 */
export async function verifyComplianceBody(
  body: Record<string, unknown>,
  env: { RRF_KV: KVNamespace },
  entityKey: string,
): Promise<VerifyResult> {
  const sig = body["sig"] as Record<string, unknown> | undefined;
  const pq_kid = body["pq_kid"];
  if (!sig || typeof pq_kid !== "string"
      || typeof sig["ml_dsa"] !== "string"
      || typeof sig["ed25519"] !== "string"
      || typeof sig["ed25519_pub"] !== "string") {
    return { ok: false, status: 400, error: "Missing signature fields" };
  }

  const stored = await env.RRF_KV.get(entityKey, "text");
  if (!stored) return { ok: false, status: 401, error: "Robot not registered" };

  const rrnMatch = entityKey.match(/^robot:(RRN-\d{12})$/);
  if (rrnMatch && await isRevoked(env, rrnMatch[1])) {
    return { ok: false, status: 403, error: "Entity key is revoked" };
  }

  let record: Record<string, unknown>;
  try {
    record = JSON.parse(stored) as Record<string, unknown>;
  } catch {
    return { ok: false, status: 500, error: "Corrupt entity record" };
  }

  const pqPubB64 = record["pq_signing_pub"];
  if (typeof pqPubB64 !== "string") {
    return { ok: false, status: 401, error: "Entity has no registered PQ key" };
  }

  let verified = false;
  try {
    const pqPub = Uint8Array.from(atob(pqPubB64), (c) => c.charCodeAt(0));
    verified = await verifyBody(body, pqPub);
  } catch {
    verified = false;
  }
  if (!verified) {
    return { ok: false, status: 401, error: "Signature verification failed" };
  }

  const document: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) {
    if (k !== "sig" && k !== "pq_kid" && k !== "pq_signing_pub") document[k] = v;
  }
  return { ok: true, document };
}
