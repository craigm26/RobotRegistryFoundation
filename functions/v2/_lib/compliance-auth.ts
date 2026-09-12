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

/**
 * Bearer-token gate for reads of a robot's own compliance artifacts.
 *
 * Distinct from verifyComplianceSubmission: submissions carry a detached
 * ML-DSA signature, while a retrieval carries only the api_key minted at
 * registration. This is the same credential and the same order of checks as
 * robots/[rrn]/index.ts (PATCH/DELETE), factored out so the compliance reads
 * cannot drift back into a decorative prefix check.
 *
 * Order matters: 401 when no bearer is presented, 404 when the robot is not
 * registered, 403 when the key on record is revoked, 403 on mismatch. The KV
 * read of the artifact must happen only after this returns ok, so that an
 * invalid credential cannot distinguish a stored artifact from an absent one.
 */
export interface ApiKeyOk { ok: true }
export type ApiKeyResult = ApiKeyOk | VerifyError;

export async function requireRobotApiKey(
  request: Request,
  env: { RRF_KV: KVNamespace },
  rrn: string,
): Promise<ApiKeyResult> {
  const auth = request.headers.get("Authorization");
  const presented = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!presented) return { ok: false, status: 401, error: "Missing bearer token" };

  const raw = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!raw) return { ok: false, status: 404, error: "Not found" };

  if (await isRevoked(env, rrn)) {
    return { ok: false, status: 403, error: "Record is revoked" };
  }

  let record: Record<string, unknown>;
  try {
    record = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { ok: false, status: 500, error: "Corrupt entity record" };
  }

  const stored = record["api_key"];
  if (typeof stored !== "string" || !timingSafeEqual(stored, presented)) {
    return { ok: false, status: 403, error: "Unauthorized" };
  }
  return { ok: true };
}

/** Constant-time string compare. Length is not secret; the bytes are. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
