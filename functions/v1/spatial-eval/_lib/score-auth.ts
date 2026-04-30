/**
 * Verify the robot's `rcan_signature` on a submitted spatial-eval Score JSON.
 *
 * §27 doesn't use the rcan-ts hybrid envelope (sig.ml_dsa + ed25519) that
 * §22-26 use via verifyComplianceSubmission. Score JSON has a single
 * `rcan_signature` field — base64(ML-DSA-65(payloadBytes(score))) — produced
 * by `robot_md.spatial_eval.sign.sign_score`. We mirror that here.
 *
 * KV lookup: `robot:{rrn}` (same key §22-26 use to fetch pq_signing_pub).
 */

import { verifyMlDsa } from "rcan-ts";
import { isRevoked } from "../../../v2/_lib/revocation.js";
import { payloadBytes } from "./score-canonical.js";

export interface VerifiedScore {
  ok: true;
  score: Record<string, unknown>;
}

export interface VerifyError {
  ok: false;
  status: number;
  error: string;
}

export type VerifyResult = VerifiedScore | VerifyError;

const RRN_RE = /^RRN-\d{12}$/;

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function verifyRobotScoreSignature(
  score: Record<string, unknown>,
  env: { RRF_KV: KVNamespace },
): Promise<VerifyResult> {
  const rrn = score["rrn"];
  if (typeof rrn !== "string" || !RRN_RE.test(rrn)) {
    return { ok: false, status: 400, error: "Score missing or malformed rrn" };
  }

  const sigB64 = score["rcan_signature"];
  if (typeof sigB64 !== "string" || sigB64.length === 0) {
    return { ok: false, status: 400, error: "Score missing rcan_signature" };
  }

  if (await isRevoked(env, rrn)) {
    return { ok: false, status: 403, error: "Robot key is revoked" };
  }

  const stored = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!stored) {
    return { ok: false, status: 401, error: "Robot not registered" };
  }

  let record: Record<string, unknown>;
  try {
    record = JSON.parse(stored) as Record<string, unknown>;
  } catch {
    return { ok: false, status: 500, error: "Corrupt entity record" };
  }

  const pqPubB64 = record["pq_signing_pub"];
  if (typeof pqPubB64 !== "string") {
    return { ok: false, status: 401, error: "Robot has no registered PQ key" };
  }

  let verified = false;
  try {
    const pqPub = fromBase64(pqPubB64);
    const sigBytes = fromBase64(sigB64);
    verified = verifyMlDsa(pqPub, payloadBytes(score), sigBytes);
  } catch {
    verified = false;
  }
  if (!verified) {
    return { ok: false, status: 422, error: "rcan_signature failed verification" };
  }

  return { ok: true, score };
}
