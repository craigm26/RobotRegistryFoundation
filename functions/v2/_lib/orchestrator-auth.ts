/**
 * Proof-of-possession auth for orchestrator routes.
 *
 * The registry already stores an Ed25519 public key on every orchestrator
 * record (`orchestrator_key`, a SPKI PEM supplied at registration). This helper
 * makes the caller prove it holds the matching private key, which is the only
 * credential the registry can actually check. There is no CREATOR token and no
 * issuer for one; do not reintroduce that claim.
 *
 * Wire format (caller side):
 *   X-RRF-Nonce:     base64url, decoding to >= 16 bytes, fresh per request
 *   X-RRF-Timestamp: ISO-8601 UTC, within +/- 300 s of registry time
 *   Authorization:   Signature <b64url(Ed25519 sig)>
 *                    over the UTF-8 bytes of `${id}:${nonce}:${timestamp}`
 *                    where `nonce` and `timestamp` are the header values verbatim
 *
 * Every failure answers 401 with a JSON reason, including "orchestrator id not
 * found": an unauthenticated caller must not be able to probe which ids exist.
 *
 * Replay note: the nonce is required and bound into the signed string, but this
 * helper does not yet keep a seen-nonce set. The 300 s clock window is the
 * replay bound today. A KV-backed nonce cache is the next hardening step.
 */

import { fromB64Url, pemToDer } from "./jwt-verify.js";

export interface OrchestratorRecordShape {
  id: string;
  rrn: string;
  orchestrator_key: string;
  fleet_rrns: string[];
  status: string;
  consents?: Record<string, boolean>;
  [k: string]: unknown;
}

export interface OrchestratorProofOk {
  ok: true;
  record: OrchestratorRecordShape;
}

export interface OrchestratorProofError {
  ok: false;
  status: number;
  error: string;
}

export type OrchestratorProofResult = OrchestratorProofOk | OrchestratorProofError;

/** Uniform failure: never disclose whether the id or the signature was wrong. */
const deny = (error: string): OrchestratorProofError => ({ ok: false, status: 401, error });

/** Max clock skew between the caller's timestamp and registry time, in ms. */
export const PROOF_SKEW_MS = 300_000;

export async function verifyOrchestratorProof(
  request: Request,
  env: { RRF_KV: KVNamespace },
  id: string,
): Promise<OrchestratorProofResult> {
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Signature ")) {
    return deny("Authorization: Signature <b64url> over `id:nonce:timestamp` required");
  }
  const sigB64 = authHeader.slice("Signature ".length).trim();
  if (!sigB64) {
    return deny("Authorization: Signature <b64url> over `id:nonce:timestamp` required");
  }

  const nonce = request.headers.get("X-RRF-Nonce") ?? "";
  if (!nonce) {
    return deny("X-RRF-Nonce header required");
  }
  let nonceBytes: Uint8Array;
  try {
    nonceBytes = fromB64Url(nonce);
  } catch {
    return deny("X-RRF-Nonce must be base64url");
  }
  if (nonceBytes.length < 16) {
    return deny("X-RRF-Nonce must decode to at least 16 bytes");
  }

  const timestamp = request.headers.get("X-RRF-Timestamp") ?? "";
  if (!timestamp) {
    return deny("X-RRF-Timestamp header required");
  }
  const ts = Date.parse(timestamp);
  if (Number.isNaN(ts)) {
    return deny("X-RRF-Timestamp must be ISO-8601");
  }
  if (Math.abs(Date.now() - ts) > PROOF_SKEW_MS) {
    return deny("X-RRF-Timestamp outside the 300 s window");
  }

  const stored = await env.RRF_KV.get(`orchestrator:${id}`, "text");
  if (!stored) {
    // Deliberately 401, not 404: the pre-fix route leaked orchestrator
    // existence to any caller holding a junk bearer string.
    return deny("Orchestrator proof rejected");
  }

  let record: OrchestratorRecordShape;
  try {
    record = JSON.parse(stored) as OrchestratorRecordShape;
  } catch {
    return { ok: false, status: 500, error: "Corrupt orchestrator record" };
  }

  if (typeof record.orchestrator_key !== "string" || !record.orchestrator_key) {
    return deny("Orchestrator has no registered key");
  }

  const signingInput = `${id}:${nonce}:${timestamp}`;
  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      pemToDer(record.orchestrator_key),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      fromB64Url(sigB64),
      new TextEncoder().encode(signingInput),
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    return deny("Orchestrator proof rejected");
  }

  return { ok: true, record };
}
