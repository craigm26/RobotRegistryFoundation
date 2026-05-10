/**
 * Verify a run-bundle's hybrid (Ed25519 + ML-DSA-65) signature.
 *
 * The gateway (robot-md-gateway) signs:
 *   canonicalJson(body, exclude={"sig"})
 * with a hybrid key pair registered under a RAN.  run_id is included in the
 * signed bytes (the gateway injects run_id before signing).
 *
 * This verifier:
 *   1. Validates body shape (gateway_ran, sig with ml_dsa + ed25519 fields).
 *   2. Resolves body.gateway_ran → AuthorityRecord from KV at authority:{ran}.
 *   3. Checks body.pq_signing_pub matches the registered ML-DSA key (or prior[]).
 *   4. Recomputes canonicalJson(body - sig) — same bytes the gateway signed.
 *   5. Calls rcan-ts.verifyHybrid(ed25519Pub, mlDsaPub, msg, hybridSig) using
 *      trust-anchor keys (from the authority record, not from the body).
 *
 * Policy differences from verify-bundle-hybrid.ts:
 *   - No resolveKidToAuthority: resolved directly by gateway_ran → authority:{ran}.
 *   - No assertAggregatorScopedFor: run-bundle POST is RAN-gated, not scope-gated.
 *   - Status codes: 404 (RAN not found), 403 (key mismatch), 400 (sig invalid).
 */

import { canonicalJson, verifyHybrid, type HybridSignature } from "rcan-ts";

export type VerifyOk = { ok: true; ran: `RAN-${string}` };
export type VerifyError = { ok: false; status: number; error: string };
export type VerifyRunBundleResult = VerifyOk | VerifyError;

interface RunBundleSig {
  ml_dsa: string;     // base64
  ed25519: string;    // base64
  ed25519_pub?: string; // informational; not used for verification
}

function isRunBundleSig(v: unknown): v is RunBundleSig {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  if (typeof o.ml_dsa !== "string") return false;
  if (typeof o.ed25519 !== "string") return false;
  return true;
}

function b64ToBytes(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

export async function verifyRunBundleHybrid(
  env: { RRF_KV: KVNamespace },
  body: Record<string, unknown>,
): Promise<VerifyRunBundleResult> {
  // 1. Validate required fields.
  const gatewayRan = body.gateway_ran;
  if (typeof gatewayRan !== "string" || !/^RAN-\d{12}$/.test(gatewayRan)) {
    return { ok: false, status: 400, error: "gateway_ran missing or invalid format" };
  }
  const sig = body.sig;
  if (!isRunBundleSig(sig)) {
    return { ok: false, status: 400, error: "sig missing or malformed (requires ml_dsa + ed25519)" };
  }
  const bodyPqPub = body.pq_signing_pub;
  if (typeof bodyPqPub !== "string") {
    return { ok: false, status: 400, error: "pq_signing_pub missing" };
  }

  // 2. Resolve gateway_ran → authority record.
  const rawAuth = await env.RRF_KV.get(`authority:${gatewayRan}`, "text");
  if (!rawAuth) {
    return { ok: false, status: 404, error: `gateway_ran ${gatewayRan} not registered` };
  }
  let auth: {
    ran: `RAN-${string}`;
    signing_pub: string;
    pq_signing_pub: string;
    pq_signing_pub_prior?: string[];
    status?: string;
  };
  try {
    auth = JSON.parse(rawAuth);
  } catch {
    return { ok: false, status: 500, error: "authority record corrupt" };
  }

  // 3. Key-match check: body.pq_signing_pub must equal the registered ML-DSA key
  //    (or one of pq_signing_pub_prior[] during key rotation).
  const acceptedPqPubs = [auth.pq_signing_pub];
  if (Array.isArray(auth.pq_signing_pub_prior)) {
    acceptedPqPubs.push(...auth.pq_signing_pub_prior);
  }
  if (!acceptedPqPubs.includes(bodyPqPub)) {
    return { ok: false, status: 403, error: "pq_signing_pub does not match registered key for this RAN" };
  }

  // 4. Recompute canonical bytes: exclude only sig; run_id stays in.
  const { sig: _sig, ...rest } = body;
  void _sig;
  const canonBytes = canonicalJson(rest);

  // 5. Decode key bytes from trust-anchor (authority record), not from body.
  let ed25519Pub: Uint8Array;
  let mlDsaPub: Uint8Array;
  let ed25519Sig: Uint8Array;
  let mlDsaSig: Uint8Array;
  try {
    ed25519Pub = b64ToBytes(auth.signing_pub);
    mlDsaPub = b64ToBytes(auth.pq_signing_pub);
    ed25519Sig = b64ToBytes(sig.ed25519);
    mlDsaSig = b64ToBytes(sig.ml_dsa);
  } catch {
    return { ok: false, status: 400, error: "sig or authority record contains invalid base64" };
  }

  const hybridSig: HybridSignature = {
    profile: "pqc-hybrid-v1",
    ed25519Sig,
    mlDsaSig,
  };

  // verifyHybrid is sync; noble/curves can throw on invalid byte lengths.
  let ok = false;
  try {
    ok = verifyHybrid(ed25519Pub, mlDsaPub, canonBytes, hybridSig);
  } catch {
    ok = false;
  }
  if (!ok) {
    return { ok: false, status: 400, error: "run-bundle hybrid signature did not verify" };
  }

  return { ok: true, ran: auth.ran };
}
