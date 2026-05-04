/**
 * Verify a compliance bundle's hybrid (Ed25519 + ML-DSA-65) signature.
 *
 * The aggregator (opencastor-ops monitor/compliance_bundle.py) signs:
 *   data = canonical_json(payload, exclude="bundle_signature")
 * with a `_Signer` that produces:
 *   bundle_signature = {
 *     kid: <string>,
 *     alg: ["Ed25519", "ML-DSA-65"],
 *     sig: { ed25519: <b64>, ml_dsa: <b64>, ed25519_pub: <b64-informational> },
 *   }
 *
 * This verifier:
 *   1. Validates bundle_signature shape + signed_at is a string.
 *   2. Resolves bundle_signature.kid → AuthorityForVerify via KV (kid + window).
 *   3. Recomputes canonicalJson(payload - bundle_signature) — the SAME bytes
 *      the aggregator signed.
 *   4. Calls rcan-ts.verifyHybrid(ed25519Pub, mlDsaPub, msg, sig) where:
 *      - ed25519Pub is sourced from authority.signing_pub (TRUST ANCHOR)
 *        not from bundle_signature.sig.ed25519_pub (informational; could lie).
 *      - mlDsaPub is sourced from authority.pq_signing_pub.
 *
 * SPEC DEVIATION (controller-authorized 2026-05-04, second instance after
 * Task 6): the plan body's Step 3 proposed reshaping
 *   { bundle_signature → sig, kid → pq_kid }
 * and calling rcan-ts.verifyBody. That cannot work because:
 *   1. verifyBody requires signed["pq_signing_pub"] string field — the
 *      reshape adds pq_kid and sig but NOT pq_signing_pub, so verifyBody
 *      returns false at the field-presence check.
 *   2. verifyBody internally computes canonicalJson(signed - sig), which
 *      includes the added pq_kid + (missing) pq_signing_pub. Those bytes
 *      will NOT match canonical_json(payload, exclude="bundle_signature")
 *      that the aggregator actually signed.
 *
 * Therefore we use verifyHybrid directly — the right primitive — so that
 * sign and verify operate on the SAME canonical bytes.
 */

import { canonicalJson, verifyHybrid, type HybridSignature } from "rcan-ts";
import { resolveKidToAuthority } from "./kid-resolve.js";

export type VerifyOk = { ok: true; ran: `RAN-${string}` };
export type VerifyError = { ok: false; status: number; error: string };
export type VerifyHybridResult = VerifyOk | VerifyError;

interface BundleSignature {
  kid: string;
  alg: string[];
  sig: {
    ed25519: string;
    ml_dsa: string;
    ed25519_pub: string;
  };
}

function isBundleSignature(v: unknown): v is BundleSignature {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  if (typeof o.kid !== "string") return false;
  if (!Array.isArray(o.alg)) return false;
  if (!o.sig || typeof o.sig !== "object") return false;
  const s = o.sig as Record<string, unknown>;
  if (typeof s.ed25519 !== "string") return false;
  if (typeof s.ml_dsa !== "string") return false;
  if (typeof s.ed25519_pub !== "string") return false;
  return true;
}

function b64ToBytes(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

export async function verifyBundleHybrid(
  env: { RRF_KV: KVNamespace },
  payload: Record<string, unknown>,
): Promise<VerifyHybridResult> {
  const bsig = payload.bundle_signature;
  if (!isBundleSignature(bsig)) {
    return { ok: false, status: 400, error: "bundle_signature missing or malformed" };
  }
  const signedAt = payload.signed_at;
  if (typeof signedAt !== "string") {
    return { ok: false, status: 400, error: "signed_at must be an ISO-8601 string" };
  }

  const auth = await resolveKidToAuthority(env, bsig.kid, signedAt);
  if (!auth) {
    return {
      ok: false,
      status: 403,
      error: "kid not registered or signed_at outside validity window",
    };
  }

  // Recompute the bytes the aggregator signed: canonical_json(payload - bundle_signature).
  // Destructure to drop the field; canonicalJson the rest.
  const { bundle_signature: _bsig, ...rest } = payload;
  void _bsig;
  const canonBytes = canonicalJson(rest);

  let ed25519Sig: Uint8Array;
  let mlDsaSig: Uint8Array;
  let ed25519Pub: Uint8Array;
  let mlDsaPub: Uint8Array;
  try {
    ed25519Sig = b64ToBytes(bsig.sig.ed25519);
    mlDsaSig = b64ToBytes(bsig.sig.ml_dsa);
    ed25519Pub = b64ToBytes(auth.signing_pub);
    mlDsaPub = b64ToBytes(auth.pq_signing_pub);
  } catch {
    return { ok: false, status: 400, error: "bundle_signature contains invalid base64" };
  }

  const sig: HybridSignature = {
    profile: "pqc-hybrid-v1",
    ed25519Sig,
    mlDsaSig,
  };

  // verifyHybrid is sync; noble/curves can throw on invalid byte lengths.
  let ok = false;
  try {
    ok = verifyHybrid(ed25519Pub, mlDsaPub, canonBytes, sig);
  } catch {
    ok = false;
  }
  if (!ok) {
    return { ok: false, status: 403, error: "bundle hybrid signature did not verify" };
  }
  return { ok: true, ran: auth.ran };
}
