/**
 * GET  /v2/compatibility-matrix → returns the latest signed daily matrix envelope from KV.
 * POST /v2/compatibility-matrix → verifies aggregator hybrid signature, stores in KV.
 *
 * Storage model: opencastor-ops cron POSTs after signing; RRF stores in KV. Each successful
 * push writes both `compatibility-matrix:latest` and `compatibility-matrix:<YYYY-MM-DD>`
 * (date from envelope.signed_at).
 *
 * Auth (POST): signature gate only.
 *   - envelope.ran must resolve to an active authority via `authority:${ran}` (single KV get).
 *   - authority.purpose must be "compatibility-matrix-aggregate".
 *   - authority.status must be "active".
 *   - envelope.pq_kid must equal authority.pq_kid.
 *   - signature_mldsa65 MUST verify (verifyMlDsa from rcan-ts).
 *   - If signature_ed25519 present, it MUST also verify (Web Crypto Ed25519).
 *
 * Conforms to rcan-spec /schemas/version-tuple-envelope.json. Per RCAN v3.2 Decision 3
 * (pqc-hybrid-v1, PQ-required-classical-optional): ML-DSA-65 is required, Ed25519 is
 * optional but verified when present.
 */

import type { AuthorityRecord, VersionTupleEnvelope } from "../_lib/types.js";
import { verifyMlDsa } from "rcan-ts";

export interface Env {
  RRF_KV: KVNamespace;
}

const AGGREGATOR_PURPOSE = "compatibility-matrix-aggregate";
const KV_LATEST = "compatibility-matrix:latest";

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}

function fromB64(s: string): Uint8Array {
  // Standard base64 (NOT base64url) per envelope schema contentEncoding.
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function isValidEnvelope(x: unknown): x is VersionTupleEnvelope {
  if (!x || typeof x !== "object") return false;
  const e = x as Record<string, unknown>;
  if (typeof e.ran !== "string" || !/^RAN-\d{12}$/.test(e.ran)) return false;
  if (!Array.isArray(e.alg) || e.alg.length < 1 || e.alg[0] !== "ML-DSA-65") return false;
  if (e.alg.length === 2 && e.alg[1] !== "Ed25519") return false;
  if (e.alg.length > 2) return false;
  if (typeof e.pq_kid !== "string" || !/^[0-9a-f]{8,}$/.test(e.pq_kid)) return false;
  if (typeof e.payload !== "string") return false;
  if (typeof e.signature_mldsa65 !== "string") return false;
  if (typeof e.signed_at !== "string") return false;
  // dependentRequired: signature_ed25519 → kid
  if (e.signature_ed25519 !== undefined) {
    if (typeof e.signature_ed25519 !== "string") return false;
    if (typeof e.kid !== "string" || !/^[0-9a-f]{8,}$/.test(e.kid)) return false;
  } else if (e.kid !== undefined && (typeof e.kid !== "string" || !/^[0-9a-f]{8,}$/.test(e.kid))) {
    // If kid is present without ed25519, it must still be a valid hex string;
    // we don't reject — schema allows kid alone — but we validate the type.
    return false;
  }
  return true;
}

/**
 * Real signature-verification implementation. Test seam wraps this so that
 * tests can override without statically imported handlers re-binding the
 * production function.
 */
async function realVerifyEnvelope(
  envelope: VersionTupleEnvelope,
  authority: AuthorityRecord,
): Promise<boolean> {
  const msg = fromB64(envelope.payload);
  const pqPub = fromB64(authority.pq_signing_pub);
  const pqSig = fromB64(envelope.signature_mldsa65);

  // ML-DSA-65 always required.
  if (!verifyMlDsa(pqPub, msg, pqSig)) return false;

  // Ed25519 conditional.
  if (envelope.signature_ed25519) {
    try {
      const edPub = fromB64(authority.signing_pub);
      const edSig = fromB64(envelope.signature_ed25519);
      // Web Crypto Ed25519 (Cloudflare Workers, since 2023; Node 22+).
      const key = await crypto.subtle.importKey("raw", edPub, { name: "Ed25519" }, false, ["verify"]);
      const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, edSig, msg);
      if (!ok) return false;
    } catch {
      return false;
    }
  }

  return true;
}

// Module-level mutable seam — tests swap this without trying to re-mock the
// statically imported `onRequestPost` (which would have already captured the
// original reference via lexical scope).
const __impl: {
  verifyEnvelope: (
    envelope: VersionTupleEnvelope,
    authority: AuthorityRecord,
  ) => Promise<boolean>;
} = {
  verifyEnvelope: realVerifyEnvelope,
};

/** Test-only: replace the verifyEnvelope implementation. */
export function __setVerifyEnvelopeForTests(
  fn: (envelope: VersionTupleEnvelope, authority: AuthorityRecord) => Promise<boolean>,
): void {
  __impl.verifyEnvelope = fn;
}

/** Test-only: restore the production verifyEnvelope. */
export function __resetVerifyEnvelopeForTests(): void {
  __impl.verifyEnvelope = realVerifyEnvelope;
}

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  const raw = await env.RRF_KV.get(KV_LATEST, "text");
  if (!raw) return json({ error: "no matrix available yet — check back after first daily aggregator run" }, 503);
  return new Response(raw, { status: 200, headers: { "Content-Type": "application/json" } });
};

export const onRequestPost: PagesFunction<Env> = async ({ env, request }) => {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  if (!isValidEnvelope(body)) {
    return json({ error: "envelope shape invalid (see /schemas/version-tuple-envelope.json)" }, 400);
  }
  const envelope = body as VersionTupleEnvelope;

  // Direct authority lookup (no scan).
  const raw = await env.RRF_KV.get(`authority:${envelope.ran}`, "text");
  if (!raw) return json({ error: `RAN ${envelope.ran} not found` }, 401);
  const authority = JSON.parse(raw) as AuthorityRecord;

  if (authority.status !== "active") {
    return json({ error: `authority ${envelope.ran} status is "${authority.status}"` }, 401);
  }
  if (authority.purpose !== AGGREGATOR_PURPOSE) {
    return json({ error: `authority purpose is "${authority.purpose}", not "${AGGREGATOR_PURPOSE}"` }, 401);
  }
  if (envelope.pq_kid !== authority.pq_kid) {
    return json({ error: "pq_kid does not match registered authority" }, 401);
  }

  // Signature verification (via the test-overridable seam).
  const verified = await __impl.verifyEnvelope(envelope, authority);
  if (!verified) return json({ error: "envelope signature verification failed" }, 401);

  // Storage: latest + dated.
  const date = envelope.signed_at.slice(0, 10);
  const stored = JSON.stringify(envelope);
  await env.RRF_KV.put(KV_LATEST, stored);
  await env.RRF_KV.put(`compatibility-matrix:${date}`, stored, { expirationTtl: 365 * 24 * 3600 });

  return json({ stored: true, ran: envelope.ran, pq_kid: envelope.pq_kid, date }, 201);
};
