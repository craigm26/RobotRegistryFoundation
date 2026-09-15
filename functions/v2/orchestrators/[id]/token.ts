/**
 * GET /v2/orchestrators/:id/token
 * RCAN v2.1 §2.9 — Issue a short-lived M2M_TRUSTED JWT.
 *
 * WHAT IS ENFORCED (and nothing else):
 *   1. Proof of possession of the Ed25519 key already stored on the
 *      orchestrator record (`orchestrator_key`). See _lib/orchestrator-auth.ts:
 *      headers X-RRF-Nonce + X-RRF-Timestamp and
 *      `Authorization: Signature <b64url>` over `${id}:${nonce}:${timestamp}`.
 *      An unknown id and a bad signature both answer 401; the route does not
 *      disclose whether the orchestrator exists.
 *   2. orchestrator.status === "active".
 *   3. RRF_SIGNING_KEY must be bound, or the route answers 503. There is no
 *      unsigned or mock-signed branch: the registry refuses to mint rather
 *      than hand out a token nothing can verify.
 *
 * There is no CREATOR credential anywhere in this registry. Do not document one.
 *
 * Returns: { token (JWT), exp, fleet_rrns }
 * JWT claims: sub, rcan_role='m2m_trusted', rcan_scopes=['fleet.trusted'],
 *             fleet_rrns, iat, exp (iat+86400), iss='rrf.rcan.dev'.
 *
 * On that iss value: it is an opaque issuer identifier, compared for equality
 * and never dereferenced, so it hands nobody a URL. The hostname it spells has
 * no DNS record, and the registry's receipt URLs were moved off that name on
 * 2026-09-14 (see _lib/api-base.ts). iss was deliberately left alone, because
 * verifiers outside this repository assert this exact literal and would reject
 * every token the moment the mint changed. Changing it is a coordinated
 * release across repositories with a transition window, not a rename here.
 * tests/dead-hostname-allowlist.json records the same reasoning.
 * The token is a standard RFC 7515 compact JWS: the third segment is the
 * EdDSA signature over the ASCII bytes of `${segment0}.${segment1}`, so the
 * RRF verifier (_lib/jwt-verify.ts) and any stock EdDSA verifier agree.
 *
 * Re-issuance requires re-validation (not cached).
 */

import { verifyOrchestratorProof } from "../../_lib/orchestrator-auth.js";

export interface Env {
  RRF_KV: KVNamespace;
  RRF_SIGNING_KEY?: string;  // Ed25519 private key (base64 PKCS8 DER) for JWT signing
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env, params } = context;
  const id = params["id"] as string;

  if (request.method !== "GET") {
    return json({ error: "Method not allowed" }, 405);
  }

  // Proof of possession of the registered orchestrator key. This runs before
  // any KV disclosure so an unauthenticated caller cannot probe which
  // orchestrator ids exist.
  const proof = await verifyOrchestratorProof(request, env, id);
  if (!proof.ok) {
    return json({ error: proof.error }, proof.status);
  }
  const record = proof.record;

  if (record.status !== "active") {
    return json({
      error:  `Orchestrator status is '${record.status}' — token only issued for active orchestrators`,
      status: record.status,
    }, 403);
  }

  // Fail closed: no signing key, no token. A token the registry cannot sign is
  // a token nobody can verify.
  if (!env.RRF_SIGNING_KEY) {
    return json({ error: "Token signing is not configured" }, 503);
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + 86400; // 24h max TTL per spec

  // Build JWT payload (exactly as emitted — nothing is added after signing).
  const payload = {
    sub:         id,
    iss:         "rrf.rcan.dev",
    iat:         now,
    exp,
    rcan_role:   "m2m_trusted",
    rcan_scopes: ["fleet.trusted"],
    fleet_rrns:  record.fleet_rrns,
  };

  // Sign the JWT
  const token = await buildSignedJWT(payload, env.RRF_SIGNING_KEY);

  return json({
    ok:         true,
    token,
    exp,
    fleet_rrns: record.fleet_rrns,
    iss:        "rrf.rcan.dev",
    note:       "Token valid for 24h. Re-issue before expiry.",
  });
};

/**
 * Mint an RFC 7515 compact JWS. `signingKey` is REQUIRED: there is no keyless
 * fallback, and callers must have refused the request before reaching here.
 */
export async function buildSignedJWT(
  payload: Record<string, unknown>,
  signingKey: string,
): Promise<string> {
  if (!signingKey) {
    throw new Error("buildSignedJWT: RRF_SIGNING_KEY is required; refusing to mint an unsigned token");
  }

  const header = { alg: "EdDSA", typ: "JWT" };
  const b64url = (s: string) =>
    btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const encode = (obj: unknown) => b64url(JSON.stringify(obj));

  const headerB64 = encode(header);
  const payloadB64 = encode(payload);
  const signingInput = `${headerB64}.${payloadB64}`;

  // Key is stored as base64-encoded PKCS8 DER
  const keyBytes = Uint8Array.from(atob(signingKey), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "pkcs8", keyBytes, { name: "Ed25519" }, false, ["sign"],
  );
  const encoder = new TextEncoder();
  const sigBuffer = await crypto.subtle.sign("Ed25519", key, encoder.encode(signingInput));
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

  return `${signingInput}.${sig}`;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json" },
  });
}
