/**
 * Verify a Bearer M2M_TRUSTED JWT for a given RRN scope.
 *
 * NOTE: rcan-ts.verifyM2mTrustedToken intentionally does NOT verify signatures
 * (see its d.ts: "done server-side using the rcan-py SDK or castor.auth
 * middleware"). This module performs Web Crypto Ed25519 SPKI verification
 * directly against the RRF root pubkey published at
 * functions/.well-known/rrf-root-pubkey.pem.
 *
 * The token is a standards-compliant JWS (RFC 7515) compact serialization:
 * the third segment is the detached signature over the exact ASCII bytes of
 * `${segment0}.${segment1}` as received. Nothing is re-encoded here, so a
 * stock EdDSA verifier and this function agree byte for byte. The historical
 * `rrf_sig` payload claim (signature-inside-the-signed-payload) is gone; see
 * functions/v2/orchestrators/[id]/token.ts for the matching mint.
 *
 * Flow:
 *   1. Extract Authorization: Bearer <jwt>
 *   2. Fetch rrf:root:pubkey from KV (or env fallback)
 *   3. Verify segment 2 over the received `${headerB64}.${payloadB64}`
 *   4. Assert claims.iss === "rrf.rcan.dev" and claims.exp > now
 *      (an opaque issuer identifier, compared for equality and never fetched;
 *      it is intentionally unchanged, see the note in
 *      functions/v2/orchestrators/[id]/token.ts and
 *      tests/dead-hostname-allowlist.json)
 *   5. Assert claims.rcan_scopes includes "fleet.trusted"
 *   6. Assert claims.fleet_rrns includes requiredRrn
 */

export interface JwtOk {
  ok: true;
  claims: Record<string, unknown>;
}

export interface JwtError {
  ok: false;
  status: number;
  error: string;
}

export type JwtResult = JwtOk | JwtError;

export interface JwtVerifyEnv {
  RRF_KV: KVNamespace;
  RRF_ROOT_PUBKEY?: string;
}

/** Decode URL-safe base64 to Uint8Array (Cloudflare Workers / atob-compatible). */
export function fromB64Url(s: string): Uint8Array {
  // Convert base64url → base64
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  // Pad to multiple of 4
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  return Uint8Array.from(atob(b64 + pad), (c) => c.charCodeAt(0));
}

/** Strip PEM framing + whitespace, return DER bytes. */
export function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

/** Resolve the RRF root pubkey PEM from KV (preferred) or env fallback. */
async function getRootPubkeyPem(env: JwtVerifyEnv): Promise<string | null> {
  const fromKv = await env.RRF_KV.get("rrf:root:pubkey", "text");
  if (fromKv) return fromKv;
  if (env.RRF_ROOT_PUBKEY) {
    const b64 = env.RRF_ROOT_PUBKEY.trim();
    return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`;
  }
  return null;
}

export async function verifyM2mTrustedJwt(
  env: JwtVerifyEnv,
  request: Request,
  requiredRrn: `RRN-${string}`,
): Promise<JwtResult> {
  // 1. Extract Authorization: Bearer <jwt>
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return { ok: false, status: 401, error: "Authorization: Bearer <jwt> required" };
  }
  const token = authHeader.slice("Bearer ".length).trim();
  if (!token) {
    return { ok: false, status: 401, error: "Authorization: Bearer <jwt> required" };
  }

  // 2. Token shape: header.payload.signature (3 parts)
  const parts = token.split(".");
  if (parts.length !== 3) {
    return { ok: false, status: 401, error: "Invalid JWT: expected 3 parts" };
  }
  const [headerB64, payloadB64, sigB64] = parts;

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(fromB64Url(headerB64))) as Record<string, unknown>;
    payload = JSON.parse(new TextDecoder().decode(fromB64Url(payloadB64))) as Record<string, unknown>;
  } catch {
    return { ok: false, status: 401, error: "Invalid JWT: malformed header or payload" };
  }
  if (!header || typeof header !== "object" || !payload || typeof payload !== "object") {
    return { ok: false, status: 401, error: "Invalid JWT: malformed header or payload" };
  }

  // 3. Resolve RRF root pubkey (KV preferred, env fallback)
  const pem = await getRootPubkeyPem(env);
  if (!pem) {
    return { ok: false, status: 500, error: "RRF root pubkey not provisioned" };
  }

  // 4. Verify the detached JWS signature over the segments exactly as received.
  //    No re-serialization: `${headerB64}.${payloadB64}` is the signing input a
  //    stock EdDSA JWS verifier would use, so both agree byte for byte.
  if (!sigB64) {
    return { ok: false, status: 401, error: "Invalid JWT: empty signature segment" };
  }
  const signingInput = `${headerB64}.${payloadB64}`;

  // 5. Web Crypto Ed25519 SPKI verify
  let signatureValid = false;
  try {
    const derBytes = pemToDer(pem);
    const key = await crypto.subtle.importKey(
      "spki",
      derBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const sigBytes = fromB64Url(sigB64);
    const encoder = new TextEncoder();
    signatureValid = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      sigBytes,
      encoder.encode(signingInput),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    return { ok: false, status: 401, error: "JWT signature verification failed" };
  }

  // 6. Claim assertions: iss + exp
  if (payload["iss"] !== "rrf.rcan.dev") {
    return { ok: false, status: 401, error: "Invalid issuer" };
  }
  const now = Math.floor(Date.now() / 1000);
  const exp = payload["exp"];
  if (typeof exp !== "number" || exp <= now) {
    return { ok: false, status: 401, error: "Token expired" };
  }

  // 7. rcan_scopes must include "fleet.trusted"
  const scopes = payload["rcan_scopes"];
  if (!Array.isArray(scopes) || !scopes.includes("fleet.trusted")) {
    return { ok: false, status: 403, error: "Token missing fleet.trusted scope" };
  }

  // 8. fleet_rrns must include requiredRrn
  const fleetRrns = payload["fleet_rrns"];
  if (!Array.isArray(fleetRrns) || !fleetRrns.includes(requiredRrn)) {
    return { ok: false, status: 403, error: `Token not scoped for ${requiredRrn}` };
  }

  return { ok: true, claims: payload };
}
