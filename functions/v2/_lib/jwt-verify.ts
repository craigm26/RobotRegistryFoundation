/**
 * Verify a Bearer M2M_TRUSTED JWT for a given RRN scope.
 *
 * NOTE: rcan-ts.verifyM2mTrustedToken intentionally does NOT verify signatures
 * (see its d.ts: "done server-side using the rcan-py SDK or castor.auth
 * middleware"). This module performs Web Crypto Ed25519 SPKI verification
 * directly against the RRF root pubkey published at
 * functions/.well-known/rrf-root-pubkey.pem.
 *
 * Mirrors the signing-input reconstruction pattern from
 * functions/v2/orchestrators/[id]/token.ts (strips rrf_sig before signing
 * input is hashed; the emitted token's payload contains the embedded sig).
 *
 * Flow:
 *   1. Extract Authorization: Bearer <jwt>
 *   2. Fetch rrf:root:pubkey from KV (or env fallback)
 *   3. Reconstruct signing input: b64u(header).b64u(payload-minus-rrf_sig)
 *   4. Web Crypto Ed25519 SPKI verify
 *   5. Assert claims.iss === "rrf.rcan.dev" and claims.exp > now
 *   6. Assert claims.rcan_scopes includes "fleet.trusted"
 *   7. Assert claims.fleet_rrns includes requiredRrn
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
function fromB64Url(s: string): Uint8Array {
  // Convert base64url → base64
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  // Pad to multiple of 4
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  return Uint8Array.from(atob(b64 + pad), (c) => c.charCodeAt(0));
}

/** Strip PEM framing + whitespace, return DER bytes. */
function pemToDer(pem: string): Uint8Array {
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
  const [headerB64, payloadB64, _sigB64] = parts;

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

  // 4. Extract embedded rrf_sig and reconstruct signing input
  // (mirrors the mint at functions/v2/orchestrators/[id]/token.ts:84-87 —
  // signing input is b64u(header).b64u(payload-minus-rrf_sig))
  const rrfSig = payload["rrf_sig"];
  if (typeof rrfSig !== "string" || rrfSig.length === 0) {
    return { ok: false, status: 401, error: "Invalid JWT: missing rrf_sig in payload" };
  }
  const { rrf_sig: _omit, ...payloadWithoutSig } = payload;

  const b64u = (s: string) =>
    btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payloadWithoutSig))}`;

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
    const sigBytes = fromB64Url(rrfSig);
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
