/**
 * GET /v2/orchestrators/:id/token
 * RCAN v2.1 §2.9 — Issue a short-lived M2M_TRUSTED JWT.
 *
 * Returns: { token (JWT), exp, fleet_rrns }
 * JWT claims: sub, rcan_role='m2m_trusted', rcan_scopes=['fleet.trusted'],
 *             fleet_rrns, exp=86400, iss='rrf.rcan.dev', rrf_sig
 *
 * Only issued when orchestrator.status === 'active'.
 * Re-issuance requires re-validation (not cached).
 */

export interface Env {
  RRF_KV: KVNamespace;
  RRF_SIGNING_KEY?: string;  // Ed25519 private key (base64url) for JWT signing
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env, params } = context;
  const id = params["id"] as string;

  if (request.method !== "GET") {
    return json({ error: "Method not allowed" }, 405);
  }

  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return json({ error: "Authorization required" }, 401);
  }

  const stored = await env.RRF_KV.get(`orchestrator:${id}`, "text");
  if (!stored) {
    return json({ error: "Orchestrator not found", id }, 404);
  }

  const record = JSON.parse(stored) as {
    id: string; rrn: string; fleet_rrns: string[];
    status: string; orchestrator_key: string;
  };

  if (record.status !== "active") {
    return json({
      error:  `Orchestrator status is '${record.status}' — token only issued for active orchestrators`,
      status: record.status,
    }, 403);
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + 86400; // 24h max TTL per spec

  // Build JWT payload
  const payload = {
    sub:         id,
    iss:         "rrf.rcan.dev",
    iat:         now,
    exp,
    rcan_role:   "m2m_trusted",
    rcan_scopes: ["fleet.trusted"],
    fleet_rrns:  record.fleet_rrns,
    rrf_sig:     "", // will be filled in after signing
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

async function buildSignedJWT(
  payload: Record<string, unknown>,
  signingKey?: string,
): Promise<string> {
  const header = { alg: "EdDSA", typ: "JWT" };
  const b64url = (s: string) =>
    btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  const encode = (obj: unknown) => b64url(JSON.stringify(obj));

  // Compute the signing input (without rrf_sig in the payload)
  const { rrf_sig: _, ...payloadWithoutSig } = payload as Record<string, unknown>;
  const signingInput = `${encode(header)}.${encode(payloadWithoutSig)}`;

  let sig: string;
  if (signingKey) {
    // Key is stored as base64-encoded PKCS8 DER
    const keyBytes = Uint8Array.from(atob(signingKey), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      "pkcs8", keyBytes, { name: "Ed25519" }, false, ["sign"],
    );
    const encoder = new TextEncoder();
    const sigBuffer = await crypto.subtle.sign("Ed25519", key, encoder.encode(signingInput));
    sig = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  } else {
    // Development mock signature
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest("SHA-256", encoder.encode(signingInput));
    sig = btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  // Embed rrf_sig in payload
  const finalPayload = { ...payloadWithoutSig, rrf_sig: sig };
  return `${encode(header)}.${encode(finalPayload)}.${sig}`;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json" },
  });
}
