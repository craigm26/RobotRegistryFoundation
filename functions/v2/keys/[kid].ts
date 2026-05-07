/**
 * GET /v2/keys/<kid> — resolve a kid to its registered hybrid pubkey pair.
 *
 * Bridges robot-md-gateway's RRFResolverFromEnv to the existing kid:/authority:
 * KV registry. Returns Ed25519 PEM (gateway reads this today) plus ML-DSA-65
 * raw base64 + pq_kid (forward-compat for hybrid verifiers).
 *
 * Spec: docs/superpowers/specs/2026-05-04-rrf-keys-endpoint-design.md
 * Plan: docs/superpowers/plans/2026-05-04-rrf-keys-endpoint.md (Task A4)
 *
 * Note: this handler does NOT delegate to resolveKidToAuthority because that
 * helper collapses "authority record unparseable" into "null" — losing the
 * 502-vs-404 distinction this endpoint needs. We inline a single-pass scan
 * over kid:<kid>:* that selects the most-recent registered_at covering NOW,
 * then fetches the authority record explicitly so we can surface parse
 * failures as 502 (registry data integrity error) rather than 404.
 */

import { ed25519RawToPem } from "../_lib/spki.js";

interface AuthorityForRead {
  ran: `RAN-${string}`;
  organization?: string;
  display_name?: string;
  purpose?: string;
  signing_pub: string;
  pq_signing_pub: string;
  pq_kid: string;
  signing_alg?: string[];
  registered_at?: string;
  status?: "active" | "revoked";
  revoked_at?: string;
  revocation_reason?: string;
}

interface KidMappingForRead {
  ran: `RAN-${string}`;
  valid_from: string;
  valid_until?: string;
  registered_at: string;
  registered_by?: string;
}

const NO_STORE = { "Content-Type": "application/json", "Cache-Control": "no-store" };

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = NO_STORE): Response {
  return new Response(JSON.stringify(body), { status, headers });
}

export const onRequest: PagesFunction<{ RRF_KV: KVNamespace }, "kid"> = async ({ request, env, params }) => {
  if (request.method !== "GET") {
    return jsonResponse(405, { error: "Method not allowed" });
  }
  const kid = String(params.kid ?? "");
  if (!kid) {
    return jsonResponse(404, { error: "kid not registered", kid });
  }

  // Single-pass scan of kid:<kid>:* — find the most-recent registered_at
  // mapping that covers NOW.
  let listResult;
  try {
    listResult = await env.RRF_KV.list({ prefix: `kid:${kid}:` });
  } catch {
    return jsonResponse(502, { error: "registry temporarily unavailable" });
  }
  if (listResult.keys.length === 0) {
    return jsonResponse(404, { error: "kid not registered", kid });
  }

  const nowMs = Date.now();
  type Cand = { mapping: KidMappingForRead; key: string };
  const candidates: Cand[] = [];
  for (const k of listResult.keys) {
    let raw: string | null;
    try {
      raw = await env.RRF_KV.get(k.name, "text");
    } catch {
      return jsonResponse(502, { error: "registry temporarily unavailable" });
    }
    if (!raw) continue;
    let mapping: KidMappingForRead;
    try {
      mapping = JSON.parse(raw) as KidMappingForRead;
    } catch {
      // Skip a single corrupt mapping — other versions may still be valid.
      continue;
    }
    const fromMs = Date.parse(mapping.valid_from);
    const untilMs = mapping.valid_until ? Date.parse(mapping.valid_until) : Number.POSITIVE_INFINITY;
    if (Number.isNaN(fromMs)) continue;
    if (nowMs < fromMs) continue;
    if (nowMs >= untilMs) continue;
    candidates.push({ mapping, key: k.name });
  }
  if (candidates.length === 0) {
    return jsonResponse(404, { error: "kid has no valid mapping at this time", kid });
  }
  // Lexicographic ISO-8601 sort = chronological; most-recent registered_at wins.
  candidates.sort((a, b) => b.mapping.registered_at.localeCompare(a.mapping.registered_at));
  const winner = candidates[0].mapping;

  // Fetch the authority record. Distinguish missing (404) from unparseable (502).
  let authRaw: string | null;
  try {
    authRaw = await env.RRF_KV.get(`authority:${winner.ran}`, "text");
  } catch {
    return jsonResponse(502, { error: "registry temporarily unavailable" });
  }
  if (!authRaw) {
    return jsonResponse(404, { error: "kid has no valid mapping at this time", kid });
  }

  let auth: AuthorityForRead;
  try {
    auth = JSON.parse(authRaw) as AuthorityForRead;
  } catch {
    return jsonResponse(502, { error: "registry data integrity error" });
  }

  if (auth.status === "revoked") {
    const body: Record<string, unknown> = { error: "kid revoked", kid, ran: auth.ran };
    if (auth.revoked_at) body.revoked_at = auth.revoked_at;
    if (auth.revocation_reason) body.revocation_reason = auth.revocation_reason;
    return jsonResponse(410, body);
  }

  let edRaw: Uint8Array;
  let pqRaw: Uint8Array;
  try {
    edRaw = Uint8Array.from(atob(auth.signing_pub), c => c.charCodeAt(0));
    pqRaw = Uint8Array.from(atob(auth.pq_signing_pub), c => c.charCodeAt(0));
  } catch {
    return jsonResponse(502, { error: "registry data integrity error" });
  }
  if (edRaw.length !== 32 || pqRaw.length !== 1952) {
    return jsonResponse(502, { error: "registry data integrity error" });
  }
  if (!auth.pq_kid || typeof auth.pq_kid !== "string") {
    return jsonResponse(502, { error: "registry data integrity error" });
  }

  let publicKeyPem: string;
  try {
    publicKeyPem = ed25519RawToPem(edRaw);
  } catch {
    return jsonResponse(502, { error: "registry data integrity error" });
  }

  return jsonResponse(200, {
    kid,
    alg: "Ed25519",
    public_key_pem: publicKeyPem,
    pq_alg: "ML-DSA-65",
    pq_public_key_b64: auth.pq_signing_pub,
    pq_kid: auth.pq_kid,
    ran: auth.ran,
    valid_from: winner.valid_from,
    valid_until: winner.valid_until ?? null,
    status: "active",
  }, { "Content-Type": "application/json", "Cache-Control": "public, max-age=60" });
};
