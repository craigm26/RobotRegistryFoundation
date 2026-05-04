/**
 * GET /v2/cert-intake/{cert_id}
 *
 * Bearer-gated (M2M_TRUSTED JWT). Returns the full as-submitted payload
 * (augmented with server-resolved rrn). Mirrors compliance-bundle/[bundle_id]/index.ts.
 */

import { verifyM2mTrustedJwt } from "../../_lib/jwt-verify.js";

export interface Env {
  RRF_KV: KVNamespace;
  RRF_ROOT_PUBKEY?: string;
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env, "cert_id"> = async ({ env, request, params }) => {
  const certId = params["cert_id"] as string;
  if (!certId || !certId.startsWith("cert_")) {
    return json({ error: "cert_id missing or malformed" }, 400);
  }

  // Read first to find the RRN — needed for JWT scope check.
  const raw = await env.RRF_KV.get(`cert-intake:${certId}`, "text");
  if (!raw) return json({ error: `cert_id ${certId} not found` }, 404);

  let payload: Record<string, unknown>;
  try { payload = JSON.parse(raw) as Record<string, unknown>; }
  catch { return json({ error: "corrupt cert-intake record" }, 500); }

  const rrn = payload["rrn"];
  if (typeof rrn !== "string" || !/^RRN-\d{12}$/.test(rrn)) {
    return json({ error: "stored cert-intake has malformed rrn" }, 500);
  }

  const jwtResult = await verifyM2mTrustedJwt(env, request, rrn as `RRN-${string}`);
  if (!jwtResult.ok) {
    return json({ error: jwtResult.error }, jwtResult.status);
  }

  return json(payload, 200);
};
