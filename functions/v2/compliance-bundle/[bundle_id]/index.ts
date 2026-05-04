/**
 * GET /v2/compliance-bundle/{bundle_id}
 * Bearer-gated full bundle return. Bearer = M2M_TRUSTED JWT.
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

export const onRequestGet: PagesFunction<Env, "bundle_id"> = async ({ env, request, params }) => {
  const bundleId = params["bundle_id"] as string;
  if (!bundleId || !bundleId.startsWith("bundle_")) {
    return json({ error: "bundle_id missing or malformed" }, 400);
  }

  // Read first to find the RRN — we need it for the JWT scope check.
  const raw = await env.RRF_KV.get(`compliance-bundle:${bundleId}`, "text");
  if (!raw) return json({ error: `bundle ${bundleId} not found` }, 404);

  let payload: Record<string, unknown>;
  try { payload = JSON.parse(raw) as Record<string, unknown>; }
  catch { return json({ error: "corrupt bundle record" }, 500); }

  const rrn = payload["rrn"];
  if (typeof rrn !== "string" || !/^RRN-\d{12}$/.test(rrn)) {
    return json({ error: "stored bundle has malformed rrn" }, 500);
  }

  const jwtResult = await verifyM2mTrustedJwt(env, request, rrn as `RRN-${string}`);
  if (!jwtResult.ok) {
    return json({ error: jwtResult.error }, jwtResult.status);
  }

  return json(payload, 200);
};
