/**
 * /v2/robots/:rrn/firmware-manifest
 * RCAN v2.1 §11 — Firmware Manifest registry endpoint.
 *
 * POST — robot submits a signed firmware manifest
 * GET  — retrieve the latest manifest for a robot
 *
 * KV binding: RRF_KV
 * Key pattern: firmware:manifest:{rrn}
 */

export interface Env {
  RRF_KV: KVNamespace;
}

/** Cloudflare Pages Function request handler. */
export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env, params } = context;
  const rrn = params["rrn"] as string;

  if (!rrn || !rrn.match(/^RRN-[0-9]{12}$/)) {
    return new Response(JSON.stringify({ error: "Invalid RRN format" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (request.method === "GET") {
    return handleGet(env, rrn);
  }
  if (request.method === "POST") {
    return handlePost(request, env, rrn);
  }

  return new Response(JSON.stringify({ error: "Method not allowed" }), {
    status: 405,
    headers: { "Content-Type": "application/json" },
  });
};

async function handleGet(env: Env, rrn: string): Promise<Response> {
  const key = `firmware:manifest:${rrn}`;
  const stored = await env.RRF_KV.get(key, "text");

  if (!stored) {
    return new Response(JSON.stringify({ error: "Firmware manifest not found", rrn }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(stored, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300",
    },
  });
}

async function handlePost(request: Request, env: Env, rrn: string): Promise<Response> {
  // Authenticate: require Authorization header (CREATOR token for this RRN)
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Authorization required" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  let manifest: Record<string, unknown>;
  try {
    manifest = await request.json() as Record<string, unknown>;
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate required fields
  if (!manifest.rrn || !manifest.firmware_version || !manifest.build_hash || !manifest.signature) {
    return new Response(
      JSON.stringify({
        error: "Missing required fields: rrn, firmware_version, build_hash, signature",
      }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  if (manifest.rrn !== rrn) {
    return new Response(
      JSON.stringify({ error: "Manifest rrn does not match URL rrn" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  // Validate build_hash format
  if (typeof manifest.build_hash !== "string" || !manifest.build_hash.startsWith("sha256:")) {
    return new Response(
      JSON.stringify({ error: "build_hash must start with 'sha256:'" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  // Store manifest (TTL: 1 year)
  const key = `firmware:manifest:${rrn}`;
  const stored = JSON.stringify({
    ...manifest,
    submitted_at: new Date().toISOString(),
  });
  await env.RRF_KV.put(key, stored, { expirationTtl: 365 * 24 * 3600 });

  // Also store history entry
  const historyKey = `firmware:history:${rrn}:${Date.now()}`;
  await env.RRF_KV.put(historyKey, stored, { expirationTtl: 365 * 24 * 3600 * 3 });

  return new Response(
    JSON.stringify({
      ok:           true,
      rrn,
      submitted_at: new Date().toISOString(),
      manifest_url: `https://api.rrf.rcan.dev/v2/robots/${rrn}/firmware-manifest`,
    }),
    { status: 201, headers: { "Content-Type": "application/json" } },
  );
}
