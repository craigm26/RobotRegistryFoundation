/**
 * /v2/robots/:rrn/sbom
 * RCAN v2.1 §12 — SBOM registry + RRF countersigning.
 *
 * POST — robot submits a CycloneDX SBOM; RRF countersigns it
 * GET  — retrieve the latest countersigned SBOM for a robot
 *
 * KV binding: RRF_KV
 * Key pattern: sbom:{rrn}
 */

export interface Env {
  RRF_KV: KVNamespace;
  RRF_SIGNING_KEY?: string;  // Ed25519 private key (base64), optional for mock
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env, params } = context;
  const rrn = params["rrn"] as string;

  if (!rrn || !rrn.match(/^RRN-[0-9]{12}$/)) {
    return new Response(JSON.stringify({ error: "Invalid RRN format" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  if (request.method === "GET") return handleGet(env, rrn);
  if (request.method === "POST") return handlePost(request, env, rrn);

  return new Response(JSON.stringify({ error: "Method not allowed" }), {
    status: 405, headers: { "Content-Type": "application/json" },
  });
};

async function handleGet(env: Env, rrn: string): Promise<Response> {
  const key = `sbom:${rrn}`;
  const stored = await env.RRF_KV.get(key, "text");
  if (!stored) {
    return new Response(JSON.stringify({ error: "SBOM not found", rrn }), {
      status: 404, headers: { "Content-Type": "application/json" },
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
  try {
    return await _handlePost(request, env, rrn);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return new Response(JSON.stringify({ error: "Internal error", detail: msg }), {
      status: 500, headers: { "Content-Type": "application/json" },
    });
  }
}

async function _handlePost(request: Request, env: Env, rrn: string): Promise<Response> {
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Authorization required" }), {
      status: 401, headers: { "Content-Type": "application/json" },
    });
  }

  let sbom: Record<string, unknown>;
  try {
    sbom = await request.json() as Record<string, unknown>;
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  // Validate CycloneDX format
  if (sbom.bomFormat !== "CycloneDX") {
    return new Response(JSON.stringify({ error: "bomFormat must be 'CycloneDX'" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  // Validate RCAN extension
  const rcanExt = sbom["x-rcan"] as Record<string, unknown> | undefined;
  if (!rcanExt || rcanExt.rrn !== rrn) {
    return new Response(
      JSON.stringify({ error: "x-rcan.rrn must match URL rrn" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  // RRF countersignature — sign canonical SBOM JSON
  const canonicalJson = JSON.stringify({ ...sbom, rrf_countersig: undefined });
  const countersig = await signWithRRFKey(canonicalJson, env.RRF_SIGNING_KEY);

  // Add RRF countersig to the x-rcan extension
  const countersignedSbom = {
    ...sbom,
    "x-rcan": {
      ...rcanExt,
      rrf_countersig:  countersig,
      rrf_countersigned_at: new Date().toISOString(),
    },
    rrf_submitted_at: new Date().toISOString(),
  };

  const stored = JSON.stringify(countersignedSbom);
  await env.RRF_KV.put(`sbom:${rrn}`, stored, { expirationTtl: 365 * 24 * 3600 });
  // History
  await env.RRF_KV.put(`sbom:history:${rrn}:${Date.now()}`, stored, {
    expirationTtl: 365 * 24 * 3600 * 3,
  });

  return new Response(
    JSON.stringify({
      ok:              true,
      rrn,
      rrf_countersig:  countersig,
      sbom_url:        `https://api.rrf.rcan.dev/v2/robots/${rrn}/sbom`,
      countersigned_at: new Date().toISOString(),
    }),
    { status: 201, headers: { "Content-Type": "application/json" } },
  );
}

async function signWithRRFKey(data: string, signingKey?: string): Promise<string> {
  // If RRF_SIGNING_KEY is set, use Web Crypto Ed25519.
  // Otherwise return a deterministic mock countersig for development.
  if (!signingKey) {
    // Development mock: SHA-256 of data as countersig placeholder
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(data));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  // Production: Ed25519 signing via Web Crypto
  // Key is stored as base64-encoded PKCS8 DER
  const keyBytes = Uint8Array.from(atob(signingKey), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "pkcs8", keyBytes,
    { name: "Ed25519" },
    false, ["sign"],
  );
  const encoder = new TextEncoder();
  const sig = await crypto.subtle.sign("Ed25519", key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
