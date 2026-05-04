/**
 * /v2/compliance-bundle
 *
 * POST: schema-version routing -> handlers/v10 (or 415 on unsupported version).
 * GET /v2/compliance-bundle/{bundle_id}: full payload, Bearer-gated via M2M_TRUSTED JWT.
 *
 * Note: GET-by-id is handled by [bundle_id]/index.ts (separate file, Cloudflare
 * Pages Functions path-param convention). This file only handles the bare
 * /v2/compliance-bundle path (POST).
 */

import { handleV10 } from "./handlers/v10.js";

export interface Env {
  RRF_KV: KVNamespace;
  RRF_ROOT_PUBKEY?: string;
}

const SCHEMA_VERSION_HANDLERS: Record<string, (p: Record<string, unknown>, env: Env) => Promise<Response>> = {
  "1.0": handleV10,
};

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestPost: PagesFunction<Env> = async ({ env, request }) => {
  let payload: Record<string, unknown>;
  try {
    payload = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const schemaVersion = payload["schema_version"];
  if (typeof schemaVersion !== "string") {
    return json({ error: "schema_version required" }, 400);
  }
  const handler = SCHEMA_VERSION_HANDLERS[schemaVersion];
  if (!handler) {
    return json({
      error: `Unsupported schema_version: ${schemaVersion} (supported: ${Object.keys(SCHEMA_VERSION_HANDLERS).join(", ")})`,
    }, 415);
  }
  return handler(payload, env);
};
