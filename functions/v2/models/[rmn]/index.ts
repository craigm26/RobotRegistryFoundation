/**
 * GET /v2/models/:rmn
 * Look up a registered AI model by its RMN.
 */

import { isValidId } from "../../_lib/id.js";

export interface Env { RRF_KV: KVNamespace }

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const rmn = params["rmn"] as string;

  if (!isValidId(rmn, "RMN")) {
    return new Response(JSON.stringify({ error: "Invalid RMN format" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  const stored = await env.RRF_KV.get(`model:${rmn}`, "text");
  if (!stored) {
    return new Response(JSON.stringify({ error: "Model not found", rmn }), {
      status: 404, headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
};
