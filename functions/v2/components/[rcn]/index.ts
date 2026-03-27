/**
 * GET /v2/components/:rcn
 * Look up a registered hardware component by its RCN.
 */

import { isValidId } from "../../_lib/id.js";

export interface Env { RRF_KV: KVNamespace }

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const rcn = params["rcn"] as string;

  if (!isValidId(rcn, "RCN")) {
    return new Response(JSON.stringify({ error: "Invalid RCN format" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  const stored = await env.RRF_KV.get(`component:${rcn}`, "text");
  if (!stored) {
    return new Response(JSON.stringify({ error: "Component not found", rcn }), {
      status: 404, headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
};
