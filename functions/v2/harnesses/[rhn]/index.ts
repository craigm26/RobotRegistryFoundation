/**
 * GET /v2/harnesses/:rhn
 * Look up a registered AI harness by its RHN.
 */

import { isValidId } from "../../_lib/id.js";

export interface Env { RRF_KV: KVNamespace }

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const rhn = params["rhn"] as string;

  if (!isValidId(rhn, "RHN")) {
    return new Response(JSON.stringify({ error: "Invalid RHN format" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  const stored = await env.RRF_KV.get(`harness:${rhn}`, "text");
  if (!stored) {
    return new Response(JSON.stringify({ error: "Harness not found", rhn }), {
      status: 404, headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
};
