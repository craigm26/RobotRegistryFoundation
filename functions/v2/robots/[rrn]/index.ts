/**
 * GET /v2/robots/:rrn
 * Look up a registered whole robot by its RRN.
 */

import { isValidId } from "../../_lib/id.js";

export interface Env { RRF_KV: KVNamespace }

export const onRequestGet: PagesFunction<Env> = async ({ env, params }) => {
  const rrn = params["rrn"] as string;

  if (!isValidId(rrn, "RRN")) {
    return new Response(JSON.stringify({ error: "Invalid RRN format" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  const stored = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!stored) {
    return new Response(JSON.stringify({ error: "Robot not found", rrn }), {
      status: 404, headers: { "Content-Type": "application/json" },
    });
  }

  return new Response(stored, {
    headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=60" },
  });
};
