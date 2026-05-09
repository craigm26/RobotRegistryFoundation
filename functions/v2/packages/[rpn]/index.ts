/**
 * GET /v2/packages/[rpn] — direct lookup of a package record by RPN.
 */

import { isValidId } from "../../_lib/id.js";

export interface Env { RRF_KV: KVNamespace }

function err(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env, "rpn"> = async ({ env, params }) => {
  const rpn = params.rpn as string;
  if (!isValidId(rpn, "RPN")) return err("Malformed RPN", 400);
  const raw = await env.RRF_KV.get(`package:${rpn}`);
  if (!raw) return err(`No package with RPN ${rpn}`, 404);
  return new Response(raw, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};
