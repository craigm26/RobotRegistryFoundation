/**
 * GET /v2/packages/[rpn]/proof — return the original signed register body
 * (with sig intact) so third parties can cryptographically verify the publish.
 *
 * The /v2/packages/[rpn] endpoint returns a "stripped" record (no sig) for
 * catalog display; this endpoint returns the verifiable artifact. Both keys
 * are written at register-time and stay in sync (registers are append-only at
 * the package level — version bumps go through /versions which doesn't update
 * the proof).
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
  const raw = await env.RRF_KV.get(`package-proof:${rpn}`);
  if (!raw) return err(`No proof for RPN ${rpn}`, 404);
  return new Response(raw, {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
};
