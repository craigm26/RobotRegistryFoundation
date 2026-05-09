/**
 * GET /v2/packages — list packages with filtering.
 *
 * Query params:
 *   ?type=actuator | skill | plugin | mcp  (defaults to actuator)
 *   ?tag=<hardware_tag>                    (single tag filter; case-sensitive)
 *   ?include_revoked=1                     (defaults to false)
 *   ?limit=<int>                           (defaults to 100, max 1000)
 *   ?cursor=<rpn>                          (pagination — RPN to start AFTER)
 *
 * Returns: { packages: PackageRecord[], next_cursor?: string }
 */

import type { PackageRecord, PackageType } from "../_lib/types.js";

export interface Env { RRF_KV: KVNamespace }

const VALID_TYPES: PackageType[] = ["actuator", "skill", "plugin", "mcp"];

function err(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const url = new URL(request.url);
  const type = (url.searchParams.get("type") ?? "actuator") as PackageType;
  if (!VALID_TYPES.includes(type)) return err(`Invalid type: ${type}`, 400);
  const tag = url.searchParams.get("tag");
  const includeRevoked = url.searchParams.get("include_revoked") === "1";
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "100", 10) || 100, 1000);
  const cursor = url.searchParams.get("cursor");

  const indexRaw = await env.RRF_KV.get(`package-by-type:${type}`);
  if (!indexRaw) return new Response(JSON.stringify({ packages: [] }), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
  const allRpns = indexRaw.split("\n").filter(Boolean);

  let startIdx = 0;
  if (cursor) {
    const i = allRpns.indexOf(cursor);
    if (i >= 0) startIdx = i + 1;
  }

  const out: PackageRecord[] = [];
  let nextCursor: string | undefined;
  for (let i = startIdx; i < allRpns.length; i++) {
    if (out.length >= limit) {
      nextCursor = allRpns[i - 1];
      break;
    }
    const raw = await env.RRF_KV.get(`package:${allRpns[i]}`);
    if (!raw) continue;
    const rec = JSON.parse(raw) as PackageRecord;
    if (!includeRevoked && rec.status === "revoked") continue;
    if (tag && !rec.hardware_tags.includes(tag)) continue;
    out.push(rec);
  }

  return new Response(JSON.stringify({ packages: out, next_cursor: nextCursor }), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
};
