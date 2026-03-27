/**
 * GET /v2/registry
 * RCAN v2.2 §21 — Unified listing of all registered entities.
 *
 * Query params:
 *   type?   filter by entity_type: robot | component | model | harness
 *   limit?  max results (default 50, max 200)
 *
 * Returns: { entries[], total, entity_types_count }
 */

import type { RegistryEntry } from "../_lib/types.js";

export interface Env { RRF_KV: KVNamespace }

const PREFIXES: Array<{ prefix: string; type: RegistryEntry["entity_type"]; kvKey: string }> = [
  { prefix: "RRN",     type: "robot",     kvKey: "robot:" },
  { prefix: "RCN",     type: "component", kvKey: "component:" },
  { prefix: "RMN",     type: "model",     kvKey: "model:" },
  { prefix: "RHN",     type: "harness",   kvKey: "harness:" },
];

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const url = new URL(request.url);
  const typeFilter = url.searchParams.get("type");
  const rawLimit = parseInt(url.searchParams.get("limit") ?? "50", 10);
  const limit = Math.min(isNaN(rawLimit) ? 50 : rawLimit, 200);

  const prefixesToScan = typeFilter
    ? PREFIXES.filter((p) => p.type === typeFilter)
    : PREFIXES;

  if (typeFilter && prefixesToScan.length === 0) {
    return new Response(
      JSON.stringify({ error: "Invalid type. Must be: robot, component, model, harness" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  const entries: RegistryEntry[] = [];
  const counts: Record<string, number> = { robot: 0, component: 0, model: 0, harness: 0 };

  for (const { type, kvKey } of prefixesToScan) {
    const list = await env.RRF_KV.list({ prefix: kvKey, limit: 200 });

    counts[type] = 0; // will be updated after fetching live records below

    const toFetch = list.keys.slice(0, limit - entries.length);
    const records = await Promise.all(
      toFetch.map(async (k) => {
        const val = await env.RRF_KV.get(k.name, "text");
        return val ? JSON.parse(val) : null;
      }),
    );

    let liveCount = 0;
    for (const record of records) {
      if (!record) continue;
      liveCount++;
      entries.push(summarize(record, type));
    }
    // Use live count (from actual get()) not list.keys.length — KV list is eventually consistent
    counts[type] = liveCount;

    if (entries.length >= limit) break;
  }

  // Sort by registered_at descending (newest first)
  entries.sort((a, b) =>
    new Date(b.registered_at).getTime() - new Date(a.registered_at).getTime(),
  );

  return new Response(
    JSON.stringify({
      entries: entries.slice(0, limit),
      total: entries.length,
      entity_types_count: counts,
      rcan_version: "2.2",
    }),
    { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=60" } },
  );
};

function summarize(record: Record<string, unknown>, type: RegistryEntry["entity_type"]): RegistryEntry {
  const id = (record.rrn ?? record.rcn ?? record.rmn ?? record.rhn) as string;
  let name = "";
  let summary: Record<string, unknown> = {};

  switch (type) {
    case "robot":
      name = record.name as string;
      summary = { manufacturer: record.manufacturer, model: record.model,
                  rcan_version: record.rcan_version, firmware_version: record.firmware_version };
      break;
    case "component":
      name = `${record.model} (${record.type})`;
      summary = { type: record.type, manufacturer: record.manufacturer,
                  parent_rrn: record.parent_rrn };
      break;
    case "model":
      name = `${record.name} v${record.version}`;
      summary = { model_family: record.model_family, provider: record.provider,
                  parameter_count_b: record.parameter_count_b, quantization: record.quantization };
      break;
    case "harness":
      name = `${record.name} v${record.version}`;
      summary = { harness_type: record.harness_type, rcan_version: record.rcan_version,
                  open_source: record.open_source };
      break;
  }

  return { id, entity_type: type, name, registered_at: record.registered_at as string, summary };
}
