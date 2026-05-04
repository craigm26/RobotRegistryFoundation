/**
 * Resolve a cert-intake witness_signature.kid to the registered witness record,
 * filtered by `ran_at` falling within the kid's validity window.
 *
 * KV layout:
 *   cert-witness:<kid>:<registered_at> -> WitnessKidMapping
 *
 * Rotation overlap: most-recent registered_at wins.
 * Mirrors cert-rig-resolve.ts (Plan 6 Phase 4 Task 2) shape.
 */

import type { WitnessKidMapping } from "./types.js";

export async function resolveWitnessKid(
  env: { RRF_KV: KVNamespace },
  kid: string,
  ranAtIso: string,
): Promise<WitnessKidMapping | null> {
  const list = await env.RRF_KV.list({ prefix: `cert-witness:${kid}:` });
  if (list.keys.length === 0) return null;

  const ranAtMs = Date.parse(ranAtIso);
  if (Number.isNaN(ranAtMs)) return null;

  type Candidate = { mapping: WitnessKidMapping; key: string };
  const candidates: Candidate[] = [];
  for (const k of list.keys) {
    const raw = await env.RRF_KV.get(k.name, "text");
    if (!raw) continue;
    let mapping: WitnessKidMapping;
    try { mapping = JSON.parse(raw) as WitnessKidMapping; }
    catch { continue; }
    const fromMs = Date.parse(mapping.valid_from);
    const untilMs = mapping.valid_until ? Date.parse(mapping.valid_until) : Number.POSITIVE_INFINITY;
    if (Number.isNaN(fromMs)) continue;
    if (ranAtMs < fromMs) continue;
    if (ranAtMs >= untilMs) continue;
    candidates.push({ mapping, key: k.name });
  }
  if (candidates.length === 0) return null;
  // Pick the most-recent registered_at (lexicographic on ISO-8601 = chronological).
  candidates.sort((a, b) => b.mapping.registered_at.localeCompare(a.mapping.registered_at));
  return candidates[0].mapping;
}
