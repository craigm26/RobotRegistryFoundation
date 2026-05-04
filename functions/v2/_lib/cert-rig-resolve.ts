/**
 * Resolve a cert-intake rig_signature.kid to the registered rig record,
 * filtered by `ran_at` falling within the kid's validity window.
 *
 * KV layout:
 *   cert-rig:<kid>:<registered_at> -> RigKidMapping (versioned per registration)
 *
 * If multiple cert-rig:<kid>:* entries are valid for the ran_at, the resolver
 * picks the most-recent registered_at (defensive against operator error during
 * rotation). Mirrors kid-resolve.ts (Plan 4 Phase 3) shape.
 */

import type { RigKidMapping } from "./types.js";

export async function resolveRigKid(
  env: { RRF_KV: KVNamespace },
  kid: string,
  ranAtIso: string,
): Promise<RigKidMapping | null> {
  const list = await env.RRF_KV.list({ prefix: `cert-rig:${kid}:` });
  if (list.keys.length === 0) return null;

  const ranAtMs = Date.parse(ranAtIso);
  if (Number.isNaN(ranAtMs)) return null;

  type Candidate = { mapping: RigKidMapping; key: string };
  const candidates: Candidate[] = [];
  for (const k of list.keys) {
    const raw = await env.RRF_KV.get(k.name, "text");
    if (!raw) continue;
    let mapping: RigKidMapping;
    try { mapping = JSON.parse(raw) as RigKidMapping; }
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
