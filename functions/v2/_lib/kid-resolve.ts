/**
 * Resolve a bundle_signature.kid to the registered authority record,
 * filtered by the bundle's signed_at falling within the kid's validity window.
 *
 * KV layout:
 *   kid:<kid>:<registered_at>  -> KidMapping (versioned per registration)
 *   authority:RAN-NNN          -> AuthorityRecord
 *
 * If multiple kid:<kid>:* entries are valid for the signed_at, the resolver picks
 * the most-recent registered_at (defensive against operator error during rotation).
 */

import type { KidMapping } from "./types.js";

export interface AuthorityForVerify {
  ran: `RAN-${string}`;
  signing_pub: string;       // Ed25519 base64
  pq_signing_pub: string;    // ML-DSA-65 base64
  organization?: string;
  pq_kid?: string;
}

export async function resolveKidToAuthority(
  env: { RRF_KV: KVNamespace },
  kid: string,
  signedAt: string,
): Promise<AuthorityForVerify | null> {
  const list = await env.RRF_KV.list({ prefix: `kid:${kid}:` });
  if (list.keys.length === 0) return null;

  const signedAtMs = Date.parse(signedAt);
  if (Number.isNaN(signedAtMs)) return null;

  type Candidate = { mapping: KidMapping; key: string };
  const candidates: Candidate[] = [];
  for (const k of list.keys) {
    const raw = await env.RRF_KV.get(k.name, "text");
    if (!raw) continue;
    let mapping: KidMapping;
    try { mapping = JSON.parse(raw) as KidMapping; }
    catch { continue; }
    const fromMs = Date.parse(mapping.valid_from);
    const untilMs = mapping.valid_until ? Date.parse(mapping.valid_until) : Number.POSITIVE_INFINITY;
    if (Number.isNaN(fromMs)) continue;
    if (signedAtMs < fromMs) continue;
    if (signedAtMs >= untilMs) continue;
    candidates.push({ mapping, key: k.name });
  }
  if (candidates.length === 0) return null;
  // Pick the most-recent registered_at (lexicographic on ISO-8601 = chronological).
  candidates.sort((a, b) => b.mapping.registered_at.localeCompare(a.mapping.registered_at));
  const winner = candidates[0].mapping;

  const authRaw = await env.RRF_KV.get(`authority:${winner.ran}`, "text");
  if (!authRaw) return null;
  try {
    const auth = JSON.parse(authRaw) as AuthorityForVerify;
    return auth;
  } catch {
    return null;
  }
}
