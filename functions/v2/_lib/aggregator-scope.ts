/**
 * Check whether an aggregator (by RAN) is authorized to attest for a robot (by RRN).
 *
 * KV key: aggregator-scope:RAN-NNN/RRN-MMM -> AggregatorScope
 *
 * Used by the compliance-bundle POST handler to enforce that a registered
 * aggregator can only persist bundles for robots within its scope.
 */

import type { AggregatorScope } from "./types.js";

export type ScopeOk = { ok: true };
export type ScopeError = { ok: false; status: number; error: string };
export type ScopeResult = ScopeOk | ScopeError;

export async function assertAggregatorScopedFor(
  env: { RRF_KV: KVNamespace },
  aggregatorRan: `RAN-${string}`,
  robotRrn: `RRN-${string}`,
): Promise<ScopeResult> {
  const key = `aggregator-scope:${aggregatorRan}/${robotRrn}`;
  const raw = await env.RRF_KV.get(key, "text");
  if (!raw) {
    return {
      ok: false,
      status: 403,
      error: `aggregator ${aggregatorRan} is not authorized to attest for ${robotRrn}`,
    };
  }
  let scope: AggregatorScope;
  try {
    scope = JSON.parse(raw) as AggregatorScope;
  } catch {
    return { ok: false, status: 500, error: "Corrupt aggregator-scope record" };
  }
  if (scope.valid_until) {
    const untilMs = Date.parse(scope.valid_until);
    if (!Number.isNaN(untilMs) && untilMs <= Date.now()) {
      return {
        ok: false,
        status: 403,
        error: `aggregator scope for ${aggregatorRan}/${robotRrn} expired at ${scope.valid_until}`,
      };
    }
  }
  return { ok: true };
}
