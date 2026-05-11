/**
 * GET /v2/robots/_next
 *
 * Returns the RRN that the next call to POST /v2/robots/register will
 * allocate, plus the reserved-floor so clients understand why. Read-only;
 * does not advance the counter.
 *
 * Body:
 *   {
 *     "next_rrn": "RRN-000000000010",
 *     "reserved_floor": 10,
 *     "note": "RRN-000000000001..RRN-000000000009 reserved for canonical robots"
 *   }
 */

import { formatId, peekNextSeq, RESERVED_FLOORS } from "../_lib/id.js";

export interface Env {
  RRF_KV: KVNamespace;
}

export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
  const seq = await peekNextSeq(env.RRF_KV, "RRN");
  const reserved_floor = RESERVED_FLOORS.RRN ?? 0;
  const body = {
    next_rrn: formatId("RRN", seq),
    reserved_floor,
    note: reserved_floor > 0
      ? `RRN-${String(1).padStart(12, "0")}..RRN-${String(reserved_floor - 1).padStart(12, "0")} ` +
        `reserved for canonical robots; auto-mints start at RRN-${String(reserved_floor).padStart(12, "0")}`
      : "no reserved range",
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
};
