/**
 * RCAN Entity ID generation — sequential, zero-padded 12-digit counters.
 *
 * Prefixes (RCAN v2.2 §21):
 *   RRN — Robot Registration Number      (whole robot)
 *   RCN — Robot Component Number         (hardware component)
 *   RMN — Robot Model Number             (AI model)
 *   RHN — Robot Harness Number           (AI harness / agent)
 *   RPN — Registered Package Number      (software package: actuator/skill/plugin/mcp)
 *
 * Format:  {PREFIX}-{12-digit zero-padded sequential integer}
 * Example: RRN-000000000001, RCN-000000000003, RPN-000000000001
 *
 * Counter KV keys: counter:rrn, counter:rcn, counter:rmn, counter:rhn, counter:rpn
 */

export type EntityPrefix = "RRN" | "RCN" | "RMN" | "RHN" | "RPN";

export function prefixToCounterKey(prefix: EntityPrefix): string {
  return `counter:${prefix.toLowerCase()}`;
}

/**
 * Reserved-floor per prefix: auto-mints never produce a sequence below this
 * value. Slots below the floor are reserved for canonical/curated entities
 * (e.g. RRN-000000000001 = Bob, RRN-000000000005 = Alex) so a counter reset
 * — which restarts the sequence at 1 — does not silently collide with
 * documented well-known IDs. Operators wanting one of the reserved slots
 * must contact RRF for manual assignment.
 *
 * Set the floor with a generous margin so future canonical robots can be
 * added without bumping it again.
 */
export const RESERVED_FLOORS: Partial<Record<EntityPrefix, number>> = {
  RRN: 10,
};

/** Format a sequence number as a zero-padded 12-digit ID. */
export function formatId(prefix: EntityPrefix, seq: number): string {
  return `${prefix}-${String(seq).padStart(12, "0")}`;
}

/**
 * Return the sequence number nextId() will allocate on the next call,
 * WITHOUT incrementing the counter. Used by the /v2/robots/_next preview
 * endpoint so operators can see which RRN they'll receive before they sign
 * a registration body.
 */
export async function peekNextSeq(kv: KVNamespace, prefix: EntityPrefix): Promise<number> {
  const key = prefixToCounterKey(prefix);
  const current = await kv.get(key, "text");
  const raw = current ? parseInt(current, 10) + 1 : 1;
  const floor = RESERVED_FLOORS[prefix] ?? 0;
  return raw < floor ? floor : raw;
}

/**
 * Atomically increment the counter for a given entity prefix and return the
 * new sequential ID.  Uses optimistic locking: reads the current value, adds 1,
 * writes back with the old value as a guard (KV does not support CAS natively,
 * so we use a single-writer assumption acceptable for low-traffic RRF).
 *
 * Respects RESERVED_FLOORS: if the computed sequence falls inside a prefix's
 * reserved range, jumps the counter forward to the floor and returns the
 * floor value instead.
 */
export async function nextId(kv: KVNamespace, prefix: EntityPrefix): Promise<string> {
  const key = prefixToCounterKey(prefix);
  const current = await kv.get(key, "text");
  let seq = current ? parseInt(current, 10) + 1 : 1;
  const floor = RESERVED_FLOORS[prefix] ?? 0;
  if (seq < floor) seq = floor;
  await kv.put(key, String(seq));
  return formatId(prefix, seq);
}

/** Validate that a string matches the RCAN entity ID format. */
export function isValidId(id: string, prefix?: EntityPrefix): boolean {
  const re = prefix
    ? new RegExp(`^${prefix}-[0-9]{12}$`)
    : /^(RRN|RCN|RMN|RHN|RPN)-[0-9]{12}$/;
  return re.test(id);
}

/** Extract the prefix from an entity ID (or null if invalid). */
export function extractPrefix(id: string): EntityPrefix | null {
  const m = id.match(/^(RRN|RCN|RMN|RHN|RPN)-[0-9]{12}$/);
  return m ? (m[1] as EntityPrefix) : null;
}
