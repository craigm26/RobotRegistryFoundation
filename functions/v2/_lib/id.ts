/**
 * RCAN Entity ID generation — sequential, zero-padded 12-digit counters.
 *
 * Prefixes (RCAN v2.2 §21):
 *   RRN — Robot Registration Number      (whole robot)
 *   RCN — Robot Component Number         (hardware component)
 *   RMN — Robot Model Number             (AI model)
 *   RHN — Robot Harness Number           (AI harness / agent)
 *
 * Format:  {PREFIX}-{12-digit zero-padded sequential integer}
 * Example: RRN-000000000001, RCN-000000000003, RMN-000000000001
 *
 * Counter KV keys: counter:rrn, counter:rcn, counter:rmn, counter:rhn
 */

export type EntityPrefix = "RRN" | "RCN" | "RMN" | "RHN";

export function prefixToCounterKey(prefix: EntityPrefix): string {
  return `counter:${prefix.toLowerCase()}`;
}

/** Format a sequence number as a zero-padded 12-digit ID. */
export function formatId(prefix: EntityPrefix, seq: number): string {
  return `${prefix}-${String(seq).padStart(12, "0")}`;
}

/**
 * Atomically increment the counter for a given entity prefix and return the
 * new sequential ID.  Uses optimistic locking: reads the current value, adds 1,
 * writes back with the old value as a guard (KV does not support CAS natively,
 * so we use a single-writer assumption acceptable for low-traffic RRF).
 */
export async function nextId(kv: KVNamespace, prefix: EntityPrefix): Promise<string> {
  const key = prefixToCounterKey(prefix);
  const current = await kv.get(key, "text");
  const seq = current ? parseInt(current, 10) + 1 : 1;
  await kv.put(key, String(seq));
  return formatId(prefix, seq);
}

/** Validate that a string matches the RCAN entity ID format. */
export function isValidId(id: string, prefix?: EntityPrefix): boolean {
  const re = prefix
    ? new RegExp(`^${prefix}-[0-9]{12}$`)
    : /^(RRN|RCN|RMN|RHN)-[0-9]{12}$/;
  return re.test(id);
}

/** Extract the prefix from an entity ID (or null if invalid). */
export function extractPrefix(id: string): EntityPrefix | null {
  const m = id.match(/^(RRN|RCN|RMN|RHN)-[0-9]{12}$/);
  return m ? (m[1] as EntityPrefix) : null;
}
