/**
 * Record-redaction helper.
 *
 * The stored robot record includes fields that are secrets or server-internal
 * (notably `api_key` — a bearer token used for PATCH/DELETE authentication).
 * Responses that echo the record must strip these before returning, especially
 * for endpoints reachable without auth (GET).
 *
 * Do NOT use this on the object that gets written to KV — only on the object
 * that goes into the HTTP response body.
 */
export function redactRobotRecord<T extends Record<string, unknown>>(record: T): Omit<T, "api_key"> {
  const { api_key, ...rest } = record as T & { api_key?: unknown };
  void api_key;
  return rest as Omit<T, "api_key">;
}
