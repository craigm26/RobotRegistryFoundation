#!/usr/bin/env tsx
/**
 * One-time idempotent: write the kid -> RAN mapping at
 *   kid:<kid>:<registered_at>
 *
 * Usage (read REGIST args from CLI):
 *   tsx scripts/register-aggregator-kid.ts \
 *     --kid ops-aggregator-2026-05 \
 *     --ran RAN-000000000001 \
 *     --valid-from 2026-05-04T00:00:00Z \
 *     [--valid-until 2027-05-04T00:00:00Z] \
 *     --registered-by RAN-000000000001 \
 *     | wrangler kv:bulk put --binding RRF_KV
 */

function arg(name: string, required = true): string | undefined {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1) {
    if (required) {
      console.error(`Missing --${name}`);
      process.exit(2);
    }
    return undefined;
  }
  return process.argv[idx + 1];
}

const kid = arg("kid")!;
const ran = arg("ran")!;
const validFrom = arg("valid-from")!;
const validUntil = arg("valid-until", false);
const registeredBy = arg("registered-by")!;
const registeredAt = new Date().toISOString();

const mapping: Record<string, unknown> = {
  ran,
  valid_from: validFrom,
  registered_at: registeredAt,
  registered_by: registeredBy,
};
if (validUntil) mapping["valid_until"] = validUntil;

const bulkInput = [{
  key: `kid:${kid}:${registeredAt}`,
  value: JSON.stringify(mapping),
}];

process.stdout.write(JSON.stringify(bulkInput, null, 2));
