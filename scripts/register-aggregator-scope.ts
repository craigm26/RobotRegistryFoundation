#!/usr/bin/env tsx
/**
 * One-time idempotent: write the aggregator -> RRN scope mapping at
 *   aggregator-scope:RAN-NNN/RRN-MMM
 *
 * Usage:
 *   tsx scripts/register-aggregator-scope.ts \
 *     --aggregator-ran RAN-000000000001 \
 *     --robot-rrn RRN-000000000002 \
 *     --authorized-by RAN-000000000001 \
 *     [--valid-until 2027-05-04T00:00:00Z] \
 *     | wrangler kv:bulk put --binding RRF_KV
 */

function arg(name: string, required = true): string | undefined {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1) {
    if (required) { console.error(`Missing --${name}`); process.exit(2); }
    return undefined;
  }
  return process.argv[idx + 1];
}

const aggregatorRan = arg("aggregator-ran")!;
const robotRrn = arg("robot-rrn")!;
const authorizedBy = arg("authorized-by")!;
const validUntil = arg("valid-until", false);

const scope: Record<string, unknown> = {
  ran: aggregatorRan,
  rrn: robotRrn,
  authorized_at: new Date().toISOString(),
  authorized_by: authorizedBy,
};
if (validUntil) scope["valid_until"] = validUntil;

const bulkInput = [{
  key: `aggregator-scope:${aggregatorRan}/${robotRrn}`,
  value: JSON.stringify(scope),
}];

process.stdout.write(JSON.stringify(bulkInput, null, 2));
