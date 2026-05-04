#!/usr/bin/env tsx
/**
 * Generate a cert-rig:<kid>:<registered_at> KV record for `wrangler kv bulk put`.
 *
 * Plan 6 Phase 4 — registers a HIL rig kid so cert-intake POST can resolve
 * its sigs. Mirrors register-aggregator-kid.ts (Plan 4) shape.
 *
 * Usage:
 *   tsx scripts/register-cert-rig.ts \
 *     --kid bob-rig-2026 \
 *     --rrn RRN-000000000002 \
 *     --signing-pub-b64 <ed25519-raw-pubkey-base64> \
 *     [--rig-id bob] \
 *     [--valid-until 2027-05-04T00:00:00Z] \
 *     > rig.json
 *   wrangler kv:bulk put --binding RRF_KV rig.json
 */

import { parseArgs } from "node:util";
import { writeFileSync } from "node:fs";

const { values } = parseArgs({
  options: {
    kid: { type: "string" },
    rrn: { type: "string" },
    "signing-pub-b64": { type: "string" },
    "rig-id": { type: "string" },
    "valid-until": { type: "string" },
    out: { type: "string" },
  },
});

const kid = values.kid;
const rrn = values.rrn;
const signingPub = values["signing-pub-b64"];
if (!kid || !rrn || !signingPub) {
  console.error("error: --kid, --rrn, --signing-pub-b64 are required");
  process.exit(2);
}
if (!/^RRN-\d{12}$/.test(rrn)) {
  console.error(`error: --rrn must match RRN-NNNNNNNNNNNN; got ${rrn}`);
  process.exit(2);
}

const rigId = values["rig-id"] ?? kid.split("-")[0];
const registeredAt = new Date().toISOString();
const mapping = {
  rig_id: rigId,
  rrn,
  signing_pub: signingPub,
  valid_from: registeredAt,
  valid_until: values["valid-until"],
  registered_at: registeredAt,
};

const bulkRecord = [{
  key: `cert-rig:${kid}:${registeredAt}`,
  value: JSON.stringify(mapping),
}];

const out = JSON.stringify(bulkRecord, null, 2);
if (values.out) {
  writeFileSync(values.out, out);
  console.error(`wrote ${values.out}`);
} else {
  process.stdout.write(out + "\n");
}
