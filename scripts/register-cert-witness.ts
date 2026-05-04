/**
 * Generate a cert-witness:<kid>:<registered_at> KV record for `wrangler kv bulk put`.
 *
 * Plan 6 Phase 4 — registers a HIL witness kid paired with a specific rig.
 *
 * Usage:
 *   tsx scripts/register-cert-witness.ts \
 *     --kid witness-bob-craigm \
 *     --witness-id craigm \
 *     --rig-id bob \
 *     --signing-pub-b64 <ed25519-raw-pubkey-base64> \
 *     [--valid-until 2027-05-04T00:00:00Z] \
 *     > witness.json
 *   wrangler kv bulk put --namespace-id <NS_ID> witness.json
 */

import { parseArgs } from "node:util";
import { writeFileSync } from "node:fs";

const { values } = parseArgs({
  options: {
    kid: { type: "string" },
    "witness-id": { type: "string" },
    "rig-id": { type: "string" },
    "signing-pub-b64": { type: "string" },
    "valid-until": { type: "string" },
    out: { type: "string" },
  },
});

const kid = values.kid;
const witnessId = values["witness-id"];
const rigId = values["rig-id"];
const signingPub = values["signing-pub-b64"];
if (!kid || !witnessId || !rigId || !signingPub) {
  console.error("error: --kid, --witness-id, --rig-id, --signing-pub-b64 are required");
  process.exit(2);
}

const registeredAt = new Date().toISOString();
const mapping = {
  witness_id: witnessId,
  rig_id: rigId,
  signing_pub: signingPub,
  valid_from: registeredAt,
  valid_until: values["valid-until"],
  registered_at: registeredAt,
};

const bulkRecord = [{
  key: `cert-witness:${kid}:${registeredAt}`,
  value: JSON.stringify(mapping),
}];

const out = JSON.stringify(bulkRecord, null, 2);
if (values.out) {
  writeFileSync(values.out, out);
  console.error(`wrote ${values.out}`);
} else {
  process.stdout.write(out + "\n");
}
