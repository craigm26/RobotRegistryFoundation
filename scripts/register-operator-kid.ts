#!/usr/bin/env tsx
/**
 * Generate a kid:<kid>:<registered_at> + authority:<ran> KV record pair for
 * `wrangler kv bulk put`.
 *
 * Plan 6 Phase 5 addendum — registers a hybrid Ed25519 + ML-DSA-65 operator kid
 * (e.g., bob-operator-2026 → RAN-000000000019) so /v2/keys/<kid> can resolve
 * envelope signatures against it.
 *
 * Mirrors register-aggregator-kid.ts shape; adds authority-record fields per
 * the AuthorityRecord type in functions/v2/_lib/types.ts.
 *
 * Usage:
 *   tsx scripts/register-operator-kid.ts \
 *     --kid bob-operator-2026 \
 *     --ran RAN-000000000019 \
 *     --signing-pub-b64 <ed25519-raw-32-byte-b64> \
 *     --pq-signing-pub-b64 <ml-dsa-65-raw-1952-byte-b64> \
 *     --pq-kid <8-hex sha256(pq-pub)[:8]> \
 *     --organization OpenCastor \
 *     --display-name "bob-operator-2026 — Phase 5 INVOKE signer for Bob" \
 *     --purpose operator-envelope \
 *     --registered-by RAN-000000000018 \
 *     --valid-from 2026-05-04T15:00:00Z \
 *     [--valid-until 2027-05-04T00:00:00Z] \
 *     [--out /tmp/operator-kid.json]
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

function fail(msg: string): never {
  console.error(`error: ${msg}`);
  process.exit(2);
}

const kid = arg("kid")!;
const ran = arg("ran")!;
const signingPubB64 = arg("signing-pub-b64")!;
const pqSigningPubB64 = arg("pq-signing-pub-b64")!;
const pqKid = arg("pq-kid")!;
const organization = arg("organization")!;
const displayName = arg("display-name")!;
const purpose = arg("purpose")!;
const registeredBy = arg("registered-by")!;
const validFrom = arg("valid-from")!;
const validUntil = arg("valid-until", false);
const out = arg("out", false);

if (!/^RAN-\d{12}$/.test(ran)) fail(`--ran must match RAN-NNNNNNNNNNNN; got ${ran}`);
if (!/^RAN-\d{12}$/.test(registeredBy)) fail(`--registered-by must match RAN-NNNNNNNNNNNN; got ${registeredBy}`);
if (!/^[0-9a-f]{8}$/.test(pqKid)) fail(`--pq-kid must be 8 hex chars; got ${pqKid}`);

let edBytes: Buffer;
try { edBytes = Buffer.from(signingPubB64, "base64"); } catch { fail("--signing-pub-b64 is not valid base64"); }
if (edBytes.length !== 32) fail(`--signing-pub-b64 must decode to 32 bytes (Ed25519); got ${edBytes.length}`);

let pqBytes: Buffer;
try { pqBytes = Buffer.from(pqSigningPubB64, "base64"); } catch { fail("--pq-signing-pub-b64 is not valid base64"); }
if (pqBytes.length !== 1952) fail(`--pq-signing-pub-b64 must decode to 1952 bytes (ML-DSA-65); got ${pqBytes.length}`);

const registeredAt = new Date().toISOString();

const kidMapping: Record<string, unknown> = {
  ran,
  valid_from: validFrom,
  registered_at: registeredAt,
  registered_by: registeredBy,
};
if (validUntil) kidMapping["valid_until"] = validUntil;

const authority: Record<string, unknown> = {
  ran,
  organization,
  display_name: displayName,
  purpose,
  signing_pub: signingPubB64,
  pq_signing_pub: pqSigningPubB64,
  pq_kid: pqKid,
  signing_alg: ["Ed25519", "ML-DSA-65"],
  registered_at: registeredAt,
  status: "active",
};

const bulkRecord = [
  { key: `kid:${kid}:${registeredAt}`, value: JSON.stringify(kidMapping) },
  { key: `authority:${ran}`, value: JSON.stringify(authority) },
];

const text = JSON.stringify(bulkRecord, null, 2);
if (out) {
  const { writeFileSync } = await import("node:fs");
  writeFileSync(out, text);
  console.error(`wrote ${out}`);
} else {
  process.stdout.write(text + "\n");
}
