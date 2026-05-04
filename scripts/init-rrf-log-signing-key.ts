#!/usr/bin/env tsx
/**
 * One-time bootstrap: mint the RRF root signing keypair (Ed25519),
 * write priv to rrf:root:privkey, write pub to rrf:root:pubkey.
 *
 * NOT IDEMPOTENT: every run mints a fresh keypair. Re-running after
 * production bootstrap overwrites the root key, breaking ALL prior
 * M2M_TRUSTED JWTs (instant invalidation) and ALL prior compliance-bundle
 * proof verifications (rrf_log_signature continuity broken). The operator
 * MUST precheck before piping output to wrangler:
 *
 *   wrangler kv:key get --binding RRF_KV "rrf:root:privkey"  # MUST be empty
 *   tsx scripts/init-rrf-log-signing-key.ts | wrangler kv:bulk put --binding RRF_KV
 */

import { writeFileSync } from "node:fs";

async function main() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const privDer = await crypto.subtle.exportKey("pkcs8", (kp as CryptoKeyPair).privateKey);
  const pubDer = await crypto.subtle.exportKey("spki", (kp as CryptoKeyPair).publicKey);
  const b64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));
  const privB64 = b64(privDer);
  const pubB64 = b64(pubDer);
  const pubPem = `-----BEGIN PUBLIC KEY-----\n${pubB64}\n-----END PUBLIC KEY-----\n`;

  const bulkInput = [
    { key: "rrf:root:privkey", value: privB64 },
    { key: "rrf:root:pubkey", value: pubPem },
  ];

  // Print to stdout for piping to wrangler kv:bulk put.
  process.stdout.write(JSON.stringify(bulkInput, null, 2));

  // Also save the privkey locally for offline backup (encrypted in 1Password
  // post-bootstrap; delete the local file once archived).
  writeFileSync("/tmp/rrf-root-privkey.b64", privB64, { mode: 0o600 });
  process.stderr.write("\nLocal backup written to /tmp/rrf-root-privkey.b64 (mode 0600).\n");
  process.stderr.write("Archive to 1Password and DELETE the local file.\n");
}

main().catch(err => { console.error(err); process.exit(1); });
