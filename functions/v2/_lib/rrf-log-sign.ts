/**
 * Sign a transparency-log entry with the RRF root Ed25519 key.
 *
 * KV layout:
 *   rrf:root:privkey  -> base64 PKCS8 DER (set via wrangler kv:key put)
 *   rrf:root:pubkey   -> PEM (existing; served by .well-known/rrf-root-pubkey.pem)
 *
 * Used by compliance-bundle POST to bind the public proof to the RRF
 * authority. Signature is over canonicalJson(entry) — the entry shape
 * MUST match what the proof endpoint returns.
 */

import { canonicalJson } from "rcan-ts";

export interface RrfLogSignature {
  kid: "rrf-root";
  alg: "Ed25519";
  sig: string;  // base64 standard
}

export async function signLogEntry(
  env: { RRF_KV: KVNamespace },
  entry: Record<string, unknown>,
): Promise<RrfLogSignature> {
  const privB64 = await env.RRF_KV.get("rrf:root:privkey", "text");
  if (!privB64) {
    throw new Error("rrf:root:privkey not configured (run scripts/init-rrf-log-signing-key.ts)");
  }

  const privBytes = Uint8Array.from(atob(privB64.trim()), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "pkcs8", privBytes, { name: "Ed25519" }, false, ["sign"],
  );

  const canon = canonicalJson(entry);
  const sigBuffer = await crypto.subtle.sign("Ed25519", key, canon);
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)));

  return { kid: "rrf-root", alg: "Ed25519", sig };
}
