/**
 * Ed25519 raw 32-byte public key → PKIX SubjectPublicKeyInfo PEM.
 *
 * RFC 8410 §4 specifies Ed25519 SPKI as a 12-byte DER prefix followed by
 * the 32-byte raw key:
 *   30 2A 30 05 06 03 2B 65 70 03 21 00 || raw[32]
 *
 * This is the exact shape Python's `cryptography.hazmat.primitives.serialization
 * .load_pem_public_key()` expects for Ed25519 — confirmed by the deployed
 * gateway's RRFResolverFromEnv code path.
 */

export const PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
export const PEM_FOOTER = "-----END PUBLIC KEY-----";

const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export function ed25519RawToPem(raw: Uint8Array): string {
  if (raw.length !== 32) {
    throw new Error(`Ed25519 raw pubkey must be 32 bytes, got ${raw.length}`);
  }
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + raw.length);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(raw, ED25519_SPKI_PREFIX.length);
  // Cloudflare Workers: btoa expects a binary string; build it from bytes.
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  // Standard PEM line-wrap at 64 chars (44 bytes → ~60 chars b64; one line is fine,
  // but wrap defensively for any future caller passing larger inputs).
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `${PEM_HEADER}\n${lines.join("\n")}\n${PEM_FOOTER}\n`;
}
