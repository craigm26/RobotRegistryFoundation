/**
 * GET /.well-known/rrf-root-pubkey.pem
 * RCAN v2.1 §2.9 — RRF root Ed25519 public key.
 *
 * Published at a stable URL. Used by robots to verify M2M_TRUSTED JWT signatures.
 * Rotated annually; old key retained for 90-day grace period.
 *
 * KV key: rrf:root:pubkey (PEM string, set via wrangler kv:key put)
 */

export interface Env {
  RRF_KV: KVNamespace;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { env } = context;

  const pem = await env.RRF_KV.get("rrf:root:pubkey", "text");

  if (!pem) {
    // Return placeholder during bootstrap (before key is provisioned)
    const placeholder =
      "-----BEGIN PUBLIC KEY-----\n" +
      "# RRF root Ed25519 key not yet provisioned.\n" +
      "# Run: wrangler kv:key put --binding RRF_KV rrf:root:pubkey '<pem>'\n" +
      "-----END PUBLIC KEY-----\n";
    return new Response(placeholder, {
      headers: { "Content-Type": "application/x-pem-file", "Cache-Control": "no-cache" },
    });
  }

  return new Response(pem, {
    headers: {
      "Content-Type":  "application/x-pem-file",
      "Cache-Control": "public, max-age=3600",
    },
  });
};
