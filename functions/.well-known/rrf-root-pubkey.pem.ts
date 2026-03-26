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
  RRF_ROOT_PUBKEY?: string;  // env var fallback for bootstrap
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { env } = context;

  // Prefer KV (runtime-rotatable), fall back to env var (set at deploy time)
  const pem = (await env.RRF_KV.get("rrf:root:pubkey", "text")) ?? env.RRF_ROOT_PUBKEY ?? null;

  if (!pem) {
    return new Response("RRF root key not provisioned", {
      status: 503,
      headers: { "Content-Type": "text/plain", "Cache-Control": "no-cache" },
    });
  }

  return new Response(pem, {
    headers: {
      "Content-Type":  "application/x-pem-file",
      "Cache-Control": "public, max-age=3600",
    },
  });
};
