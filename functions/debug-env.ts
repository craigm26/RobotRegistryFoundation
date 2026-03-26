export interface Env {
  RRF_KV: KVNamespace;
  RRF_ROOT_PUBKEY?: string;
  RRF_SIGNING_KEY?: string;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { env } = context;
  return new Response(JSON.stringify({
    has_kv: !!env.RRF_KV,
    has_pubkey: !!env.RRF_ROOT_PUBKEY,
    pubkey_len: env.RRF_ROOT_PUBKEY?.length ?? 0,
    has_signing: !!env.RRF_SIGNING_KEY,
  }), { headers: { 'Content-Type': 'application/json' } });
};
