export interface RevocationEnv { RRF_KV: KVNamespace }

export async function isRevoked(env: RevocationEnv, rrn: string): Promise<boolean> {
  const raw = await env.RRF_KV.get(`revocation:${rrn}`, "text");
  return raw !== null;  // presence = revoked, regardless of content parseability
}

export async function markRevoked(env: RevocationEnv, rrn: string, reason: string): Promise<void> {
  const entry = { revoked_at: new Date().toISOString(), reason };
  await env.RRF_KV.put(`revocation:${rrn}`, JSON.stringify(entry));
}
