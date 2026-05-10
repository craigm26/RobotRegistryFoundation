import { canonicalJson } from "rcan-ts";

export async function computeRunId(body: Record<string, unknown>): Promise<string> {
  const { sig: _drop1, run_id: _drop2, ...rest } = body;
  const canonBytes = canonicalJson(rest);
  const digest = await crypto.subtle.digest("SHA-256", canonBytes as unknown as BufferSource);
  const hex = [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  return `runbundle_${hex.slice(0, 12)}`;
}
