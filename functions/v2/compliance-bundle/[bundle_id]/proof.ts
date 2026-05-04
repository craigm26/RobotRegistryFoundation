/**
 * GET /v2/compliance-bundle/{bundle_id}/proof
 *
 * Public, no auth. Returns the metadata-only ComplianceBundleEntry shape:
 * everything except the artifact bodies. Verifiable offline via:
 *   1. Fetch this proof.
 *   2. Fetch /.well-known/rrf-root-pubkey.pem.
 *   3. Verify rrf_log_signature against the canonical entry bytes.
 *
 * Optionally also verify bundle_signature against the kid-mapped aggregator
 * pubkey (kid resolve via the public kid:* index).
 */

export interface Env {
  RRF_KV: KVNamespace;
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env, "bundle_id"> = async ({ env, params }) => {
  const bundleId = params["bundle_id"] as string;
  if (!bundleId || !bundleId.startsWith("bundle_")) {
    return json({ error: "bundle_id missing or malformed" }, 400);
  }

  // Locate the log-index key for this bundle_id by scanning the index keys.
  // For O(1) retrieval we'd add a bundle_id -> index mapping; for v1 the scan
  // is acceptable at current traffic.
  const list = await env.RRF_KV.list({ prefix: "compliance-bundle-log:" });
  for (const k of list.keys) {
    const raw = await env.RRF_KV.get(k.name, "text");
    if (!raw) continue;
    let entry: { bundle_id?: string };
    try { entry = JSON.parse(raw) as { bundle_id?: string }; }
    catch { continue; }
    if (entry.bundle_id === bundleId) {
      return json(entry, 200);
    }
  }

  return json({ error: `bundle ${bundleId} not found in transparency log` }, 404);
};
