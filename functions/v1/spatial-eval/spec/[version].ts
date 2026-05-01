/**
 * GET /v1/spatial-eval/spec/[version]
 *
 * RCAN §27 — canonical spec metadata for a given spec version, including
 * the RRF spatial-eval ML-DSA-65 public key. Verifiers (e.g.
 * `robot_md.spatial_eval.verify_tool`) fetch the pubkey from here to
 * verify the `rrf_signature` on counter-signed scores. Pinned per spec
 * version so a key rotation requires a minor version bump and is
 * auditable in the leaderboard timeline.
 *
 * Pubkey registry is committed at functions/v1/spatial-eval/_lib/rrf_pubkey.json
 * — public information, never the private key.
 */

import { RRF_SPATIAL_EVAL_PUBKEYS } from "../_lib/rrf_pubkey.js";

const VERSION_RE = /^\d+\.\d+\.\d+$/;

export const onRequest: PagesFunction = async (ctx) => {
  const { request, params } = ctx;
  if (request.method !== "GET") {
    return json({ error: "Method not allowed" }, 405);
  }

  const version = params["version"] as string;
  if (!version || !VERSION_RE.test(version)) {
    return json({ error: "Invalid spec version format" }, 400);
  }

  const entry = RRF_SPATIAL_EVAL_PUBKEYS[version];
  if (!entry) {
    return json(
      {
        error: "Spec version not registered",
        version,
        available: Object.keys(RRF_SPATIAL_EVAL_PUBKEYS),
      },
      404,
    );
  }

  return json(
    {
      spec_version: version,
      rrf_pubkey: entry.pubkey,
      rrf_pubkey_alg: entry.alg,
      rrf_pubkey_generated_at: entry.generated_at,
      leaderboard_url: `https://robotregistryfoundation.org/leaderboard/spatial-eval/${version}`,
    },
    200,
    { "Cache-Control": "public, max-age=3600" },
  );
};

function json(
  body: unknown,
  status: number,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}
