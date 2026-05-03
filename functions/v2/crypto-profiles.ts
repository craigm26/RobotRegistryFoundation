/**
 * GET /v2/crypto-profiles  (R3)
 * Plan 6 Task 5 — RCAN crypto-profile registry.
 *
 * Surfaces the named crypto profiles the protocol supports. Sourced from
 * rcan-spec §8 (crypto-profile decision).
 */

const CRYPTO_PROFILES = [
  { name: "ed25519", alg: "Ed25519", status: "current", since_version: "3.0.0" },
  { name: "ml-dsa-65-hybrid", alg: "ML-DSA-65 + Ed25519 (hybrid)", status: "future", since_version: "4.0.0" },
];

export const onRequest: PagesFunction = async ({ request }) => {
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405, headers: { "Content-Type": "application/json" },
    });
  }
  const body = {
    matrix_version: "1.0",
    profiles: CRYPTO_PROFILES,
  };
  return new Response(JSON.stringify(body), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300",
    },
  });
};
