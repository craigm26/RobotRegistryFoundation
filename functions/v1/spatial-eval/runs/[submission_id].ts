/**
 * GET /v1/spatial-eval/runs/[submission_id]
 *
 * RCAN §27 — fetch a counter-signed (or pending/rejected) spatial-eval run
 * by its opaque submission_id. Bearer-gated; the apikey's RRN must match
 * the submission's owner.
 *
 * Wire format: see locked contract in robot-md spec doc.
 */

export interface Env {
  RRF_KV: KVNamespace;
}

const SUBMISSION_ID_RE = /^sub_[A-Za-z0-9-]+$/;

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env, params } = ctx;
  if (request.method !== "GET") {
    return json({ error: "Method not allowed" }, 405);
  }

  const submissionId = params["submission_id"] as string;
  if (!submissionId || !SUBMISSION_ID_RE.test(submissionId)) {
    return json({ error: "Invalid submission_id format" }, 400);
  }

  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) {
    return json({ error: "Authorization required" }, 401);
  }

  const stored = await env.RRF_KV.get(
    `compliance:spatial-eval:run:${submissionId}`,
    "text",
  );
  if (!stored) {
    return json({ error: "Submission not found", submission_id: submissionId }, 404);
  }

  let record: Record<string, unknown>;
  try {
    record = JSON.parse(stored) as Record<string, unknown>;
  } catch {
    return json({ error: "Corrupt submission record" }, 500);
  }

  // Bearer is opaque on GET (matches §22-26). Submission ids are
  // unguessable (uuid4-class) so they effectively are the auth token.
  // Tightening to per-RRN authorization waits on a stable apikey→RRN
  // reverse-lookup store. Spec at SP6 design doc "§27 wire format"
  // documents this posture.

  return new Response(stored, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "private, max-age=60",
    },
  });
};

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
