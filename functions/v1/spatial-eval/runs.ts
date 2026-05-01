/**
 * POST /v1/spatial-eval/runs
 *
 * RCAN §27 — Spatial Intelligence Eval submission intake.
 *
 * The robot uploads a self-attested Score JSON; RRF verifies the robot's
 * `rcan_signature`, counter-signs the score with the RRF spatial-eval
 * keypair, stores the result, and returns the counter-signed score
 * synchronously. Robot-md `submit_to_rrf` consumes this directly.
 *
 * Wire-format contract: see robot-md
 * docs/superpowers/specs/2026-04-26-sp6-spatial-intelligence-eval-design.md
 * "§27 wire format" subsection.
 *
 * KV layout:
 *   compliance:spatial-eval:run:{submission_id}            10y TTL
 *   compliance:spatial-eval:by_rrn:{rrn}:{run_id}          dedup index, 10y TTL
 */

import { verifyRobotScoreSignature } from "./_lib/score-auth.js";
import { counterSignScore, type SignEnv } from "./_lib/score-sign.js";

export interface Env extends SignEnv {
  RRF_KV: KVNamespace;
}

const TEN_YEARS_SECS = 10 * 365 * 24 * 3600;

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;
  if (request.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const score = body["score"];
  if (!score || typeof score !== "object") {
    return json({ error: "Missing 'score' object in request body" }, 400);
  }

  const verifyResult = await verifyRobotScoreSignature(
    score as Record<string, unknown>,
    env,
  );
  if (!verifyResult.ok) {
    return json({ error: verifyResult.error }, verifyResult.status);
  }

  const verifiedScore = verifyResult.score;
  const rrn = verifiedScore["rrn"] as string;
  const runId = verifiedScore["run_id"];
  if (typeof runId !== "string" || runId.length === 0) {
    return json({ error: "Score missing run_id" }, 400);
  }

  const dedupKey = `compliance:spatial-eval:by_rrn:${rrn}:${runId}`;
  const existingId = await env.RRF_KV.get(dedupKey, "text");
  if (existingId) {
    return json(
      { error: "Already submitted", submission_id: existingId, run_id: runId },
      409,
    );
  }

  let counterSigned: Record<string, unknown>;
  try {
    counterSigned = counterSignScore(verifiedScore, env);
  } catch (err) {
    return json(
      { error: `RRF signing unavailable: ${(err as Error).message}` },
      500,
    );
  }

  const submissionId = `sub_${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  const stored = JSON.stringify({
    submission_id: submissionId,
    rrn,
    run_id: runId,
    status: "counter_signed",
    score: counterSigned,
    submitted_at: now,
  });

  await env.RRF_KV.put(
    `compliance:spatial-eval:run:${submissionId}`,
    stored,
    { expirationTtl: TEN_YEARS_SECS },
  );
  await env.RRF_KV.put(dedupKey, submissionId, {
    expirationTtl: TEN_YEARS_SECS,
  });

  return json(
    {
      submission_id: submissionId,
      status: "counter_signed",
      score: counterSigned,
      submitted_at: now,
    },
    200,
  );
};

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
