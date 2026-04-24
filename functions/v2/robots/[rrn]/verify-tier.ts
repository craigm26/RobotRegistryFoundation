/**
 * POST /v2/robots/:rrn/verify-tier
 *
 * Promotes a robot's verification_status to manufacturer_claimed or
 * manufacturer_verified. community tier is NOT promotable via this endpoint —
 * it is maintainer-curated via PR against src/content/robots/<slug>.json, per
 * rcan-spec/docs/verification/manufacturer-verification.md.
 *
 * Request is signed with the robot's current pq_signing_pub. The outer sig is
 * verified, tier progression enforced (no downgrades), then the appropriate
 * verifier(s) run:
 *   - manufacturer_claimed: DNS TXT verifier only.
 *   - manufacturer_verified: DNS TXT + signed attestation + RURI manifest.
 *
 * The DNS and attestation verifiers are injectable via ctx.verifiers for tests.
 */

import { isValidId } from "../../_lib/id.js";
import { verifyBody } from "rcan-ts";
import { isRevoked } from "../../_lib/revocation.js";
import { verifyDnsTxt } from "../../_lib/dns-verify.js";
import { verifyAttestation } from "../../_lib/attestation-verify.js";
import { redactRobotRecord } from "../../_lib/redact.js";

export interface Env { RRF_KV: KVNamespace }

type DnsVerifierFn = typeof verifyDnsTxt;
type AttestationVerifierFn = typeof verifyAttestation;
interface Verifiers { dns: DnsVerifierFn; attestation: AttestationVerifierFn }

const TIER_RANK: Record<string, number> = {
  unverified: 0,
  community: 1,
  manufacturer_claimed: 2,
  manufacturer_verified: 3,
};
type Tier = keyof typeof TIER_RANK;

function err(msg: string, status: number): Response {
  return new Response(JSON.stringify({ error: msg }), {
    status, headers: { "Content-Type": "application/json" },
  });
}

export const onRequestPost: PagesFunction<Env> = async (ctx) => {
  const { request, env, params } = ctx;
  const verifiers: Verifiers = (ctx as any).verifiers ?? { dns: verifyDnsTxt, attestation: verifyAttestation };
  const rrn = params.rrn as string;

  if (!isValidId(rrn, "RRN")) return err("Invalid RRN format", 400);

  let body: any;
  try { body = await request.json(); }
  catch { return err("Invalid JSON body", 400); }

  if (body?.action !== "verify-tier" || body?.rrn !== rrn) {
    return err("Body must bind rrn and action:verify-tier", 400);
  }

  const targetTier = body?.target_tier;
  if (targetTier === "community") {
    return err("community tier is maintainer-curated (not promotable via API)", 400);
  }
  if (targetTier !== "manufacturer_claimed" && targetTier !== "manufacturer_verified") {
    return err("target_tier must be manufacturer_claimed or manufacturer_verified", 400);
  }

  const binding = body?.binding;
  if (!binding || binding.type !== "dns-txt" || typeof binding.value !== "string") {
    return err("binding must be {type:'dns-txt', value:<domain>}", 400);
  }

  if (targetTier === "manufacturer_verified") {
    if (typeof body?.ruri !== "string" || !body?.attestation || typeof body.attestation !== "object") {
      return err("manufacturer_verified requires ruri + attestation", 400);
    }
  }

  const stored = await env.RRF_KV.get(`robot:${rrn}`, "text");
  if (!stored) return err("Not found", 404);

  if (await isRevoked(env, rrn)) return err("Record is revoked", 403);

  const record = JSON.parse(stored);
  const pqPubB64 = record.pq_signing_pub;
  if (typeof pqPubB64 !== "string") return err("Record has no registered key", 400);

  let sigOk = false;
  try {
    const pub = Uint8Array.from(atob(pqPubB64), (c) => c.charCodeAt(0));
    sigOk = await verifyBody(body, pub);
  } catch { /* sigOk stays false */ }
  if (!sigOk) return err("Signature verification failed", 401);

  const currentTier = record.verification_status ?? "unverified";
  const currentRank = TIER_RANK[currentTier];
  if (currentRank === undefined) {
    return err(`Record has unrecognized verification_status: ${currentTier}`, 409);
  }
  const targetRank = TIER_RANK[targetTier];  // already validated to be a known tier string above
  if (targetRank <= currentRank) return err("Cannot downgrade or stay at current tier", 400);

  const dns = await verifiers.dns(binding.value, rrn, record.model);
  if (!dns.ok) return err(`DNS verification failed: ${dns.error}`, 400);

  let attestationEvidence: { attestation_digest: string; ruri_matched: string } | undefined;
  if (targetTier === "manufacturer_verified") {
    // Bind the attestation to the registered key.
    if (body.attestation.pq_kid !== record.pq_kid) {
      return err("attestation.pq_kid does not match record.pq_kid", 400);
    }
    const att = await verifiers.attestation({
      attestation: body.attestation,
      ruri: body.ruri,
      pqPubB64,
      expectedRrn: rrn,
      expectedModel: record.model,
    });
    if (!att.ok) return err(`Attestation verification failed: ${att.error}`, 400);
    attestationEvidence = att.evidence;
  }

  const now = new Date().toISOString();
  record.verification_status = targetTier;
  record.identity_binding = {
    type: "dns-txt",
    value: binding.value,
    verified_at: now,
    verifier_evidence: attestationEvidence
      ? `dns=${dns.evidence}; ruri=${attestationEvidence.ruri_matched}; attestation=${attestationEvidence.attestation_digest}`
      : `dns=${dns.evidence}`,
  };
  record.updated_at = now;
  await env.RRF_KV.put(`robot:${rrn}`, JSON.stringify(record));
  return new Response(JSON.stringify(redactRobotRecord(record)), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
};
