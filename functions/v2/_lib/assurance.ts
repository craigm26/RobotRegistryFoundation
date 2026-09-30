/**
 * Physical assurance fields on a robot record (RCAN Appendix C, informative).
 *
 * Three optional, owner-supplied fields:
 *   assurance_level         "A1" | "A2" | "A3"
 *   envelope_hash           "sha256:<64 hex>" of the robot's declared envelope
 *   assurance_evidence_url  https URL of third-party evidence
 *
 * RRF stores what the owner declares. It does not test robots, fetch or review
 * the evidence, or verify the envelope. The response says so on every record:
 *   - A1 and A2 are always presented as self-declared.
 *   - A3 is presented only when an evidence URL is present. Without one the
 *     presented level is null and the claim is shown as not displayed.
 * A-levels are independent of RCAN protocol conformance levels L1–L4.
 */

export const ASSURANCE_LEVELS = ["A1", "A2", "A3"] as const;
export type AssuranceLevel = typeof ASSURANCE_LEVELS[number];

export const ASSURANCE_FIELDS = ["assurance_level", "envelope_hash", "assurance_evidence_url"] as const;

const ENVELOPE_HASH_RE = /^sha256:[0-9a-f]{64}$/;

export const ASSURANCE_NOTE =
  "Self-declared by the robot owner. RRF does not test robots and has not reviewed any linked evidence. " +
  "Physical assurance levels A1–A3 are independent of RCAN conformance levels L1–L4. " +
  "Conformance is not certification.";

export const ASSURANCE_SPEC_URL =
  "https://github.com/RobotRegistryFoundation/rcan-spec/blob/master/spec/appendix-c-physical-assurance.md";

export interface AssuranceView {
  level: AssuranceLevel | null;
  claimed_level: AssuranceLevel;
  basis: "self-declared" | "self-declared, third-party evidence linked";
  envelope_hash: string | null;
  evidence_url: string | null;
  displayed: boolean;
  reason_not_displayed?: string;
  note: string;
  spec: string;
}

function isHttpsUrl(v: string): boolean {
  try { return new URL(v).protocol === "https:"; } catch { return false; }
}

/**
 * Validate the assurance fields of a record as it would be stored.
 * Returns an error message, or null when valid. Absent fields are valid.
 */
export function validateAssurance(rec: Record<string, unknown>): string | null {
  const level = rec.assurance_level;
  const hash = rec.envelope_hash;
  const url = rec.assurance_evidence_url;

  if (level !== undefined && !(ASSURANCE_LEVELS as readonly unknown[]).includes(level)) {
    return "assurance_level must be one of A1, A2, A3 (physical assurance; not an RCAN L-level)";
  }
  if (hash !== undefined && (typeof hash !== "string" || !ENVELOPE_HASH_RE.test(hash))) {
    return "envelope_hash must be sha256:<64 lowercase hex>";
  }
  if (url !== undefined && (typeof url !== "string" || url.length > 2048 || !isHttpsUrl(url))) {
    return "assurance_evidence_url must be an https URL";
  }
  if ((hash !== undefined || url !== undefined) && level === undefined) {
    return "envelope_hash and assurance_evidence_url require assurance_level";
  }
  if (level === "A3" && url === undefined) {
    return "assurance_level A3 requires assurance_evidence_url (third-party evidence)";
  }
  return null;
}

/** Pick the assurance fields present in a request body. null means "clear". */
export function pickAssurance(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of ASSURANCE_FIELDS) if (k in body) out[k] = body[k];
  return out;
}

/** Response view. Returns null when the record declares no assurance level. */
export function presentAssurance(rec: Record<string, unknown>): AssuranceView | null {
  const claimed = rec.assurance_level;
  if (!(ASSURANCE_LEVELS as readonly unknown[]).includes(claimed)) return null;
  const level = claimed as AssuranceLevel;
  const url = typeof rec.assurance_evidence_url === "string" && isHttpsUrl(rec.assurance_evidence_url)
    ? rec.assurance_evidence_url : null;
  const hash = typeof rec.envelope_hash === "string" && ENVELOPE_HASH_RE.test(rec.envelope_hash)
    ? rec.envelope_hash : null;
  const displayed = level !== "A3" || url !== null;

  const view: AssuranceView = {
    level: displayed ? level : null,
    claimed_level: level,
    basis: url ? "self-declared, third-party evidence linked" : "self-declared",
    envelope_hash: hash,
    evidence_url: url,
    displayed,
    note: ASSURANCE_NOTE,
    spec: ASSURANCE_SPEC_URL,
  };
  if (!displayed) view.reason_not_displayed = "A3 is shown only when a third-party evidence URL is present";
  return view;
}
