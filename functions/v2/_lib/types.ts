/**
 * RCAN Registry entity types — v2.2
 *
 * All entities are persisted in KV under:
 *   robot:{RRN}       → RobotRecord
 *   component:{RCN}   → ComponentRecord
 *   model:{RMN}       → ModelRecord
 *   harness:{RHN}     → HarnessRecord
 */

// ── Whole Robot ───────────────────────────────────────────────────────────────
export interface RobotRecord {
  rrn: string;
  name: string;
  manufacturer: string;
  model: string;
  firmware_version: string;
  rcan_version: string;            // "2.2"
  pq_signing_pub?: string;         // ML-DSA-65 public key (base64)
  pq_kid?: string;                 // key ID (8-char hex)
  ruri?: string;                   // rcan:// URI
  owner_uid?: string;              // Firebase UID of owner
  registered_at: string;           // ISO timestamp
  updated_at?: string;
  loa_enforcement?: boolean;
  components?: string[];           // RCN[] minted server-side pointing at this RRN
  // v1.10.0 — operator-declared RCAN §21 sibling IDs (from manifest metadata).
  // Independent from `components` (server-side mint tracking): these are what
  // the operator SAYS this robot is made of, captured at register time and
  // signed alongside the rest of the MintRequest body.
  rcn_ids?: string[];
  rmn?: string;
  rhn_ids?: string[];
}

// ── Hardware Component ────────────────────────────────────────────────────────
export type ComponentType =
  | "cpu" | "npu" | "gpu" | "camera" | "lidar" | "imu"
  | "actuator" | "sensor" | "battery" | "communication" | "other";

export interface ComponentRecord {
  rcn: string;
  parent_rrn: string;              // Robot that owns this component
  type: ComponentType;
  model: string;
  manufacturer: string;
  firmware_version?: string;
  serial_number?: string;
  capabilities?: string[];         // e.g. ["rgb", "depth", "npu:hailo8l"]
  specs?: Record<string, unknown>; // free-form hardware specs
  pq_signing_pub?: string;         // ML-DSA-65 public key (base64). Mandatory on register since v1.9.0.
  pq_kid?: string;                 // sha256(pq_signing_pub)[:8] hex. Mandatory on register since v1.9.0.
  registered_at: string;
}

// ── AI Model ─────────────────────────────────────────────────────────────────
export type ModelFamily =
  | "vision" | "language" | "multimodal" | "vla" | "embedding"
  | "reward" | "world_model" | "diffusion" | "other";

export type ModelQuantization =
  | "fp32" | "fp16" | "bf16" | "int8" | "int4" | "gguf" | "bnb4" | "other";

export interface ModelRecord {
  rmn: string;
  name: string;
  version: string;
  model_family: ModelFamily;
  architecture?: string;           // "transformer", "jepa", "cnn", etc.
  parameter_count_b?: number;      // billions
  quantization?: ModelQuantization;
  license?: string;                // "apache-2.0", "mit", "cc-by-4.0", "proprietary"
  provider?: string;               // "huggingface", "ollama", "openai", "anthropic", "local"
  provider_model_id?: string;      // e.g. "meta-llama/Llama-3-8B-Instruct"
  repo_url?: string;
  rcan_compatible?: boolean;
  compatible_harness_ids?: string[]; // RHN[]
  pq_signing_pub?: string;         // ML-DSA-65 public key (base64). Mandatory on register since v1.9.0.
  pq_kid?: string;                 // sha256(pq_signing_pub)[:8] hex. Mandatory on register since v1.9.0.
  registered_at: string;
  owner_uid?: string;
}

// ── AI Harness ────────────────────────────────────────────────────────────────
export type HarnessType =
  | "vla" | "llm_planner" | "multimodal" | "hybrid"
  | "specialist" | "safety_monitor" | "orchestrator" | "other";

export interface HarnessRecord {
  rhn: string;
  name: string;
  version: string;
  harness_type: HarnessType;
  rcan_version: string;            // minimum RCAN version required
  description?: string;
  model_ids?: string[];            // RMN[] of models used
  compatible_robots?: string[];    // RRN[] (empty = universal)
  open_source?: boolean;
  repo_url?: string;
  license?: string;
  pq_signing_pub?: string;         // ML-DSA-65 public key (base64). Mandatory on register since v1.9.0.
  pq_kid?: string;                 // sha256(pq_signing_pub)[:8] hex. Mandatory on register since v1.9.0.
  registered_at: string;
  owner_uid?: string;
}

// ── Robot Authority Number ────────────────────────────────────────────────────
export type RanString = `RAN-${string}`;

export type AuthorityPurpose =
  | "compatibility-matrix-aggregate"
  | "release-signing"
  | "attestation"
  | "policy"
  | "other";

export interface AuthorityRecord {
  ran: RanString;
  organization: string;
  display_name: string;
  purpose: AuthorityPurpose;
  signing_pub: string;                   // Ed25519 raw public key, base64
  pq_signing_pub: string;                // ML-DSA-65 raw public key, base64
  pq_kid: string;
  signing_alg: ["Ed25519", "ML-DSA-65"]; // tuple, locked
  registered_at: string;                 // RFC 3339 UTC
  status: "active" | "revoked";
  revoked_at?: string;
  revocation_reason?: string;
}

// ── Version-tuple envelope (hybrid-signed wrapper) ────────────────────────────
/**
 * Version-tuple envelope (hybrid-signed wrapper) — matches rcan-spec
 * /schemas/version-tuple-envelope.json verbatim. Per RCAN v3.2 Decision 3
 * (pqc-hybrid-v1): signature_mldsa65 is REQUIRED; signature_ed25519 is
 * OPTIONAL but if present must verify and must be paired with `kid`.
 *
 * The aggregator (monitor.version_matrix.sign_matrix in opencastor-ops)
 * produces this exact shape. The compatibility-matrix endpoint reuses
 * the same envelope schema (the matrix IS a version-tuple payload, just
 * with a richer inner structure than per-field tuples).
 */
export interface VersionTupleEnvelope {
  ran: string;                       // RAN-NNNNNNNNNNNN — direct authority lookup
  alg: ["ML-DSA-65"] | ["ML-DSA-65", "Ed25519"];   // ML-DSA-65 always at index 0
  pq_kid: string;                    // 8-hex; sha256(pq_pub)[:8].hex(); must equal authority.pq_kid
  kid?: string;                      // 8-hex; required iff signature_ed25519 present
  payload: string;                   // base64 (NOT base64url) of canonical-JSON inner
  signature_mldsa65: string;         // base64 — REQUIRED
  signature_ed25519?: string;        // base64 — OPTIONAL; if present, MUST verify
  signed_at: string;                 // RFC 3339 UTC
}

// ── Unified listing ───────────────────────────────────────────────────────────
export interface RegistryEntry {
  id: string;           // RRN, RCN, RMN, RHN, or RAN
  entity_type: "robot" | "component" | "model" | "harness" | "authority";
  name: string;
  registered_at: string;
  summary: Record<string, unknown>;
}

// === Compliance bundle intake — Plan 4 Phase 3 ===

export type KidMapping = {
  ran: `RAN-${string}`;
  valid_from: string;        // ISO-8601 UTC
  valid_until?: string;      // ISO-8601 UTC; absent = currently active
  registered_at: string;     // ISO-8601 UTC
  registered_by: `RAN-${string}`;
};

export type AggregatorScope = {
  ran: `RAN-${string}`;            // aggregator
  rrn: `RRN-${string}`;            // robot the aggregator may attest for
  authorized_at: string;
  authorized_by: `RAN-${string}`;
  valid_until?: string;
};

export type ComplianceBundleEntry = {
  bundle_id: string;
  rrn: `RRN-${string}`;
  schema_version: string;
  signed_at: string;
  robot_md_sha256: string;
  matrix_version?: string;
  artifact_types: string[];
  transparency_log_index: number;
  logged_at: string;
  bundle_signature: {
    kid: string;
    alg: ["Ed25519", "ML-DSA-65"];
    sig: { ed25519: string; ml_dsa: string; ed25519_pub: string };
  };
  rrf_log_signature: { kid: string; alg: "Ed25519"; sig: string };
  // Full payload (artifacts) lives at compliance-bundle:<bundle_id>
  // separately for Bearer-gated full GET access.
};

export type ComplianceBundleProof = Omit<ComplianceBundleEntry, never>;
// proof IS the entry — same fields, served at /v2/compliance-bundle/{id}/proof
// without the artifact bodies.
