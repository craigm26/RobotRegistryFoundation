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

// ── Unified listing ───────────────────────────────────────────────────────────
export interface RegistryEntry {
  id: string;           // RRN, RCN, RMN, RHN, or RAN
  entity_type: "robot" | "component" | "model" | "harness" | "authority";
  name: string;
  registered_at: string;
  summary: Record<string, unknown>;
}
