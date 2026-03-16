import { defineCollection, z } from 'astro:content';

const robotsCollection = defineCollection({
  type: 'data',
  schema: z.object({
    rrn: z.string(),
    name: z.string(),
    manufacturer: z.string(),
    model: z.string(),
    description: z.string(),
    status: z.enum(['active', 'retired', 'prototype', 'concept']).default('active'),
    production_year: z.number().optional(),
    specs: z.object({
      compute: z.string().optional(),
      sensors: z.array(z.string()).optional(),
      actuators: z.array(z.string()).optional(),
      ros_version: z.array(z.string()).optional(),
      weight_kg: z.number().optional(),
      dimensions: z.string().optional(),
      platform: z.string().optional(),
    }).optional(),
    verification_status: z.enum(['community', 'verified', 'certified', 'accredited']).default('community'),
    ruri: z.string().nullable().optional(),
    rrn_uri: z.string().optional(),
    tags: z.array(z.string()).default([]),
    submitted_by: z.string().optional(),
    submitted_date: z.string().optional(),
    registered_at: z.string().optional(),
    opencastor_version: z.string().optional(),
    hardware_safety: z.object({
      physical_estop: z.boolean().optional(),
      hardware_watchdog_mcu: z.boolean().optional(),
      force_torque_sensors: z.boolean().optional(),
      human_proximity_sensors: z.string().optional(),
      sil_level: z.string().optional(),
      voltage_monitoring: z.boolean().optional(),
    }).optional(),

    // ── RCAN v1.5 fields (GAP-02, GAP-09, GAP-11, GAP-01, GAP-06) ──────────
    /** RCAN spec version this robot supports, e.g. "1.5" */
    rcan_version: z.string().optional(),
    /**
     * Current revocation status.
     * "active"    = normal operation
     * "revoked"   = permanently revoked; commands blocked (ESTOP still accepted)
     * "suspended" = temporarily restricted; commands blocked
     */
    revocation_status: z.enum(['active', 'revoked', 'suspended']).default('active'),
    /** Fingerprint/ID of the robot's current signing key (Ed25519 kid) */
    key_id: z.string().optional(),
    /** Previous key IDs for historical audit trail (key rotation history) */
    key_history: z.array(z.string()).default([]),
    /** Whether this robot supports QoS level 2 (exactly-once) for ESTOP delivery */
    supports_qos_2: z.boolean().default(false),
    /** Whether this robot supports command delegation chains (GAP-01) */
    supports_delegation: z.boolean().default(false),
    /** Whether this robot can operate in offline mode with cached credentials */
    offline_capable: z.boolean().default(false),
  }),
});

export const collections = {
  robots: robotsCollection,
};
