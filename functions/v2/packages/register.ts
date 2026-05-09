/**
 * POST /v2/packages/register
 * RCAN 3.0 §2.2 — Register a software package, receive an RPN.
 *
 * Body: { name, description, package_type, repository_url,
 *         hardware_tags[], manifest_signals[], skill_files[],
 *         has_plugin_layout, version,
 *         pq_signing_pub, pq_kid, ed25519_pub, sig }
 *
 * Returns: { rpn, registered_at, record_url }
 */

import { nextId } from "../_lib/id.js";
import type { PackageRecord, PackageType } from "../_lib/types.js";
import { verifyBody } from "rcan-ts";

export interface Env { RRF_KV: KVNamespace }

const VALID_TYPES: PackageType[] = ["actuator", "skill", "plugin", "mcp"];

const REQUIRED_FIELDS = [
  "name", "description", "package_type", "repository_url",
  "hardware_tags", "manifest_signals", "skill_files",
  "has_plugin_layout", "version",
  "pq_signing_pub", "pq_kid", "ed25519_pub", "sig",
] as const;

function err(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  let body: Record<string, unknown>;
  try { body = (await request.json()) as Record<string, unknown>; }
  catch { return err("Invalid JSON body", 400); }

  // Required field presence check
  for (const k of REQUIRED_FIELDS) {
    if (!(k in body)) return err(`Required: ${k}`, 400);
  }

  const package_type = body.package_type as string;
  if (!VALID_TYPES.includes(package_type as PackageType)) {
    return err(`Invalid package_type: ${package_type}`, 400);
  }

  // RCAN 3.0 §2.2 — signature mandatory; shape: sig.{ml_dsa, ed25519, ed25519_pub}
  const sig = body.sig as Record<string, unknown> | undefined;
  if (!sig?.ml_dsa || !sig?.ed25519 || !sig?.ed25519_pub) {
    return err("Unsigned registration not permitted (RCAN 3.0 §2.2)", 400);
  }

  // Signature verification: all fields except `sig` are signed
  const { sig: _omit, ...signedFields } = body;
  const pq_signing_pub = body.pq_signing_pub as string;

  let verified = false;
  try {
    const pqPub = Uint8Array.from(atob(pq_signing_pub), c => c.charCodeAt(0));
    verified = await verifyBody({ ...signedFields, sig }, pqPub);
  } catch { /* verified stays false */ }
  if (!verified) return err("Signature verification failed", 400);

  const name = body.name as string;
  const byNameKey = `package-by-name:${package_type}:${name}`;
  const existing = await env.RRF_KV.get(byNameKey);
  if (existing) return err(`Name already taken in type ${package_type}: ${name}`, 409);

  const rpn = await nextId(env.RRF_KV, "RPN");
  const registered_at = new Date().toISOString();

  const record: PackageRecord = {
    rpn,
    package_type: package_type as PackageType,
    name,
    description: body.description as string,
    repository_url: body.repository_url as string,
    hardware_tags: (body.hardware_tags as string[]) ?? [],
    manifest_signals: (body.manifest_signals as string[]) ?? [],
    skill_files: (body.skill_files as string[]) ?? [],
    has_plugin_layout: body.has_plugin_layout as boolean,
    versions: [
      {
        version: body.version as string,
        released_at: registered_at,
        artifact_hash: body.artifact_hash as string | undefined,
      },
    ],
    publisher: {
      pq_signing_pub,
      pq_kid: body.pq_kid as string,
      ed25519_pub: body.ed25519_pub as string,
    },
    registered_at,
    status: "active",
  };

  await env.RRF_KV.put(`package:${rpn}`, JSON.stringify(record));
  await env.RRF_KV.put(byNameKey, rpn);

  const byTypeKey = `package-by-type:${package_type}`;
  const existingList = await env.RRF_KV.get(byTypeKey);
  const newList = existingList ? `${existingList}\n${rpn}` : rpn;
  await env.RRF_KV.put(byTypeKey, newList);

  const url = new URL(request.url);
  const record_url = `${url.origin}/v2/packages/${rpn}`;
  return new Response(JSON.stringify({ rpn, registered_at, record_url }), {
    status: 201,
    headers: { "Content-Type": "application/json" },
  });
};
