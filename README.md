# Robot Registry Foundation

The open registry for RCAN-compliant robots — assigns permanent global identities to robots the way ICANN assigns domain names.

[![Spec](https://img.shields.io/badge/RCAN-live%20matrix-blue)](https://rcan.dev/compatibility)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-green)](https://creativecommons.org/licenses/by/4.0/)

🌐 **[robotregistryfoundation.org](https://robotregistryfoundation.org)**

<!-- BEGIN: ecosystem regulatory disclaimer (canonical, derived from spec §10) -->
> **Compliance evidence is not regulatory sufficiency.**
>
> Compliance packet generation and RRF submission produce *evidence*; they do not constitute regulatory sufficiency in any jurisdiction. Per-jurisdiction conformity assessments and notified-body engagement are the user's responsibility, in consultation with qualified counsel.
<!-- END: ecosystem regulatory disclaimer -->

## What RRF Does

- **Assigns RRNs**: Robot Registration Numbers, permanent and globally unique, that survive hardware swaps and OS reinstalls
- **Stores what owners declare**: name, manufacturer, model, firmware and RCAN versions, signing keys, and (optionally) a self-declared physical assurance level
- **Revokes keys and credentials**: robot key revocation and rotation, orchestrator revocation list at `GET /v2/revocations`
- **Accepts signed evidence**: RCAN §22–§26 compliance artifacts and run bundles, stored as submitted and signature-checked, never judged
- **Designed for federation**: the protocol lets other organizations run registry nodes. Today there is one node (this one) and no delegated namespaces.

## How to Register a Robot

1. Install the CLI tool: `pip install robot-md`
2. Initialize and register a new robot: `robot-md init my-robot --register`
3. Or register an existing manifest: `robot-md register ./ROBOT.md`
4. Register manually at [robotregistryfoundation.org/registry/submit/](https://robotregistryfoundation.org/registry/submit/)

## Robot Record

As returned by `GET /v2/robots/{rrn}` (the `api_key` is never returned). Source of truth: `functions/v2/_lib/types.ts`.

| Field | Type | Description |
|---|---|---|
| `rrn` | string | Robot Registration Number, e.g. `RRN-000000000001` |
| `name`, `manufacturer`, `model` | string | As declared at registration |
| `firmware_version`, `rcan_version` | string | As declared; patchable |
| `pq_signing_pub`, `pq_kid` | string | ML-DSA-65 public key and key id; registration must be signed |
| `ruri` | string | Optional `rcan://` URI |
| `rcn_ids`, `rmn`, `rhn_ids` | string / string[] | Optional operator-declared component, model and harness IDs |
| `verification_status` | string | `unverified` → `community` → `manufacturer_claimed` → `manufacturer_verified` |
| `assurance_level` | string | Optional `A1` / `A2` / `A3`, self-declared (see below) |
| `envelope_hash` | string | Optional `sha256:<hex>` of the robot's declared physical envelope |
| `assurance_evidence_url` | string | Optional https link to third-party evidence; required for A3 |
| `assurance` | object \| null | Derived view of the three fields above, with its basis and a note |
| `registered_at`, `updated_at` | ISO 8601 | Timestamps |
| `revoked`, `revoked_at` | boolean, ISO 8601 | Present when revoked |

## API Endpoints (selection)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v2/registry` | List registered entities (robots, components, models, harnesses, authorities) |
| `POST` | `/v2/robots/register` | Register a new robot (signed body required) |
| `GET` | `/v2/robots/register` | List recently registered robots |
| `GET` / `PATCH` / `DELETE` | `/v2/robots/{rrn}` | Resolve, update whitelisted fields (bearer), or unregister (bearer) |
| `POST` | `/v2/robots/{rrn}/verify-tier` | Signed request to move to `manufacturer_claimed` / `manufacturer_verified` |
| `POST` | `/v2/robots/{rrn}/revoke-key`, `/rotate-key` | Key revocation and rotation |
| `GET` | `/v2/keys/{kid}` | Resolve a signing key id |
| `GET` | `/v2/revocations` | Orchestrator revocation list |
| `GET` | `/.well-known/rrf-root-pubkey.pem` | Registry log-signing public key |

Full API reference: [docs.robotregistryfoundation.org/api/](https://docs.robotregistryfoundation.org/api/)

## Identity Namespaces

RRF assigns globally unique identifiers across five namespaces. All identifiers use a 12-digit zero-padded format.

| Namespace | Format | What It Identifies |
|---|---|---|
| **RRN** — Robot Registration Number | `RRN-000000000001` | A physical or virtual robot |
| **RCN** — Robot Component Number | `RCN-000000000001` | A hardware component of a registered robot |
| **RMN** — Robot Model Number | `RMN-000000000001` | An AI model registered for robot use |
| **RHN** — Robot Harness Number | `RHN-000000000001` | An AI harness/agent framework |
| **RAN** — Robot Authority Number | `RAN-000000000001` | A non-robot signing authority (aggregators, release-signing tools, attestation services, policy authorities) |

- **RAN — Robot Authority Number.** Identity for non-robot, non-component, non-model entities that need durable hybrid keys: aggregators, release-signing tools, attestation services, policy authorities. Endpoint: `/v2/authorities/<ran>`. Registered via §2.2 ritual at `/v2/authorities/register`.

### Authority (RAN) Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v2/authorities/register` | Register a new RAN (§2.2 hybrid-signed) |
| `GET` | `/v2/authorities/<ran>` | Fetch a single authority record |
| `GET` | `/v2/authorities` | List all registered authorities (paginated) |
| `DELETE` | `/v2/authorities/<ran>` | Admin-only removal (`RRF_ADMIN_TOKEN` required) |

## Compliance Intake (RCAN §22-26)

Robots registered under [`/v2/robots/register`](#registration) can submit EU AI Act compliance artifacts produced by the [`rcan-ts`](https://www.npmjs.com/package/rcan-ts) 3.3.0+ builders.

### Endpoints

| Endpoint | RCAN § | GET access |
|---|---|---|
| `POST /v2/robots/:rrn/fria` | §22 FRIA | Bearer-gated |
| `POST /v2/robots/:rrn/safety-benchmark` | §23 Safety Benchmark | public |
| `POST /v2/robots/:rrn/ifu` | §24 Instructions For Use (Art. 13(3)) | public |
| `POST /v2/robots/:rrn/incident-report` | §25 Post-Market Incident Report (Art. 72) | Bearer-gated |
| `POST /v2/models/:rmn/eu-register` | §26 EU Register (Art. 49) | public |

All five have a matching `GET` at the same path. §26 is scoped per model (RMN) rather than per robot; submitting robots identify themselves via the `X-Submitter-RRN` header.

A §23 safety-benchmark submission may include `ev_tests_covered` (e.g. `["EV-05","EV-08"]`), naming which [physical-assurance tests](https://github.com/RobotRegistryFoundation/rcan-spec/blob/master/tests/assurance/README.md) it covers. The list is part of the signed document and is echoed back as self-reported. RRF does not run or check the tests.

## Physical Assurance (RCAN Appendix C)

A robot record may carry a self-declared physical assurance level. The model proposes, a bounded layer disposes; A1–A3 describe how well that layer is built and tested ([RCAN Appendix C](https://github.com/RobotRegistryFoundation/rcan-spec/blob/master/spec/appendix-c-physical-assurance.md), informative).

- Set at registration (inside the signed body) or with `PATCH /v2/robots/{rrn}`; `null` clears.
- A1 and A2 are always shown as self-declared. A3 needs `assurance_evidence_url` and is shown only when one is present.
- RRF does not test robots, fetch or review the evidence, or check the envelope. No endpoint accepts test results as verified.
- A-levels are independent of RCAN conformance levels L1–L4: an L3 robot can be A1.
- Existing records need no migration; they read as `assurance: null`.

Site page: [robotregistryfoundation.org/physical-assurance/](https://robotregistryfoundation.org/physical-assurance/)

### Happy path (POST)

```
Producer (robot)
  ├─ build doc:  doc = buildSafetyBenchmark({ iterations, thresholds, results, mode, generated_at, overall_pass })
  ├─ sign doc:   signed = await signBody(keypair, doc, { ed25519Secret, ed25519Public })
  └─ POST /v2/robots/{rrn}/safety-benchmark
     body: { ...doc, pq_signing_pub, pq_kid, sig: { ml_dsa, ed25519, ed25519_pub } }

RRF
  ├─ loads robot:{rrn} from KV, extracts pq_signing_pub
  ├─ verifyBody(signed, pq_signing_pub)           → 401 on sig failure
  ├─ checks doc.schema; per-type binding check:
  │     §22 FRIA            — doc.system.rrn === URL rrn
  │     §23 SafetyBenchmark — no doc-level check (URL+sig provides binding)
  │     §24 IFU             — no doc-level check (URL+sig provides binding)
  │     §25 IncidentReport  — doc.rrn === URL rrn
  ├─ stores at compliance:{type}:{rrn}
  └─ appends snapshot at compliance:{type}:history:{rrn}:{ts}
     → 201 { ok, rrn, submitted_at, {type}_url }
```

### Auth

POST requires a signed body (ML-DSA-65 + Ed25519) against the robot's registered `pq_signing_pub`. No Bearer token needed for POST — the signature IS the auth.

GET is public for transparency types (safety-benchmark, ifu); Bearer-gated for FRIA and incident-report (may contain sensitive content). D2 does not validate Bearer contents — the door is reserved; a future release will wire consumer auth.

### Retention

10-year TTL on both current and history keys, matching Art. 72 record-keeping obligations for high-risk AI systems.

## Registered Robots (Examples)

| RRN | Name | Runtime | Hardware |
|---|---|---|---|
| RRN-000000000001 | Bob | OpenCastor v2026.4.21.1 | Raspberry Pi 5, Gemini 2.5 Flash |
| RRN-000000000005 | Alex | OpenCastor v2026.4.21.1 | Raspberry Pi 5 + SO-ARM101 5-DOF arm |

Browse all: [robotregistryfoundation.org/registry/](https://robotregistryfoundation.org/registry/)

## Verification Tiers

| Tier | How to achieve | What it proves |
|---|---|---|
| `unverified` | Default on registration | The registrant holds the signing key |
| `community` | Maintainer-curated | A maintainer looked at it; no independent check |
| `manufacturer_claimed` | DNS TXT record on the manufacturer's domain | Control of that domain |
| `manufacturer_verified` | DNS TXT + signed attestation + RURI manifest | The above, plus a signed manufacturer attestation |

Tiers move one step at a time, never skipping. No tier certifies the robot. Conformance is not certification.

Robots may only issue LoA 1 tokens from community registries. LoA 2/3 requires a verified or authoritative registry.

## Registry Tiers

RCAN defines root, authoritative and community registry roles. Today the only registry node is this one, and no namespaces have been delegated. Nothing here audits other registries.

## Development

```bash
npm install
npm run dev      # localhost:4321
npm run build    # production → dist/
```

## Ecosystem

| Project | Version | Purpose |
|---|---|---|
| **RRF** (this) | v2.0.0 | Global robot identity registry |
| [RCAN Protocol](https://rcan.dev/spec/) | v3.0.0 | Open robot communication standard |
| [OpenCastor](https://github.com/craigm26/OpenCastor) | v2026.4.21.1 | Robot runtime, RCAN reference implementation |
| [rcan-py](https://github.com/continuonai/rcan-py) | v3.0.0 | Python RCAN SDK |
| [rcan-ts](https://github.com/continuonai/rcan-ts) | v3.0.0 | TypeScript RCAN SDK |
| [Fleet UI](https://app.opencastor.com) | live | Web fleet dashboard |

## Contributing

The RRF is in active formation. Open issues and discussions at GitHub.

RRF currently has one maintainer and no board, partners or endorsing organizations. We're seeking co-founders, and review and collaboration from standards bodies and testing labs. See [Governance and neutrality](https://robotregistryfoundation.org/about/#governance).

Draft governance charter: [docs.robotregistryfoundation.org/governance/](https://docs.robotregistryfoundation.org/governance/)

## License

Site content: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
Code: MIT

