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

- **Assigns RRNs** — Robot Registration Numbers: permanent, globally unique identifiers that survive hardware swaps and OS reinstalls
- **Stores capability declarations** — each robot record includes hardware specs, RCAN version, and declared capabilities
- **Provides a revocation API** — operators can revoke a robot's identity if it's compromised or decommissioned
- **Operates trust anchors** — as a root registry, RRF signs authoritative sub-registry keys via DNSSEC trust chains
- **Federated architecture** — manufacturers can run their own authoritative registry nodes; RRF is the root

## How to Register a Robot

1. Install the CLI tool: `pip install robot-md`
2. Initialize and register a new robot: `robot-md init my-robot --register`
3. Or register an existing manifest: `robot-md register ./ROBOT.md`
4. Register manually at [robotregistryfoundation.org/register](https://robotregistryfoundation.org/register)

## Robot Document Schema

| Field | Type | Description |
|---|---|---|
| `rrn` | string | Robot Registration Number, e.g. `RRN-000000000001` |
| `name` | string | Human-readable robot name |
| `owner` | string | Owner identifier (email or org) |
| `capabilities` | object | Capability Object Map (§18) — declared skills and hardware |
| `hardware_safety` | object | P66 manifest — ESTOP config, LoA requirements |
| `rcan_version` | string | Highest RCAN spec version supported |
| `verification_tier` | string | `community` / `verified` / `partner` / `certified` |
| `runtime` | string | e.g. `opencastor/2026.3.17.1` |
| `registered_at` | ISO 8601 | Registration timestamp |
| `revoked` | boolean | Whether this robot's identity is revoked |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v2/robots` | List all registered robots (paginated) |
| `GET` | `/v2/robots/{rrn}` | Resolve a robot record by RRN |
| `GET` | `/v2/robots/{rrn}/revocation-status` | Check if an RRN is revoked |
| `GET` | `/v2/robots/{rrn}/keys` | Fetch JWKS public keys for an RRN |
| `POST` | `/v2/robots/register` | Register a new robot |
| `GET` | `/.well-known/rcan-node.json` | Registry node manifest |

Full API reference: [robotregistryfoundation.org/api/](https://robotregistryfoundation.org/api/)

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

| Tier | Badge | How to Achieve |
|---|---|---|
| Community | ⬜ | Self-registered; no identity check |
| Verified | 🟡 | Email or domain verified; manufacturer identity confirmed |
| Partner | 🔵 | Signed partnership agreement with RRF |
| Certified | ✅ | Passed third-party conformance test suite |

Robots may only issue LoA 1 tokens from community registries. LoA 2/3 requires a verified or authoritative registry.

## Registry Tiers

| Tier | Who | Trust Level |
|---|---|---|
| **Root** | RRF (rcan.dev) | Signs authoritative registry keys; manages global trust anchors |
| **Authoritative** | Manufacturers, verified operators | Can issue LoA 2/3 JWTs; must pass annual audit |
| **Community** | Anyone | Self-signed; LoA 1 only |

Any organization can run an authoritative registry node. RCAN's federation model means robots registered at `bd.rcan.example` are fully interoperable with robots registered at `rcan.dev`.

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

We're seeking co-founders, board members, manufacturer partnerships, and standards body endorsements.

Governance charter: [robotregistryfoundation.org/governance/](https://robotregistryfoundation.org/governance/)

## License

Site content: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
Code: MIT

