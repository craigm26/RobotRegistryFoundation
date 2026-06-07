# U1b — RRF Attestation Registration Runbook

Mint a hybrid attestation keypair, register its `kid` in RRF bound to GitHub org
`OpenCastor`, provision **only** the Ed25519 private key to the gateway, and archive
the ML-DSA key offline. PQ is **mandatory** in RRF: hybrid is required both to register
(`register.ts:46-106`) and to serve (`keys/[kid].ts:136-141`). Do **not** relax this.

Prereqs:
- `~/rcan-py/.venv/bin/python` with rcan 3.4.0 (`[pq]` + `[crypto]`). Verify:
  `~/rcan-py/.venv/bin/python -c "import rcan, dilithium_py, cryptography; print(rcan.__version__)"` → `3.4.0`.
- `wrangler` authenticated for the RRF account (KV namespace binding `RRF_KV`, id in `wrangler.toml`).
- An RRF RAN for this attestation authority (the `--ran` below). NOTE: `register-operator-kid.ts`
  takes an explicit RAN and does NOT use `counter:ran`; pick a RAN that does not collide with any
  existing `authority:RAN-*` and is outside the range `POST /v2/authorities/register` will auto-assign.
  Confirm YOUR chosen RAN is free (the deployed bob-gw-attest-2026 used RAN-000000000777; pick a DIFFERENT free reserved RAN for a new robot):  `wrangler kv key get "authority:<RAN>" --binding RRF_KV --remote`  → expect "key not found".

Choose values (used throughout):
    KID=bob-gw-attest-2026
    RAN=RAN-000000000777
    REGISTERED_BY=RAN-000000000018
    VALID_FROM=2026-06-06T00:00:00.000Z
    MINT_DIR=~/.opencastor-ops-keys/attestation-2026-06-06

## 1. Mint the keypair + registration body
    ~/rcan-py/.venv/bin/python ~/RobotRegistryFoundation/scripts/mint-attestation-kid.py \
      --organization OpenCastor \
      --display-name "Bob gateway attestation signer" \
      --out-dir "$MINT_DIR"
Output prints the `pq_kid` and `signing_pub`; `$MINT_DIR` now holds
`attestation-ed25519-private.pem`, `attestation-mldsa65-private.pem`, `mint-manifest.json`.

## 2. Generate the `wrangler kv bulk put` record
Read the minted values straight from the manifest (no hand-copying):
    SIGNING_PUB=$(~/rcan-py/.venv/bin/python -c "import json,sys;print(json.load(open('$MINT_DIR/mint-manifest.json'))['signing_pub_b64'])")
    PQ_PUB=$(~/rcan-py/.venv/bin/python -c "import json,sys;print(json.load(open('$MINT_DIR/mint-manifest.json'))['pq_signing_pub_b64'])")
    PQ_KID=$(~/rcan-py/.venv/bin/python -c "import json,sys;print(json.load(open('$MINT_DIR/mint-manifest.json'))['pq_kid'])")

    cd ~/RobotRegistryFoundation
    npx tsx scripts/register-operator-kid.ts \
      --kid "$KID" \
      --ran "$RAN" \
      --signing-pub-b64 "$SIGNING_PUB" \
      --pq-signing-pub-b64 "$PQ_PUB" \
      --pq-kid "$PQ_KID" \
      --organization OpenCastor \
      --display-name "Bob gateway attestation signer" \
      --purpose attestation \
      --registered-by "$REGISTERED_BY" \
      --valid-from "$VALID_FROM" \
      --out /tmp/u1b-attestation-kv.json
This writes a 2-element JSON array: `kid:<KID>:<ts>` + `authority:<RAN>`.

## 3. Push to KV (scope item 4)
    cd ~/RobotRegistryFoundation
    wrangler kv bulk put /tmp/u1b-attestation-kv.json --binding RRF_KV --remote
Expect: `Success! ... 2 ... key value pairs.`

## 4. Verify the served key (scope item: GET 200 with public_key_pem + status:active)
    curl -s https://rcan.dev/v2/keys/$KID | python3 -m json.tool
Expect HTTP 200 and a body with:
  - `"status": "active"`
  - `"alg": "Ed25519"` and a `"public_key_pem"` beginning `-----BEGIN PUBLIC KEY-----`
  - `"pq_alg": "ML-DSA-65"`, `"pq_public_key_b64"` (1952-byte decode), `"pq_kid"` == `$PQ_KID`, `"ran"` == `$RAN`
A 404 → the `kid:*` mapping did not land (re-check step 3). A 502 → byte-length/integrity gate
(`keys/[kid].ts:136-141`); re-mint, the pub bytes are wrong.

## 5. Provision the gateway (Ed25519 only) — scope item 5 / U1a files
Provision out-of-band to the gateway host (never commit these):
    ROBOT_MD_ATTESTATION_KEY_FILE = $MINT_DIR/attestation-ed25519-private.pem
    ROBOT_MD_ATTESTATION_KID      = bob-gw-attest-2026
    ROBOT_MD_ATTESTATION_RAN      = RAN-000000000777
The gateway-side loader that reads these env vars is U1a's scope — out of scope here.
The **public** kid/RAN may live in `OpenCastor/bob-spec-b-pick-place` non-secret config; the
PEM must NOT (spec §11.1: keys stay in `~/.opencastor-ops-keys`).

## 6. Archive the ML-DSA private key OFFLINE — scope item 5
`attestation-mldsa65-private.pem` is needed only to re-register/rotate. Move it to offline cold
storage (the operator key vault); it MUST NOT reach the robot/gateway. Rotation = re-mint +
re-register (new RAN) + re-provision the new Ed25519 PEM.

## Rollback
Revoke the authority: `wrangler kv key put "authority:$RAN" "<record with status:revoked, revoked_at>" --binding RRF_KV --remote`.
`GET /v2/keys/$KID` then returns 410 (`keys/[kid].ts:121-126`) → S3 maps to `revoked`.
