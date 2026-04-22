"""Generate PATCH fixture: a signed {rrn, pq_signing_pub, pq_kid} payload.

Used by functions/v2/robots/[rrn]/index.test.ts to confirm the PATCH handler's
sig verification path works end-to-end against a Python-produced signature.

RRN constant matches the test's RRN constant (RRN-000000000042).
"""
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric import ed25519
from rcan.crypto import generate_ml_dsa_keypair, sign_hybrid

RRN = "RRN-000000000042"

kp = generate_ml_dsa_keypair()
ed_sec = ed25519.Ed25519PrivateKey.generate()
ed_sec_bytes = ed_sec.private_bytes_raw()
ed_pub_bytes = ed_sec.public_key().public_bytes_raw()

ml_dsa_pub_b64 = base64.b64encode(kp.public_key_bytes).decode()
pq_kid = hashlib.sha256(kp.public_key_bytes).hexdigest()[:8]

payload = {"rrn": RRN, "pq_signing_pub": ml_dsa_pub_b64, "pq_kid": pq_kid}
message = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
hs = sign_hybrid(kp, ed_sec_bytes, message)

# IMPORTANT: rcan's HybridSignature uses hs.ml_dsa_sig / hs.ed25519_sig
print(json.dumps({
    "rrn": RRN,
    "pq_signing_pub": ml_dsa_pub_b64,
    "pq_kid": pq_kid,
    "canonical_bytes_b64": base64.b64encode(message).decode(),
    "sig": {
        "ml_dsa": base64.b64encode(hs.ml_dsa_sig).decode(),
        "ed25519": base64.b64encode(hs.ed25519_sig).decode(),
        "ed25519_pub": base64.b64encode(ed_pub_bytes).decode(),
    },
}, indent=2))
