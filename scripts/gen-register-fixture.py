"""Generate register fixture: signed MintRequest body for POST /v2/robots/register."""
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric import ed25519
from rcan.crypto import generate_ml_dsa_keypair, sign_hybrid

kp = generate_ml_dsa_keypair()
ed_sec = ed25519.Ed25519PrivateKey.generate()
ed_sec_bytes = ed_sec.private_bytes_raw()
ed_pub_bytes = ed_sec.public_key().public_bytes_raw()

ml_dsa_pub_b64 = base64.b64encode(kp.public_key_bytes).decode()
pq_kid = hashlib.sha256(kp.public_key_bytes).hexdigest()[:8]

# Signed-fields block (matches what robot-md's signing.py will produce)
signed_fields = {
    "name": "register-fx-bot",
    "manufacturer": "acme-corp",
    "model": "reg-001",
    "firmware_version": "1.0.0",
    "rcan_version": "3.0",
    "pq_signing_pub": ml_dsa_pub_b64,
    "pq_kid": pq_kid,
    "ruri": "rcan://robotregistryfoundation.org/acme-corp/reg-001/register-fx-bot",
}
message = json.dumps(signed_fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
hs = sign_hybrid(kp, ed_sec_bytes, message)

# HTTP body POSTed to /v2/robots/register = signed_fields + {sig}
http_body = {
    **signed_fields,
    "sig": {
        "ml_dsa": base64.b64encode(hs.ml_dsa_sig).decode(),
        "ed25519": base64.b64encode(hs.ed25519_sig).decode(),
        "ed25519_pub": base64.b64encode(ed_pub_bytes).decode(),
    },
}

print(json.dumps({
    "http_body": http_body,
    "canonical_bytes_b64": base64.b64encode(message).decode(),
}, indent=2))
