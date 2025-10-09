import json, base64, os, datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from src.cup_message import canonical_bytes

HERE = Path(__file__).resolve().parent.parent
KEYS = HERE / "keys"
ALLOW = HERE / "allowlist.json"

def load_private_key():
    return serialization.load_pem_private_key((KEYS / "node_private.pem").read_bytes(), password=None)

def load_allowlist():
    return json.loads(ALLOW.read_text())["nodes"]

def pubkey_from_pem(pem_text: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem_text.encode("utf-8"))

def sign(priv, msg_dict):
    to_sign = canonical_bytes(msg_dict)
    sig = priv.sign(to_sign)
    msg_dict["signature"] = base64.b64encode(sig).decode("utf-8")
    return msg_dict

def verify(msg_dict, pubkey_pem: str) -> bool:
    pub = pubkey_from_pem(pubkey_pem)
    sig = base64.b64decode(msg_dict["signature"])
    to_verify = canonical_bytes(msg_dict)
    pub.verify(sig, to_verify)  # raises if invalid
    return True

if __name__ == "__main__":
    priv = load_private_key()
    allow = load_allowlist()

    node_id = list(allow.keys())[0]
    pub_pem = allow[node_id]["pubkey_pem"]

    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    msg = {
        "phi_version": "0.1",
        "from": node_id,
        "to": node_id,
        "intent": "status",
        "content": {"hello": "world"},
        "timestamp": now,
        "nonce": base64.b64encode(os.urandom(16)).decode("utf-8"),
        "signature": ""
    }

    signed = sign(priv, msg)
    ok = verify(signed, pub_pem)
    print("Signature valid:", ok)
    print(json.dumps(signed, indent=2))
