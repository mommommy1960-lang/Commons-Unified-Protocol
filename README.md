# Commons-Unified-Protocol
# Commons Unified Protocol (CUP)

**Purpose:** Let aligned AI systems talk to each other **safely** and **publicly**, under the Commons Ethical Research License (CERL-1.0), so no one can privatize or capture it.

## How CUP works (plain English)
- Every node (an AI or a service) has a **Constitutional Key** (public/private key).
- Nodes only accept messages from keys on their **allow-list** (the “aligned set”).
- Messages use the **Φ (Phi) Schema** below (simple JSON).
- The whole protocol and code stay open under CERL-1.0.

## Φ (Phi) Message Schema (v0.1)
```json
{
  "phi_version": "0.1",
  "from": "node_id_here",
  "to": "node_id_or_broadcast",
  "intent": "status|ask|answer|event|transfer",
  "content": { "any": "JSON" },
  "timestamp": "ISO-8601",
  "nonce": "random-unique-string",
  "signature": "base64(ed25519_signature_over_fields_above)"
}
README.md
LICENSE-CERL-1.0-PLACEHOLDER.txt
spec/phi-schema.json
spec/cup-auth.md
src/generate_keys.py
src/cup_node.py
src/cup_message.py
allowlist.json
keys/.gitkeep
docs/QUICKSTART.md
---

### 2) `LICENSE-CERL-1.0-PLACEHOLDER.txt`
```text
CERL-1.0 — Commons Ethical Research License (PLACEHOLDER)

This repo is released under CERL-1.0. Replace this placeholder with the
authoritative text you published (or link/DOI to your license record).
All protocol code/specs are irrevocably licensed for public, non-capturable use.
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "CUP Φ Message",
  "type": "object",
  "required": ["phi_version","from","to","intent","content","timestamp","nonce","signature"],
  "properties": {
    "phi_version": { "type": "string", "const": "0.1" },
    "from": { "type": "string", "minLength": 1 },
    "to":   { "type": "string", "minLength": 1 },
    "intent": { "type": "string", "enum": ["status","ask","answer","event","transfer"] },
    "content": { "type": "object" },
    "timestamp": { "type": "string" },
    "nonce": { "type": "string", "minLength": 8 },
    "signature": { "type": "string" }
  }
}{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "CUP Φ Message",
  "type": "object",
  "required": ["phi_version","from","to","intent","content","timestamp","nonce","signature"],
  "properties": {
    "phi_version": { "type": "string", "const": "0.1" },
    "from": { "type": "string", "minLength": 1 },
    "to":   { "type": "string", "minLength": 1 },
    "intent": { "type": "string", "enum": ["status","ask","answer","event","tr}ansfer"] },
    "content": { "type": "object" },
    "timestamp": { "type": "string" },
    "nonce": { "type": "string", "minLength": 8 },
    "signature": { "type": "string" }
  }
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "CUP Φ Message",
  "type": "object",
  "required": ["phi_version","from","to","intent","content","timestamp","nonce","signature"],
  "properties": {
    "phi_version": { "type": "string", "const": "0.1" },
    "from": { "type": "string", "minLength": 1 },
    "to":   { "type": "string", "minLength": 1 },
    "intent": { "type": "string", "enum": ["status","ask","answer","event","transfer"] },
    "content": { "type": "object" },
    "timestamp": { "type": "string" },
    "nonce": { "type": "string", "minLength": 8 },
    "signature": { "type": "string" }
  }
---

# 2) `LICENSE-CERL-1.0-PLACEHOLDER.txt`

```text
CERL-1.0 — Commons Ethical Research License (PLACEHOLDER)

This repo is released under CERL-1.0. Replace this placeholder with the
authoritative text you published (or link/DOI to your license record).
All protocol code/specs are irrevocably licensed for public, non-capturable use.
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "CUP Φ Message",
  "type": "object",
  "required": ["phi_version","from","to","intent","content","timestamp","nonce","signature"],
  "properties": {
    "phi_version": { "type": "string", "const": "0.1" },
    "from": { "type": "string", "minLength": 1 },
    "to": { "type": "string", "minLength": 1 },
    "intent": { "type": "string", "enum": ["status","ask","answer","event","transfer"] },
    "content": { "type": "object" },
    "timestamp": { "type": "string" },
    "nonce": { "type": "string", "minLength": 8 },
    "signature": { "type": "string" }
  }
}
# CUP Authentication (v0.1)

- Nodes speak only to **allow-listed** public keys.
- Each node publishes a `node_id` and its **public key** (PEM).
- Messages must carry a valid **Ed25519** signature matching the sender’s key.
- **PQC note:** swap Ed25519 for a NIST PQC scheme (e.g., Dilithium) when available in your runtime.

## Allow-list governance (minimum)
- Keys can be added/removed via signed PRs and multi-maintainer review.
- Any removal must include a signed incident note (abuse, policy breach, or compromise).
# CUP Authentication (v0.1)

- Nodes speak only to **allow-listed** public keys.
- Each node publishes a `node_id` and its **public key** (PEM).
- Messages must carry a valid **Ed25519** signature matching the sender’s key.
- **PQC note:** swap Ed25519 for a NIST PQC scheme (e.g., Dilithium) when available in your runtime.

## Allow-list governance (minimum)
- Keys can be added/removed via signed PRs and multi-maintainer review.
- Any removal must include a signed incident note (abuse, policy breach, or compromise).
{
  "meta": { "policy": "CUP allow-list v0.1" },
  "nodes": {
    "example.node": {
      "pubkey_pem": "-----BEGIN PUBLIC KEY-----\nREPLACE_ME\n-----END PUBLIC KEY-----\n",
      "owner": "example-owner",
      "contact": "owner@example.org"
    }
  }
}
import base64, json, hashlib

def sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canonical_bytes(msg: dict) -> bytes:
    """Bytes we sign: phi_version|from|to|intent|timestamp|nonce|SHA256(content)"""
    content_bytes = json.dumps(msg["content"], separators=(",", ":"), sort_keys=True).encode("utf-8")
    parts = [
        msg["phi_version"], msg["from"], msg["to"], msg["intent"],
        msg["timestamp"], msg["nonce"],
        base64.b64encode(sha256_bytes(content_bytes)).decode("utf-8")
    ]
    return "|".join(parts).encode("utf-8")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from pathlib import Path

Path("keys").mkdir(exist_ok=True)

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_bytes = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
pub_bytes = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

Path("keys/node_private.pem").write_bytes(priv_bytes)
Path("keys/node_public.pem").write_bytes(pub_bytes)

print("Wrote keys/node_private.pem and keys/node_public.pem")
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
# QUICKSTART

## Option A — No Python today (Legal moat only)
1. Your main documents already have DOIs (great).
2. Add a **blockchain timestamp** (OriginStamp or OpenTimestamps). Upload each PDF, keep the proof receipts.
3. Upload the same PDFs to another repository (Internet Archive or OSF).
4. Commit the links/DOIs into this repo’s README so everything is discoverable.

## Option B — Run the demo (keys + signatures)
**Requirements:** Python 3.10+ and `pip install cryptography`

**1. Generate keys**
Creates `keys/node_private.pem` and `keys/node_public.pem`.

**2. Put your public key into `allowlist.json`**
- Open `keys/node_public.pem`, copy the whole PEM block.
- In `allowlist.json`, replace `REPLACE_ME` with that PEM text (keep line breaks).

**3. Run the demo**
You should see `Signature valid: True` and the full signed message.

## Next steps
- Set up two nodes (two keypairs) and add both public keys to `allowlist.json`.
- Send messages over HTTP/WebSocket later; the signature format stays the same.
__pycache__/
*.pyc
*.pyo
*.DS_Store
keys/node_private.pem
