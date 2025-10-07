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
