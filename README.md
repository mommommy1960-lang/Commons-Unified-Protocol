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
```

### Signature rules
Sign the bytes of:
`phi_version|from|to|intent|timestamp|nonce|SHA256(content)`

Attach the Base64 signature in `signature`.

## COMMONS NETWORK

This repository is one node in the Commons Initiative project nervous system.

- **Continuity spine:** https://github.com/mommommy1960-lang/commons-sentience-sandbox/tree/main/docs/continuity
- **Network map:** https://github.com/mommommy1960-lang/commons-sentience-sandbox/blob/main/docs/continuity/PROJECT_NERVOUS_SYSTEM.md
- **Aurora:** https://github.com/mommommy1960-lang/aurora-sovereign-core
- **Flux:** https://github.com/mommommy1960-lang/flux-drive-kernel

Local repositories own their domain-specific implementation. Cross-project status, handoffs, dependencies, and evidence boundaries are synchronized through the continuity spine so future collaborators can traverse the system without reconstructing it from chat history.
