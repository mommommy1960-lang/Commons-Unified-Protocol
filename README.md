# Commons Unified Protocol (CUP)

## Local CUP / ATN receiver prototype — October 17, 2026

`python -m src.atn_demo` demonstrates two local node identities exchanging one
signed synthetic message, then rejecting a replay, withdrawn consent and a revoked
sender key. Install `requirements.txt` first. Run tests with
`python -m unittest discover -s tests -v`.

`src/cup_receiver.py` checks the exact recipient, current allow-listed Ed25519 key,
message age, signature and an explicit current-consent callback. SQLite stores
accepted sender/nonce pairs; supply a file path for replay rejection across restarts.
The receiver records messages; it does not execute their content. JSON extension
fields and ambiguous pipe-delimited identifiers are rejected. The previously empty
Phi schema now documents the implemented envelope.

This is an in-process transport demonstration, not a deployed global network,
post-quantum implementation, independently reviewed security system or commercial
delivery guarantee. Registry/policy administration, authenticated key updates,
cross-process revocation ordering, storage quotas, encryption and independent
review remain deployment work. Message freshness depends on a trustworthy clock.
The legacy signature-only `verify` helper is not the acceptance boundary.

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


## Mutual collaboration boundaries

Before protected exchange or shared work, read our [collaboration boundaries](https://github.com/mommommy1960-lang/commons-sentience-sandbox/blob/main/docs/continuity/PUBLIC_COLLABORATION_BOUNDARIES.md). Both parties retain their existing rights; scope, confidentiality, contributions, access and exit must be agreed for the actual engagement. Existing licenses and lawful reporting rights remain unaffected. This operating notice is not an executed contract.


### License text needs review

[LICENSE-CERL-1.0-PLACEHOLDER.txt](LICENSE-CERL-1.0-PLACEHOLDER.txt) is explicitly a placeholder and contains an existing public-use statement. It is not a complete license instrument. No replacement license or withdrawal of earlier rights is made by this notice. Resolve the authoritative text and scope before relying on a specific reuse or commercialization grant.
