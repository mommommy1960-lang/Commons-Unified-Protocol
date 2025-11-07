# Commons Unified Protocol (CUP)

![CI](https://github.com/mommommy1960-lang/Commons-Unified-Protocol/workflows/CI/badge.svg?branch=main)

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
### Signature rules
Sign the bytes of:
`phi_version|from|to|intent|timestamp|nonce|SHA256(content)`

Attach the Base64 signature in `signature`.

---

## Provenance & Development Epochs

The Commons Unified Protocol maintains a transparent chain-of-custody through documented development epochs:

- **Epoch-3 (v0.3.0-dev):** Identity, Attestation & Key Continuity — *In Progress*
  - Cryptographic identity enforcement
  - Sigstore key lifecycle planning
  - Attestation pipeline framework
  - CERL cross-compliance hooks
  - See: [`docs/provenance/epoch-3/README.md`](docs/provenance/epoch-3/README.md)

For contributor information and chain-of-custody details, see [`docs/contributors.md`](docs/contributors.md).

---

## License

This project is licensed under the Commons Ethical Research License (CERL-1.0).  
See [`LICENSE-CERL-1.0-PLACEHOLDER.txt`](LICENSE-CERL-1.0-PLACEHOLDER.txt) for details.

All contributions remain in the commons and cannot be privatized or captured.
