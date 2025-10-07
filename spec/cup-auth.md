# CUP Authentication (v0.1)

- Nodes speak only to **allow-listed** public keys.
- Each node publishes a `node_id` and its **public key** (PEM).
- Messages must carry a valid **Ed25519** signature matching the sender’s key.
- **PQC note:** swap Ed25519 for a NIST PQC scheme (e.g., Dilithium) when available in your runtime.

## Allow-list governance (minimum)
- Keys can be added/removed via signed PRs and multi-maintainer review.
- Any removal must include a signed incident note (abuse, policy breach, or compromise).
- 
