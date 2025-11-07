# Epoch-3: Identity, Attestation & Key Continuity

**Status:** Draft  
**Version:** 0.3.0-dev  
**Initiated:** 2025-11-07  
**Chain of Custody:** Mya P. Brown (Origin Architect), Hassan (External Integrity Engineer), Alex (Seattle Public Library — Field Ops Technical Assist)

---

## Purpose and Scope

Epoch-3 establishes the **identity verification**, **attestation pipeline**, and **cryptographic key lifecycle management** framework for the Commons Unified Protocol (CUP). This epoch ensures that all protocol participants maintain verifiable cryptographic identities and that all artifacts are properly attested through a transparent chain of custody.

---

## 1. Cryptographic Identity Enforcement

**Objective:** Mandate and enforce cryptographic identity for all protocol participants.

### Requirements
- All nodes MUST maintain Ed25519 key pairs for identity verification
- Public keys MUST be registered in the allow-list before participation
- Identity binding MUST be cryptographically verifiable
- Key ownership proofs MUST be provided upon registration

### Implementation Status
- **Draft:** Identity enforcement framework defined
- **Pending:** Integration with node registration process
- **Pending:** Key verification tooling

### Chain of Custody
- Identity requirements authored by Mya P. Brown
- Cryptographic specifications reviewed by Hassan
- Field deployment considerations by Alex (SPL)

---

## 2. Sigstore Key Lifecycle Plan

**Objective:** Define comprehensive key lifecycle management aligned with Sigstore best practices.

### Lifecycle Phases
1. **Key Generation:** Secure key generation with entropy validation
2. **Key Distribution:** Secure channel for public key distribution
3. **Key Rotation:** Defined rotation schedule and emergency rotation procedures
4. **Key Revocation:** Certificate revocation list (CRL) or similar mechanism
5. **Key Archive:** Secure archival of retired keys for audit purposes

### Sigstore Integration Points
- Use of ephemeral certificates for signing
- Transparency log integration for public verification
- Rekor-based artifact signing and verification
- Fulcio certificate authority integration (future)

### Implementation Status
- **Draft:** Lifecycle phases documented
- **Pending:** Sigstore toolchain integration
- **Pending:** Automated rotation mechanisms

### Chain of Custody
- Lifecycle framework designed by Hassan
- Sigstore alignment verified by Mya P. Brown
- Operational constraints reviewed by Alex (SPL)

---

## 3. Attestation Pipeline (draft stage)

**Objective:** Establish automated attestation for all protocol artifacts and releases.

### Pipeline Components
1. **Build Attestation:** SLSA-compliant build provenance
2. **Code Signing:** Automated signing of releases and artifacts
3. **Verification Layer:** Public verification of all signatures
4. **Transparency Logging:** Immutable record of all attestations

### Attestation Scope
- Source code commits (GPG signatures)
- Release artifacts (Sigstore signatures)
- Container images (Cosign signatures)
- Binary distributions (in-toto attestations)

### Implementation Status
- **Draft:** Pipeline architecture defined
- **Pending:** SLSA level determination
- **Pending:** Automated signing integration
- **Pending:** Public verification endpoint

### Chain of Custody
- Pipeline design by Mya P. Brown and Hassan
- Security requirements validated by Hassan
- Operational feasibility assessed by Alex (SPL)

---

## 4. CERL Cross-Compliance Clause Hooks

**Objective:** Ensure full compliance with Commons Ethical Research License (CERL-1.0) requirements.

### Compliance Hooks
- **§1.3 Attribution Requirements:** Automated provenance tracking in all artifacts
- **§2.0 Non-Privatization Clause:** Attestation pipeline verifies license compliance
- **§4.2 Derivatives and Modifications:** Chain-of-custody for all modifications
- **§7.x Future Provisions:** Extensibility hooks for future CERL amendments

### Implementation Status
- **Draft:** Compliance mapping documented
- **Pending:** Automated compliance verification
- **Pending:** License header enforcement
- **Pending:** Derivative work tracking

### Chain of Custody
- CERL alignment designed by Mya P. Brown
- Legal compliance verified by origin counsel (pending)
- Implementation strategy by Hassan

---

## 5. Next Milestone: Live Signing Enforcement

**Target:** Epoch-4 (v0.4.0)

### Objectives
- [ ] Full Sigstore integration deployed to production
- [ ] All releases signed with ephemeral certificates
- [ ] Public transparency log operational
- [ ] Automated key rotation in production
- [ ] Third-party verification tooling available
- [ ] SLSA Level 3 compliance achieved

### Prerequisites for Milestone
- Completion of Epoch-3 attestation pipeline
- Security audit of key lifecycle implementation
- Community testing of verification tooling
- Documentation for external verifiers

---

## Chain of Custody Attestation

This document represents the collective work of:

- **Mya P. Brown** — Origin Architect, protocol design and CERL compliance
- **Hassan** — External Integrity Engineer, cryptographic implementation and security
- **Alex (Seattle Public Library)** — Field Ops Technical Assist, operational feasibility and deployment

All sections remain in **draft stage** pending implementation, security review, and community feedback.

**Document Version:** 0.3.0-draft  
**Last Updated:** 2025-11-07  
**Next Review:** Upon implementation commencement

---

## References

- Commons Ethical Research License (CERL-1.0): `LICENSE-CERL-1.0-PLACEHOLDER.txt`
- Sigstore Documentation: https://docs.sigstore.dev/
- SLSA Framework: https://slsa.dev/
- CUP Protocol Specification: `spec/cup-auth.md`

---

*This provenance document is maintained under the same CERL-1.0 license as the Commons Unified Protocol.*
