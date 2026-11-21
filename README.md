# QORVYNT Web4

QORVYNT Web4 is an independent project for a user-controlled, permissioned web where AI agents, identity, data, and federated services can interact under explicit authority.

**Scope:** AI agent network + decentralized identity/data/permissions + federated network/browser/apps.

## Project status

Early foundation implementation. The first milestone is a small, auditable authorization core. This repository is separate from QORVYNT Lang and Fleur Network.

## Design principles

- **User authority first:** agents receive narrow, explicit capabilities; no implicit access to user data or actions.
- **Deny by default:** missing, expired, revoked, or mismatched grants are denied.
- **Portable identity:** identity identifiers are distinct from authentication keys and service accounts.
- **Data minimization:** services receive only the data required for an authorized operation.
- **Federation, not forced centralization:** nodes can interoperate through documented protocols.
- **Verifiable behavior:** protocol changes require tests and CI evidence.

## Repository map

- `src/lib.rs` — exact-match capability authorization core
- `src/permissions.rs` — permission request validation, approval-to-capability conversion, and structured audit event types
- `src/identity.rs` — canonical key-derived DID identifiers, strict Ed25519 verification, and signed key rotation
- `src/resolver.rs` — signed identity registration, rotation, revocation, and active-key resolution
- `src/storage.rs` — append-only file-backed lifecycle log and signature-verified replay
- `src/protocol.rs` — versioned signed federation envelopes and in-memory replay protection
- `src/vault.rs` — owner/resource-bound XChaCha20-Poly1305 encryption primitive
- `docs/ARCHITECTURE.md` — system boundaries and phased roadmap

## Initial local checks

```sh
cargo test
cargo fmt --check
```

The identity module defines a project-specific `did:qorvynt:` v1 key identifier; it is not a W3C DID-method conformance claim. Strict Ed25519 verification, signed key rotation, and cryptographically verified owner-consent primitives are implemented. File-backed identity lifecycle history and verified replay are implemented as a local single-writer storage adapter. Tamper-evident checkpoints, multi-process coordination, key recovery, encrypted vault persistence/key management, live network transport, durable replay protection, and browser integration are not yet implemented. The federation module currently provides a signed, versioned message envelope with strict recipient, time-window, payload-size, and replay checks; it is transport-independent and not a running peer network.
