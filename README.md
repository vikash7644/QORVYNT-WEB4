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
- `src/permissions.rs` — permission request validation, approval-to-capability conversion, and structured audit event types\n- `src/identity.rs` — canonical key-derived DID identifiers, strict Ed25519 verification, signed key rotation, and local revocation-time model
- `docs/ARCHITECTURE.md` — system boundaries and phased roadmap

## Initial local checks

```sh
cargo test
cargo fmt --check
```

The identity module defines a project-specific `did:qorvynt:` v1 key identifier; it is not a W3C DID-method conformance claim. Key verification and rotation primitives are implemented, but identity discovery, durable rotation/revocation history, key recovery, encrypted storage, network transport, and browser integration are not yet implemented.
