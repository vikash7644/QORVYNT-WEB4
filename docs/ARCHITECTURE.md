# QORVYNT Web4 architecture

## Goal

Build a federated, user-controlled application network in which people can delegate bounded tasks to AI agents without surrendering identity, data, or decision authority.

## System boundaries

1. **Identity** — portable subject identifiers, key binding, key rotation, recovery, and revocation. An identifier is not proof of control.
2. **Authorization** — explicit capabilities scoped to a subject, resource, action, and validity period. Deny by default. This is the first code milestone.
3. **Agent runtime** — agents declare requested capabilities before acting; every protected operation is checked at the resource boundary.
4. **Personal data vault** — encrypted-at-rest and encrypted-in-transit storage, owner-controlled export/deletion, and auditable access grants.
5. **Federation protocol** — authenticated node-to-node discovery and message exchange with replay protection and version negotiation.
6. **Apps and browser** — clients display identity, origin, requested permissions, and meaningful consent before delegation.

## Non-goals for the first milestone

- No token, coin, chain consensus, or wallet is required.
- No implicit trust based on a domain, agent name, or network membership.
- No claim of production cryptography or decentralized identity until key formats, signature verification, rotation, recovery, and interoperability tests exist.
- QORVYNT Lang and Fleur Network remain separate repositories and products.

## Authorization contract

A capability grant binds exactly:
- subject principal
- protected resource
- one or more exact action identifiers
- expiration timestamp
- revocation state

A request is denied when any binding differs, the grant has expired, or it is revoked. Wildcards and prefix matching are intentionally absent in the initial core. Authentication and signature verification must happen before the policy evaluator is called.

## Phased delivery

### M0 — policy core (current)
- [x] Define exact-match capability model
- [x] Deny expired, revoked, and mismatched requests
- [x] Add unit tests for allow/deny behavior
- [ ] CI validation and code review

### M1 — identity and key lifecycle
- DID method specification and canonical encoding
- Ed25519 key binding and signature verification
- Key rotation, recovery, and revocation semantics
- Test vectors and cross-implementation fixtures

### M2 — agent permissions and audit
- Capability request/approval/revocation flow
- Resource-side enforcement middleware
- Append-only audit event schema with privacy minimization
- Human-readable consent receipts

### M3 — personal data vault
- Encryption envelope and key ownership model
- Export, deletion, backup, and recovery
- Per-resource and per-field authorization

### M4 — federation
- Node identity, mutual authentication, replay protection
- Versioned message envelope and discovery
- Rate limits, abuse reporting, and trust boundaries

### M5 — Web4 apps and browser
- Permission-aware app manifest
- Origin identity and clear consent UX
- Agent sandbox and user-visible action confirmations

Each milestone requires tests, threat-model review, and green CI before being called complete.
