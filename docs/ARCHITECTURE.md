# QORVYNT Web4 architecture

## Goal

Build a federated, user-controlled application network in which people can delegate bounded tasks to AI agents without surrendering identity, data, or decision authority.

## System boundaries

1. **Identity** — portable subject identifiers, key binding, key rotation, recovery, and revocation. An identifier is not proof of control.
2. **Authorization** — explicit capabilities scoped to a subject, resource, action, and validity period. Deny by default.
3. **Agent runtime** — agents declare requested capabilities before acting; every protected operation is checked at the resource boundary.
4. **Personal data vault** — encrypted-at-rest and encrypted-in-transit storage, owner-controlled export/deletion, and auditable access grants.
5. **Federation protocol** — authenticated node-to-node discovery and message exchange with replay protection and version negotiation.
6. **Apps and browser** — clients display identity, origin, requested permissions, and meaningful consent before delegation.

## Non-goals for the initial foundation

- No token, coin, chain consensus, or wallet is required.
- No implicit trust based on a domain, agent name, or network membership.
- The `did:qorvynt:` identifier is a project-specific v1 draft, not a claim of W3C DID-method registration or conformance.
- The local file-backed identity log supports signed-operation replay; it is not a distributed resolver, key-recovery service, or tamper-proof audit system.
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

### M0 — policy core
- [x] Define exact-match capability model
- [x] Deny expired, revoked, and mismatched requests
- [x] Add unit tests for allow/deny behavior
- [ ] CI validation and code review

### M1 — identity and key lifecycle
- [x] Define canonical project-specific `did:qorvynt:` v1 identifiers from Ed25519 public keys
- [x] Verify domain-separated Ed25519 signatures with strict verification
- [x] Require old-key authorization and new-key proof for rotation statements
- [x] Model identity creation and revocation timestamps
- [x] In-memory trusted-key resolver with signed registration, rotation, revocation, and append-only event history
- [x] File-backed append-only identity operation log with signature-verified replay and fail-closed truncated-log handling
- [ ] Tamper-evident checkpoints, multi-process coordination, and production resolver service
- [ ] Key recovery, interoperability fixtures, and independent security review

### M2 — agent permissions and audit
- [x] Validate explicit permission requests (non-empty, unique actions, bounded validity)
- [x] Convert a declared resource-owner approval into an exact-scope capability
- [x] Define structured approval audit event types
- [x] Verify resource-owner approval signatures against the declared owner key
- [x] Resolve owner keys and enforce active/revoked identity status before approval
- [ ] Durable tamper-evident audit storage and resource-side enforcement middleware
- [ ] Denial/revocation workflow and human-readable consent receipts

### M3 — personal data vault
- [ ] Encryption envelope and key ownership model
- [ ] Export, deletion, backup, and recovery
- [ ] Per-resource and per-field authorization

### M4 — federation
- [ ] Node identity, mutual authentication, replay protection
- [ ] Versioned message envelope and discovery
- [ ] Rate limits, abuse reporting, and trust boundaries

### M5 — Web4 apps and browser
- [ ] Permission-aware app manifest
- [ ] Origin identity and clear consent UX
- [ ] Agent sandbox and user-visible action confirmations

Each milestone requires tests, threat-model review, and green CI before being called complete.
