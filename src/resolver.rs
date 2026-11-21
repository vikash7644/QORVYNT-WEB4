//! Trusted-key resolution and append-only identity lifecycle history.
//!
//! This first resolver is process-local: its event history is append-only while
//! the instance lives, but is not durable across restarts. Persisted storage and
//! tamper-evident checkpoints are a separate milestone.

use std::collections::BTreeMap;

use crate::identity::{IdentityError, IdentityKey, IdentityRecord, KeyRotation};

const REGISTER_DOMAIN: &[u8] = b"QORVYNT-WEB4-IDENTITY-REGISTER-V1\0";
const REVOKE_DOMAIN: &[u8] = b"QORVYNT-WEB4-IDENTITY-REVOKE-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityEvent {
    Registered {
        did: String,
        occurred_at: u64,
    },
    Rotated {
        old_did: String,
        new_did: String,
        occurred_at: u64,
    },
    Revoked {
        did: String,
        occurred_at: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverError {
    InvalidSignature,
    UnknownIdentity,
    IdentityAlreadyExists,
    IdentityNotActive,
    InvalidRotation,
    NonMonotonicTimestamp,
}

impl From<IdentityError> for ResolverError {
    fn from(_: IdentityError) -> Self {
        Self::InvalidSignature
    }
}

/// A process-local resolver. All lifecycle transitions are signed and ordered.
#[derive(Debug, Default)]
pub struct IdentityResolver {
    records: BTreeMap<String, IdentityRecord>,
    events: Vec<IdentityEvent>,
    last_event_at: Option<u64>,
}

impl IdentityResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn registration_payload(did: &str, created_at: u64) -> Vec<u8> {
        let mut payload = REGISTER_DOMAIN.to_vec();
        append_field(&mut payload, did);
        payload.extend_from_slice(&created_at.to_be_bytes());
        payload
    }

    pub fn revocation_payload(did: &str, revoked_at: u64) -> Vec<u8> {
        let mut payload = REVOKE_DOMAIN.to_vec();
        append_field(&mut payload, did);
        payload.extend_from_slice(&revoked_at.to_be_bytes());
        payload
    }

    pub fn register(
        &mut self,
        key: IdentityKey,
        created_at: u64,
        proof: &[u8; 64],
    ) -> Result<(), ResolverError> {
        let did = key.did().to_owned();
        if self.records.contains_key(&did) {
            return Err(ResolverError::IdentityAlreadyExists);
        }
        self.check_timestamp(created_at)?;
        key.verify(&Self::registration_payload(&did, created_at), proof)
            .map_err(|_| ResolverError::InvalidSignature)?;
        self.records.insert(
            did.clone(),
            IdentityRecord {
                key,
                created_at,
                revoked_at: None,
            },
        );
        self.events.push(IdentityEvent::Registered {
            did,
            occurred_at: created_at,
        });
        self.last_event_at = Some(created_at);
        Ok(())
    }

    pub fn rotate(&mut self, rotation: KeyRotation) -> Result<(), ResolverError> {
        self.check_timestamp(rotation.effective_at)?;
        let old = self
            .records
            .get(&rotation.old_did)
            .ok_or(ResolverError::UnknownIdentity)?;
        if !old.is_active_at(rotation.effective_at) {
            return Err(ResolverError::IdentityNotActive);
        }
        let old_key = old.key.clone();
        let new_key = IdentityKey::from_did(&rotation.new_did)
            .map_err(|_| ResolverError::InvalidRotation)?;
        if self.records.contains_key(&rotation.new_did) {
            return Err(ResolverError::IdentityAlreadyExists);
        }
        rotation
            .verify(&old_key, &new_key)
            .map_err(|_| ResolverError::InvalidSignature)?;

        let old_did = rotation.old_did.clone();
        let new_did = rotation.new_did.clone();
        if let Some(record) = self.records.get_mut(&old_did) {
            record.revoked_at = Some(rotation.effective_at);
        }
        self.records.insert(
            new_did.clone(),
            IdentityRecord {
                key: new_key,
                created_at: rotation.effective_at,
                revoked_at: None,
            },
        );
        self.events.push(IdentityEvent::Rotated {
            old_did,
            new_did,
            occurred_at: rotation.effective_at,
        });
        self.last_event_at = Some(rotation.effective_at);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        did: &str,
        revoked_at: u64,
        signature: &[u8; 64],
    ) -> Result<(), ResolverError> {
        self.check_timestamp(revoked_at)?;
        let record = self
            .records
            .get(did)
            .ok_or(ResolverError::UnknownIdentity)?;
        if !record.is_active_at(revoked_at) {
            return Err(ResolverError::IdentityNotActive);
        }
        record
            .key
            .verify(&Self::revocation_payload(did, revoked_at), signature)
            .map_err(|_| ResolverError::InvalidSignature)?;
        if let Some(record) = self.records.get_mut(did) {
            record.revoked_at = Some(revoked_at);
        }
        self.events.push(IdentityEvent::Revoked {
            did: did.to_owned(),
            occurred_at: revoked_at,
        });
        self.last_event_at = Some(revoked_at);
        Ok(())
    }

    pub fn resolve(&self, did: &str, at: u64) -> Option<&IdentityKey> {
        self.records
            .get(did)
            .filter(|record| record.is_active_at(at))
            .map(|record| &record.key)
    }

    pub fn record(&self, did: &str) -> Option<&IdentityRecord> {
        self.records.get(did)
    }

    pub fn events(&self) -> &[IdentityEvent] {
        &self.events
    }

    fn check_timestamp(&self, timestamp: u64) -> Result<(), ResolverError> {
        if self
            .last_event_at
            .is_some_and(|last| timestamp < last)
        {
            return Err(ResolverError::NonMonotonicTimestamp);
        }
        Ok(())
    }
}

fn append_field(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn identity(key: &SigningKey) -> IdentityKey {
        IdentityKey::from_public_key(key.verifying_key().to_bytes()).unwrap()
    }

    #[test]
    fn registration_requires_proof_of_possession_and_resolves_only_after_creation() {
        let signing = signer(31);
        let key = identity(&signing);
        let did = key.did().to_owned();
        let payload = IdentityResolver::registration_payload(&did, 10);
        let proof = signing
            .sign(&IdentityKey::signature_payload(&payload))
            .to_bytes();
        let mut resolver = IdentityResolver::new();
        assert!(resolver.resolve(&did, 10).is_none());
        resolver.register(key.clone(), 10, &proof).unwrap();
        assert!(resolver.resolve(&did, 9).is_none());
        assert_eq!(resolver.resolve(&did, 10), Some(&key));
        assert_eq!(resolver.events().len(), 1);
        assert_eq!(
            resolver.register(key, 11, &proof),
            Err(ResolverError::IdentityAlreadyExists)
        );
    }

    #[test]
    fn rotation_revokes_old_key_and_activates_proven_successor() {
        let old_signer = signer(32);
        let new_signer = signer(33);
        let old_key = identity(&old_signer);
        let new_key = identity(&new_signer);
        let mut resolver = IdentityResolver::new();
        let registration = IdentityResolver::registration_payload(old_key.did(), 10);
        let proof = old_signer
            .sign(&IdentityKey::signature_payload(&registration))
            .to_bytes();
        resolver.register(old_key.clone(), 10, &proof).unwrap();
        let payload = KeyRotation::signing_payload(old_key.did(), new_key.did(), 20);
        let rotation = KeyRotation {
            old_did: old_key.did().into(),
            new_did: new_key.did().into(),
            effective_at: 20,
            old_key_signature: old_signer.sign(&payload).to_bytes(),
            new_key_proof: new_signer
                .sign(&KeyRotation::new_key_proof_payload(&payload))
                .to_bytes(),
        };
        resolver.rotate(rotation).unwrap();
        assert!(resolver.resolve(old_key.did(), 20).is_none());
        assert_eq!(resolver.resolve(new_key.did(), 20), Some(&new_key));
        assert_eq!(resolver.events().len(), 2);
    }

    #[test]
    fn revocation_requires_identity_signature_and_blocks_future_resolution() {
        let signing = signer(34);
        let key = identity(&signing);
        let did = key.did().to_owned();
        let registration = IdentityResolver::registration_payload(&did, 1);
        let proof = signing
            .sign(&IdentityKey::signature_payload(&registration))
            .to_bytes();
        let mut resolver = IdentityResolver::new();
        resolver.register(key, 1, &proof).unwrap();
        let payload = IdentityResolver::revocation_payload(&did, 5);
        let signature = signing
            .sign(&IdentityKey::signature_payload(&payload))
            .to_bytes();
        resolver.revoke(&did, 5, &signature).unwrap();
        assert!(resolver.resolve(&did, 4).is_some());
        assert!(resolver.resolve(&did, 5).is_none());
        assert_eq!(resolver.events().len(), 2);
    }

    #[test]
    fn rejects_backdated_transitions_and_invalid_signatures() {
        let signing = signer(35);
        let key = identity(&signing);
        let mut resolver = IdentityResolver::new();
        assert_eq!(
            resolver.register(key, 2, &[0; 64]),
            Err(ResolverError::InvalidSignature)
        );
        let signing = signer(36);
        let key = identity(&signing);
        let did = key.did().to_owned();
        let payload = IdentityResolver::registration_payload(&did, 10);
        let proof = signing
            .sign(&IdentityKey::signature_payload(&payload))
            .to_bytes();
        resolver.register(key, 10, &proof).unwrap();
        assert_eq!(
            resolver.revoke(&did, 9, &[0; 64]),
            Err(ResolverError::NonMonotonicTimestamp)
        );
    }
}
