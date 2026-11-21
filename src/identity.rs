//! Ed25519 identity keys and signed key-rotation statements.
//!
//! DID method v1: `did:qorvynt:<lowercase-hex-ed25519-public-key>`.
//! This is a project-specific key identifier, not a W3C DID-method claim.
//! An identifier is not proof of control; signatures must be verified.

use ed25519_dalek::{Signature, VerifyingKey};

const DID_PREFIX: &str = "did:qorvynt:";
const SIGNATURE_DOMAIN: &[u8] = b"QORVYNT-WEB4-IDENTITY-V1\0";
const ROTATION_DOMAIN: &[u8] = b"QORVYNT-WEB4-KEY-ROTATION-V1\0";
const NEW_KEY_PROOF_DOMAIN: &[u8] = b"QORVYNT-WEB4-NEW-KEY-PROOF-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKey {
    did: String,
    public_key: [u8; 32],
}

impl IdentityKey {
    pub fn from_public_key(public_key: [u8; 32]) -> Result<Self, IdentityError> {
        VerifyingKey::from_bytes(&public_key).map_err(|_| IdentityError::InvalidPublicKey)?;
        let did = format!("{DID_PREFIX}{}", encode_hex(&public_key));
        Ok(Self { did, public_key })
    }

    /// Parse only the canonical lowercase-hex v1 identifier.
    pub fn from_did(did: &str) -> Result<Self, IdentityError> {
        let encoded = did
            .strip_prefix(DID_PREFIX)
            .ok_or(IdentityError::InvalidDid)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IdentityError::InvalidDid);
        }
        let bytes = decode_hex(encoded).ok_or(IdentityError::InvalidDid)?;
        let mut public_key = [0_u8; 32];
        public_key.copy_from_slice(&bytes);
        let identity = Self::from_public_key(public_key)?;
        if identity.did != did {
            return Err(IdentityError::InvalidDid);
        }
        Ok(identity)
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Verify a domain-separated application message with strict Ed25519 checks.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), IdentityError> {
        let payload = domain_payload(SIGNATURE_DOMAIN, message);
        self.verify_raw(&payload, signature)
    }

    fn verify_raw(&self, payload: &[u8], signature: &[u8; 64]) -> Result<(), IdentityError> {
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        key.verify_strict(payload, &Signature::from_bytes(signature))
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

/// A rotation requires authorization by the old key and proof of possession
/// by the successor key. A resolver must still persist and enforce its history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotation {
    pub old_did: String,
    pub new_did: String,
    pub effective_at: u64,
    pub old_key_signature: [u8; 64],
    pub new_key_proof: [u8; 64],
}

impl KeyRotation {
    pub fn signing_payload(old_did: &str, new_did: &str, effective_at: u64) -> Vec<u8> {
        let statement = format!("{old_did}\n{new_did}\n{effective_at}");
        domain_payload(ROTATION_DOMAIN, statement.as_bytes())
    }

    pub fn new_key_proof_payload(rotation_payload: &[u8]) -> Vec<u8> {
        domain_payload(NEW_KEY_PROOF_DOMAIN, rotation_payload)
    }

    pub fn verify(
        &self,
        old_key: &IdentityKey,
        new_key: &IdentityKey,
    ) -> Result<(), IdentityError> {
        if self.old_did != old_key.did()
            || self.new_did != new_key.did()
            || self.old_did == self.new_did
        {
            return Err(IdentityError::InvalidRotation);
        }
        let payload = Self::signing_payload(&self.old_did, &self.new_did, self.effective_at);
        old_key.verify_raw(&payload, &self.old_key_signature)?;
        new_key.verify_raw(&Self::new_key_proof_payload(&payload), &self.new_key_proof)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecord {
    pub key: IdentityKey,
    pub created_at: u64,
    /// Revocation takes effect at this timestamp, inclusive.
    pub revoked_at: Option<u64>,
}

impl IdentityRecord {
    pub fn is_active_at(&self, timestamp: u64) -> bool {
        timestamp >= self.created_at
            && self
                .revoked_at
                .map_or(true, |revoked_at| timestamp < revoked_at)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    InvalidDid,
    InvalidPublicKey,
    InvalidSignature,
    InvalidRotation,
}

fn domain_payload(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(domain.len() + message.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(message);
    payload
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn did_is_canonical_and_round_trips_public_key() {
        let signer = signing_key(7);
        let identity = IdentityKey::from_public_key(signer.verifying_key().to_bytes()).unwrap();
        let parsed = IdentityKey::from_did(identity.did()).unwrap();
        assert_eq!(parsed, identity);
        assert_eq!(parsed.public_key(), &signer.verifying_key().to_bytes());
        assert_eq!(
            IdentityKey::from_did(&identity.did().to_uppercase()),
            Err(IdentityError::InvalidDid)
        );
    }

    #[test]
    fn verifies_domain_separated_signatures_for_the_correct_key_only() {
        let signer = signing_key(9);
        let identity = IdentityKey::from_public_key(signer.verifying_key().to_bytes()).unwrap();
        let message = b"agent:planner:data.read";
        let signature = signer
            .sign(&domain_payload(SIGNATURE_DOMAIN, message))
            .to_bytes();
        assert_eq!(identity.verify(message, &signature), Ok(()));
        assert_eq!(
            identity.verify(b"agent:planner:data.write", &signature),
            Err(IdentityError::InvalidSignature)
        );
        let other =
            IdentityKey::from_public_key(signing_key(10).verifying_key().to_bytes()).unwrap();
        assert_eq!(
            other.verify(message, &signature),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rotation_requires_old_authorization_and_new_key_possession() {
        let old_signer = signing_key(11);
        let new_signer = signing_key(12);
        let old_key = IdentityKey::from_public_key(old_signer.verifying_key().to_bytes()).unwrap();
        let new_key = IdentityKey::from_public_key(new_signer.verifying_key().to_bytes()).unwrap();
        let payload = KeyRotation::signing_payload(old_key.did(), new_key.did(), 1_700_000_000);
        let rotation = KeyRotation {
            old_did: old_key.did().to_owned(),
            new_did: new_key.did().to_owned(),
            effective_at: 1_700_000_000,
            old_key_signature: old_signer.sign(&payload).to_bytes(),
            new_key_proof: new_signer
                .sign(&KeyRotation::new_key_proof_payload(&payload))
                .to_bytes(),
        };
        assert_eq!(rotation.verify(&old_key, &new_key), Ok(()));
        let mut tampered = rotation.clone();
        tampered.effective_at += 1;
        assert_eq!(
            tampered.verify(&old_key, &new_key),
            Err(IdentityError::InvalidSignature)
        );
        let wrong_successor =
            IdentityKey::from_public_key(signing_key(13).verifying_key().to_bytes()).unwrap();
        assert_eq!(
            rotation.verify(&old_key, &wrong_successor),
            Err(IdentityError::InvalidRotation)
        );
    }

    #[test]
    fn identity_record_enforces_creation_and_revocation_times() {
        let key = IdentityKey::from_public_key(signing_key(42).verifying_key().to_bytes()).unwrap();
        let record = IdentityRecord {
            key,
            created_at: 100,
            revoked_at: Some(200),
        };
        assert!(!record.is_active_at(99));
        assert!(record.is_active_at(100));
        assert!(record.is_active_at(199));
        assert!(!record.is_active_at(200));
    }
}
