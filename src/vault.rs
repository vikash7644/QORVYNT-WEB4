//! Authenticated encryption primitives for owner-scoped Web4 vault records.
//!
//! The caller is responsible for generating and protecting a random 256-bit
//! key and a unique random 192-bit nonce per key. Never reuse a nonce with the
//! same key. Key derivation, key wrapping, rotation, durable storage, and
//! transport are intentionally outside this small primitive.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

pub const VAULT_FORMAT_VERSION: u16 = 1;
pub const VAULT_KEY_BYTES: usize = 32;
pub const VAULT_NONCE_BYTES: usize = 24;

const VAULT_DOMAIN: &[u8] = b"QORVYNT-WEB4-DATA-VAULT-V1\\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedRecord {
    pub version: u16,
    pub owner_did: String,
    pub resource_id: String,
    pub nonce: [u8; VAULT_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    UnsupportedVersion, EmptyOwner, EmptyResource, PlaintextTooLarge, AuthenticationFailed,
}

pub struct DataVault;

impl DataVault {
    /// Encrypt plaintext with XChaCha20-Poly1305.
    /// The caller must supply a random 32-byte key and a fresh random 24-byte nonce.
    /// Never reuse a nonce with the same key. Owner and resource are authenticated as AAD.
    pub fn encrypt(
        owner_did: impl Into<String>, resource_id: impl Into<String>, plaintext: &[u8],
        key: &[u8; VAULT_KEY_BYTES], nonce: [u8; VAULT_NONCE_BYTES],
    ) -> Result<EncryptedRecord, VaultError> {
        let owner_did = owner_did.into();
        let resource_id = resource_id.into();
        validate_labels(&owner_did, &resource_id)?;
        if plaintext.len() > super::protocol::MAX_MESSAGE_BYTES {
            return Err(VaultError::PlaintextTooLarge);
        }
        let cipher = XChaCha20Poly1305::new(key.into());
        let aad = associated_data(VAULT_FORMAT_VERSION, &owner_did, &resource_id);
        let ciphertext = cipher.encrypt(
            XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad },
        ).map_err(|_| VaultError::AuthenticationFailed)?;
        Ok(EncryptedRecord { version: VAULT_FORMAT_VERSION, owner_did, resource_id, nonce, ciphertext })
    }

    /// Decrypt only when owner and resource exactly match the authenticated labels.
    pub fn decrypt(
        record: &EncryptedRecord, expected_owner: &str, expected_resource: &str,
        key: &[u8; VAULT_KEY_BYTES],
    ) -> Result<Vec<u8>, VaultError> {
        if record.version != VAULT_FORMAT_VERSION { return Err(VaultError::UnsupportedVersion); }
        validate_labels(expected_owner, expected_resource)?;
        if record.owner_did != expected_owner || record.resource_id != expected_resource {
            return Err(VaultError::AuthenticationFailed);
        }
        let cipher = XChaCha20Poly1305::new(key.into());
        let aad = associated_data(record.version, expected_owner, expected_resource);
        cipher.decrypt(XNonce::from_slice(&record.nonce), Payload { msg: &record.ciphertext, aad: &aad })
            .map_err(|_| VaultError::AuthenticationFailed)
    }
}

fn validate_labels(owner: &str, resource: &str) -> Result<(), VaultError> {
    if owner.trim().is_empty() { return Err(VaultError::EmptyOwner); }
    if resource.trim().is_empty() { return Err(VaultError::EmptyResource); }
    Ok(())
}

fn associated_data(version: u16, owner: &str, resource: &str) -> Vec<u8> {
    let mut aad = VAULT_DOMAIN.to_vec();
    aad.extend_from_slice(&version.to_be_bytes());
    append_field(&mut aad, owner.as_bytes());
    append_field(&mut aad, resource.as_bytes());
    aad
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    const OWNER: &str = "did:qorvynt:user:alice";
    const RESOURCE: &str = "vault:alice:profile";
    fn key() -> [u8; VAULT_KEY_BYTES] { [0x42; VAULT_KEY_BYTES] }
    fn nonce() -> [u8; VAULT_NONCE_BYTES] { [0x24; VAULT_NONCE_BYTES] }

    #[test]
    fn encrypts_and_decrypts_owner_scoped_record() {
        let record = DataVault::encrypt(OWNER, RESOURCE, b"private profile", &key(), nonce()).unwrap();
        assert_ne!(record.ciphertext, b"private profile");
        assert_eq!(DataVault::decrypt(&record, OWNER, RESOURCE, &key()).unwrap(), b"private profile");
    }

    #[test]
    fn rejects_wrong_owner_resource_and_key() {
        let record = DataVault::encrypt(OWNER, RESOURCE, b"secret", &key(), nonce()).unwrap();
        assert_eq!(DataVault::decrypt(&record, "did:qorvynt:user:bob", RESOURCE, &key()), Err(VaultError::AuthenticationFailed));
        assert_eq!(DataVault::decrypt(&record, OWNER, "vault:alice:payments", &key()), Err(VaultError::AuthenticationFailed));
        assert_eq!(DataVault::decrypt(&record, OWNER, RESOURCE, &[0x99; VAULT_KEY_BYTES]), Err(VaultError::AuthenticationFailed));
    }

    #[test]
    fn rejects_ciphertext_and_nonce_tampering() {
        let mut record = DataVault::encrypt(OWNER, RESOURCE, b"secret", &key(), nonce()).unwrap();
        record.ciphertext[0] ^= 1;
        assert_eq!(DataVault::decrypt(&record, OWNER, RESOURCE, &key()), Err(VaultError::AuthenticationFailed));
        let mut record = DataVault::encrypt(OWNER, RESOURCE, b"secret", &key(), nonce()).unwrap();
        record.nonce[0] ^= 1;
        assert_eq!(DataVault::decrypt(&record, OWNER, RESOURCE, &key()), Err(VaultError::AuthenticationFailed));
    }

    #[test]
    fn rejects_empty_labels_and_oversized_plaintext() {
        assert_eq!(DataVault::encrypt("", RESOURCE, b"x", &key(), nonce()), Err(VaultError::EmptyOwner));
        assert_eq!(DataVault::encrypt(OWNER, "", b"x", &key(), nonce()), Err(VaultError::EmptyResource));
        let large = vec![0; super::super::protocol::MAX_MESSAGE_BYTES + 1];
        assert_eq!(DataVault::encrypt(OWNER, RESOURCE, &large, &key(), nonce()), Err(VaultError::PlaintextTooLarge));
    }
}