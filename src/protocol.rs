//! Versioned, signed node-to-node message envelopes with replay protection.
//!
//! This is a transport-independent protocol primitive. It does not perform
//! discovery, networking, TLS, rate limiting, or durable replay storage.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};

use crate::identity::IdentityKey;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const ENVELOPE_DOMAIN: &[u8] = b"QORVYNT-WEB4-FEDERATION-ENVELOPE-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub version: u16,
    pub sender: String,
    pub recipient: String,
    pub message_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

impl MessageEnvelope {
    pub fn signing_payload(&self) -> Result<Vec<u8>, EnvelopeError> {
        if self.version != PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        if self.sender.trim().is_empty()
            || self.recipient.trim().is_empty()
            || self.message_id.trim().is_empty()
        {
            return Err(EnvelopeError::EmptyField);
        }
        if self.payload.len() > MAX_MESSAGE_BYTES {
            return Err(EnvelopeError::PayloadTooLarge);
        }
        let mut output = ENVELOPE_DOMAIN.to_vec();
        output.extend_from_slice(&self.version.to_be_bytes());
        append_field(&mut output, self.sender.as_bytes());
        append_field(&mut output, self.recipient.as_bytes());
        append_field(&mut output, self.message_id.as_bytes());
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        append_field(&mut output, &self.payload);
        Ok(output)
    }

    pub fn sign(
        sender: &IdentityKey,
        recipient: impl Into<String>,
        message_id: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        payload: Vec<u8>,
        signing_key: &SigningKey,
    ) -> Result<Self, EnvelopeError> {
        if signing_key.verifying_key().to_bytes() != *sender.public_key() {
            return Err(EnvelopeError::SignerDoesNotMatchSender);
        }
        let mut envelope = Self {
            version: PROTOCOL_VERSION,
            sender: sender.did().to_owned(),
            recipient: recipient.into(),
            message_id: message_id.into(),
            issued_at,
            expires_at,
            payload,
            signature: [0; 64],
        };
        let payload = envelope.signing_payload()?;
        envelope.signature = signing_key
            .sign(&IdentityKey::signature_payload(&payload))
            .to_bytes();
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    UnsupportedVersion,
    EmptyField,
    PayloadTooLarge,
    SignerDoesNotMatchSender,
    SenderMismatch,
    WrongRecipient,
    InvalidTimeWindow,
    MessageExpired,
    IssuedInFuture,
    LifetimeTooLong,
    InvalidSignature,
    Replay,
}

/// In-memory replay guard. Production nodes must persist or share this state
/// across restarts and replicas before accepting messages at scale.
#[derive(Debug, Clone, Default)]
pub struct ReplayGuard {
    seen: BTreeMap<(String, String), u64>,
}

impl ReplayGuard {
    pub fn new() -> Self { Self::default() }

    pub fn accept(
        &mut self,
        envelope: &MessageEnvelope,
        sender_key: &IdentityKey,
        expected_recipient: &str,
        now: u64,
        max_future_skew: u64,
        max_lifetime: u64,
    ) -> Result<(), EnvelopeError> {
        if envelope.sender != sender_key.did() {
            return Err(EnvelopeError::SenderMismatch);
        }
        if envelope.recipient != expected_recipient {
            return Err(EnvelopeError::WrongRecipient);
        }
        if envelope.expires_at <= envelope.issued_at {
            return Err(EnvelopeError::InvalidTimeWindow);
        }
        if envelope.expires_at <= now {
            return Err(EnvelopeError::MessageExpired);
        }
        if envelope.issued_at > now.saturating_add(max_future_skew) {
            return Err(EnvelopeError::IssuedInFuture);
        }
        if envelope.expires_at.saturating_sub(envelope.issued_at) > max_lifetime {
            return Err(EnvelopeError::LifetimeTooLong);
        }
        let payload = envelope.signing_payload()?;
        sender_key.verify(&payload, &envelope.signature)
            .map_err(|_| EnvelopeError::InvalidSignature)?;

        self.seen.retain(|_, expires_at| *expires_at > now);
        let key = (envelope.sender.clone(), envelope.message_id.clone());
        if self.seen.contains_key(&key) {
            return Err(EnvelopeError::Replay);
        }
        self.seen.insert(key, envelope.expires_at);
        Ok(())
    }

    pub fn tracked_messages(&self) -> usize { self.seen.len() }
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn identity(seed: u8) -> (SigningKey, IdentityKey) {
        let signer = SigningKey::from_bytes(&[seed; 32]);
        let key = IdentityKey::from_public_key(signer.verifying_key().to_bytes()).unwrap();
        (signer, key)
    }

    #[test]
    fn accepts_valid_signed_message_once_and_rejects_replay() {
        let (signer, sender) = identity(31);
        let envelope = MessageEnvelope::sign(
            &sender, "did:qorvynt:node:receiver", "msg-001", 100, 160,
            b"agent.task".to_vec(), &signer,
        ).unwrap();
        let mut guard = ReplayGuard::new();
        assert_eq!(guard.accept(&envelope, &sender, "did:qorvynt:node:receiver", 110, 5, 120), Ok(()));
        assert_eq!(guard.tracked_messages(), 1);
        assert_eq!(guard.accept(&envelope, &sender, "did:qorvynt:node:receiver", 110, 5, 120), Err(EnvelopeError::Replay));
    }

    #[test]
    fn rejects_wrong_recipient_expired_and_future_messages() {
        let (signer, sender) = identity(32);
        let envelope = MessageEnvelope::sign(&sender, "node:b", "msg-002", 100, 160, vec![1], &signer).unwrap();
        let mut guard = ReplayGuard::new();
        assert_eq!(guard.accept(&envelope, &sender, "node:c", 110, 5, 120), Err(EnvelopeError::WrongRecipient));
        assert_eq!(guard.accept(&envelope, &sender, "node:b", 160, 5, 120), Err(EnvelopeError::MessageExpired));
        assert_eq!(guard.accept(&envelope, &sender, "node:b", 90, 5, 120), Err(EnvelopeError::IssuedInFuture));
    }

    #[test]
    fn rejects_tampering_and_excessive_lifetime() {
        let (signer, sender) = identity(33);
        let mut envelope = MessageEnvelope::sign(&sender, "node:b", "msg-003", 100, 300, vec![1], &signer).unwrap();
        let mut guard = ReplayGuard::new();
        assert_eq!(guard.accept(&envelope, &sender, "node:b", 110, 5, 120), Err(EnvelopeError::LifetimeTooLong));
        envelope.expires_at = 160;
        assert_eq!(guard.accept(&envelope, &sender, "node:b", 110, 5, 120), Err(EnvelopeError::InvalidSignature));
    }

    #[test]
    fn refuses_signing_key_that_does_not_match_sender_identity() {
        let (_, sender) = identity(34);
        let other = SigningKey::from_bytes(&[35; 32]);
        assert_eq!(MessageEnvelope::sign(&sender, "node:b", "msg-004", 100, 160, vec![], &other), Err(EnvelopeError::SignerDoesNotMatchSender));
    }
}
