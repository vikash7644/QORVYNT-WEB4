//! Permission request, approval, and audit-event data types.
//!
//! These are deterministic domain primitives. Signed approvals verify owner
//! consent, but the caller must still check key activity in a trusted resolver.
//! Audit events are not persisted by this module.

use crate::{identity::IdentityKey, Action, Capability, PrincipalId, ResourceId};

/// A request for narrowly-scoped access, submitted by an already identified agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRequest {
    pub id: String,
    pub requester: PrincipalId,
    /// Principal authorized to approve access to this resource.
    pub resource_owner: PrincipalId,
    pub resource: ResourceId,
    pub actions: Vec<Action>,
    pub requested_at: u64,
    pub expires_at: u64,
}

impl PermissionRequest {
    /// Build an unambiguous, deterministic message for owner consent.
    pub fn approval_signing_payload(&self, approved_at: u64) -> Vec<u8> {
        let mut payload = b"QORVYNT-WEB4-PERMISSION-APPROVAL-V1\0".to_vec();
        append_field(&mut payload, &self.id);
        append_field(&mut payload, &self.requester);
        append_field(&mut payload, &self.resource_owner);
        append_field(&mut payload, &self.resource);
        append_u64(&mut payload, self.requested_at);
        append_u64(&mut payload, self.expires_at);
        append_u64(&mut payload, approved_at);
        append_u64(&mut payload, self.actions.len() as u64);
        for action in &self.actions {
            append_field(&mut payload, action);
        }
        payload
    }

    /// Reject malformed or ambiguous requests before they reach a consent UI.
    pub fn validate(&self) -> Result<(), RequestValidationError> {
        if self.id.trim().is_empty() {
            return Err(RequestValidationError::EmptyRequestId);
        }
        if self.requester.trim().is_empty() {
            return Err(RequestValidationError::EmptyRequester);
        }
        if self.resource_owner.trim().is_empty() {
            return Err(RequestValidationError::EmptyResourceOwner);
        }
        if self.resource.trim().is_empty() {
            return Err(RequestValidationError::EmptyResource);
        }
        if self.actions.is_empty() {
            return Err(RequestValidationError::NoActions);
        }
        if self.actions.iter().any(|action| action.trim().is_empty()) {
            return Err(RequestValidationError::EmptyAction);
        }
        for (index, action) in self.actions.iter().enumerate() {
            if self.actions[..index].contains(action) {
                return Err(RequestValidationError::DuplicateAction);
            }
        }
        if self.expires_at <= self.requested_at {
            return Err(RequestValidationError::InvalidValidityWindow);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestValidationError {
    EmptyRequestId,
    EmptyRequester,
    EmptyResourceOwner,
    EmptyResource,
    NoActions,
    EmptyAction,
    DuplicateAction,
    InvalidValidityWindow,
}

/// A consent decision represented as a structured, reviewable event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    Requested {
        request_id: String,
        requester: PrincipalId,
        resource: ResourceId,
        actions: Vec<Action>,
        occurred_at: u64,
    },
    Approved {
        request_id: String,
        approver: PrincipalId,
        occurred_at: u64,
        capability_expires_at: u64,
    },
    Denied {
        request_id: String,
        approver: PrincipalId,
        occurred_at: u64,
    },
    Revoked {
        request_id: String,
        revoker: PrincipalId,
        occurred_at: u64,
    },
}

/// Validate an explicit approval and produce the capability it authorizes.
///
/// The caller remains responsible for authenticating the approver and storing
/// the returned event in a durable, tamper-evident audit system.
pub fn approve_request(
    request: &PermissionRequest,
    approver: &str,
    approved_at: u64,
) -> Result<(Capability, AuditEvent), ApprovalError> {
    request.validate().map_err(ApprovalError::InvalidRequest)?;
    if approver.trim().is_empty() {
        return Err(ApprovalError::EmptyApprover);
    }
    if approver != request.resource_owner.as_str() {
        return Err(ApprovalError::ApproverNotResourceOwner);
    }
    if approved_at < request.requested_at || approved_at >= request.expires_at {
        return Err(ApprovalError::ApprovalOutsideRequestWindow);
    }

    let capability = Capability {
        subject: request.requester.clone(),
        resource: request.resource.clone(),
        actions: request.actions.clone(),
        expires_at: request.expires_at,
        revoked: false,
    };
    let event = AuditEvent::Approved {
        request_id: request.id.clone(),
        approver: approver.to_owned(),
        occurred_at: approved_at,
        capability_expires_at: request.expires_at,
    };
    Ok((capability, event))
}

/// Approve only after verifying a signature from the declared resource owner.
/// The caller must still ensure the identity key is active in its trusted resolver.
pub fn approve_request_with_signature(
    request: &PermissionRequest,
    approver_key: &IdentityKey,
    approved_at: u64,
    signature: &[u8; 64],
) -> Result<(Capability, AuditEvent), ApprovalError> {
    request.validate().map_err(ApprovalError::InvalidRequest)?;
    if approver_key.did() != request.resource_owner {
        return Err(ApprovalError::ApproverNotResourceOwner);
    }
    approver_key
        .verify(&request.approval_signing_payload(approved_at), signature)
        .map_err(|_| ApprovalError::InvalidApproverSignature)?;
    approve_request(request, approver_key.did(), approved_at)
}

fn append_field(output: &mut Vec<u8>, value: &str) {
    append_u64(output, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalError {
    InvalidRequest(RequestValidationError),
    EmptyApprover,
    ApproverNotResourceOwner,
    InvalidApproverSignature,
    ApprovalOutsideRequestWindow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn request() -> PermissionRequest {
        PermissionRequest {
            id: "req-001".into(),
            requester: "did:qorvynt:agent:planner".into(),
            resource_owner: "did:qorvynt:user:owner".into(),
            resource: "vault:user:notes".into(),
            actions: vec!["data.read".into()],
            requested_at: 100,
            expires_at: 500,
        }
    }

    #[test]
    fn approval_creates_only_the_requested_capability() {
        let (capability, event) = approve_request(&request(), "did:qorvynt:user:owner", 200)
            .expect("valid owner approval");
        assert_eq!(capability.subject, "did:qorvynt:agent:planner");
        assert_eq!(capability.resource, "vault:user:notes");
        assert_eq!(capability.actions, vec!["data.read"]);
        assert_eq!(capability.expires_at, 500);
        assert!(!capability.revoked);
        assert_eq!(
            event,
            AuditEvent::Approved {
                request_id: "req-001".into(),
                approver: "did:qorvynt:user:owner".into(),
                occurred_at: 200,
                capability_expires_at: 500,
            }
        );
    }

    #[test]
    fn signed_approval_requires_owner_key_and_exact_request_contents() {
        let signer = SigningKey::from_bytes(&[23; 32]);
        let owner_key = IdentityKey::from_public_key(signer.verifying_key().to_bytes()).unwrap();
        let mut request = request();
        request.resource_owner = owner_key.did().to_owned();
        let payload = request.approval_signing_payload(200);
        let signature = signer.sign(&IdentityKey::signature_payload(&payload)).to_bytes();

        assert!(approve_request_with_signature(&request, &owner_key, 200, &signature).is_ok());

        let mut tampered = request.clone();
        tampered.actions.push("data.write".into());
        assert_eq!(
            approve_request_with_signature(&tampered, &owner_key, 200, &signature),
            Err(ApprovalError::InvalidApproverSignature)
        );

        let other_signer = SigningKey::from_bytes(&[24; 32]);
        let other_key =
            IdentityKey::from_public_key(other_signer.verifying_key().to_bytes()).unwrap();
        assert_eq!(
            approve_request_with_signature(&request, &other_key, 200, &signature),
            Err(ApprovalError::ApproverNotResourceOwner)
        );
    }

    #[test]
    fn rejects_duplicate_actions_and_invalid_approval_times() {
        let mut invalid = request();
        invalid.actions.push("data.read".into());
        assert_eq!(
            invalid.validate(),
            Err(RequestValidationError::DuplicateAction)
        );
        assert_eq!(
            approve_request(&request(), "did:qorvynt:user:owner", 500),
            Err(ApprovalError::ApprovalOutsideRequestWindow)
        );
    }

    #[test]
    fn rejects_non_owner_approval() {
        assert_eq!(
            approve_request(&request(), "did:qorvynt:user:other", 200),
            Err(ApprovalError::ApproverNotResourceOwner)
        );
    }

    #[test]
    fn rejects_empty_approver_and_empty_action() {
        assert_eq!(
            approve_request(&request(), "  ", 200),
            Err(ApprovalError::EmptyApprover)
        );
        let mut invalid = request();
        invalid.actions = vec![" ".into()];
        assert_eq!(invalid.validate(), Err(RequestValidationError::EmptyAction));
    }
}
