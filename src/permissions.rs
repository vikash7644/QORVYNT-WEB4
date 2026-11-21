//! Permission request, approval, and audit-event data types.
//!
//! These are deterministic domain primitives only. They do not persist an
//! append-only log, authenticate approvers, or provide cryptographic receipts.

use crate::{Action, Capability, PrincipalId, ResourceId};

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
    if approver != request.resource_owner {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalError {
    InvalidRequest(RequestValidationError),
    EmptyApprover,
    ApproverNotResourceOwner,
    ApprovalOutsideRequestWindow,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rejects_duplicate_actions_and_invalid_approval_times() {
        let mut invalid = request();
        invalid.actions.push("data.read".into());
        assert_eq!(
            invalid.validate(),
            Err(RequestValidationError::DuplicateAction)
        );
        assert_eq!(
            approve_request(&request(), "owner", 500),
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
        assert_eq!(
            invalid.validate(),
            Err(RequestValidationError::EmptyAction)
        );
    }
}
