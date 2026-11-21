//! Minimal, deterministic authorization primitives for QORVYNT Web4.
//!
//! This module evaluates already-authenticated principals against explicit
//! capabilities. It does not authenticate identities, verify signatures, or
//! access data/network resources.

pub mod identity;
pub mod permissions;

/// Stable application-level identifier for a user, agent, or service.
pub type PrincipalId = String;

/// Stable identifier for a protected resource (for example, a data vault).
pub type ResourceId = String;

/// Action names are protocol-defined strings such as "data.read" or "agent.invoke".
pub type Action = String;

/// A narrow grant issued by a resource owner to one principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub subject: PrincipalId,
    pub resource: ResourceId,
    pub actions: Vec<Action>,
    /// Unix timestamp in seconds. The grant is invalid at and after this time.
    pub expires_at: u64,
    /// Revocation is authoritative even if the grant has not expired.
    pub revoked: bool,
}

impl Capability {
    /// Evaluate one requested action at a supplied Unix timestamp.
    ///
    /// The caller must authenticate `subject` before invoking this method.
    /// This function deliberately performs no wildcard or prefix matching.
    pub fn permits(
        &self,
        subject: &str,
        resource: &str,
        action: &str,
        now_unix: u64,
    ) -> AuthorizationDecision {
        let reason = if self.revoked {
            Some(DenialReason::Revoked)
        } else if now_unix >= self.expires_at {
            Some(DenialReason::Expired)
        } else if self.subject != subject {
            Some(DenialReason::SubjectMismatch)
        } else if self.resource != resource {
            Some(DenialReason::ResourceMismatch)
        } else if !self.actions.iter().any(|granted| granted == action) {
            Some(DenialReason::ActionNotGranted)
        } else {
            None
        };

        match reason {
            Some(reason) => AuthorizationDecision::Deny(reason),
            None => AuthorizationDecision::Allow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    Revoked,
    Expired,
    SubjectMismatch,
    ResourceMismatch,
    ActionNotGranted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    Deny(DenialReason),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> Capability {
        Capability {
            subject: "did:qorvynt:user:alice".into(),
            resource: "vault:alice:profile".into(),
            actions: vec!["data.read".into()],
            expires_at: 2_000,
            revoked: false,
        }
    }

    #[test]
    fn allows_only_the_exact_granted_subject_resource_and_action() {
        assert_eq!(
            grant().permits(
                "did:qorvynt:user:alice",
                "vault:alice:profile",
                "data.read",
                1_999
            ),
            AuthorizationDecision::Allow
        );
        assert_eq!(
            grant().permits(
                "did:qorvynt:user:alice",
                "vault:alice:profile",
                "data.write",
                1_999
            ),
            AuthorizationDecision::Deny(DenialReason::ActionNotGranted)
        );
    }

    #[test]
    fn denies_expired_and_revoked_capabilities() {
        assert_eq!(
            grant().permits(
                "did:qorvynt:user:alice",
                "vault:alice:profile",
                "data.read",
                2_000
            ),
            AuthorizationDecision::Deny(DenialReason::Expired)
        );

        let mut revoked = grant();
        revoked.revoked = true;
        assert_eq!(
            revoked.permits(
                "did:qorvynt:user:alice",
                "vault:alice:profile",
                "data.read",
                1_000
            ),
            AuthorizationDecision::Deny(DenialReason::Revoked)
        );
    }

    #[test]
    fn denies_subject_and_resource_mismatches() {
        let grant = grant();
        assert_eq!(
            grant.permits(
                "did:qorvynt:agent:other",
                "vault:alice:profile",
                "data.read",
                1_000
            ),
            AuthorizationDecision::Deny(DenialReason::SubjectMismatch)
        );
        assert_eq!(
            grant.permits("did:qorvynt:user:alice", "vault:other", "data.read", 1_000),
            AuthorizationDecision::Deny(DenialReason::ResourceMismatch)
        );
    }
}
