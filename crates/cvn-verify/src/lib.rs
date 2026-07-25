//! Verification support for TUFF-CVN.

/// Placeholder verification status for scaffolded code paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Verification has not been implemented yet.
    NotImplemented,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_status_is_available() {
        assert_eq!(
            VerificationStatus::NotImplemented,
            VerificationStatus::NotImplemented
        );
    }
}
