//! Shared domain types for TUFF-CVN.

/// Project name used across crates.
pub const PROJECT_NAME: &str = "TUFF-CVN";

/// Expanded project name.
pub const EXPANDED_NAME: &str = "TUFF Canonical Verifiable Notation";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_name_is_defined() {
        assert_eq!(PROJECT_NAME, "TUFF-CVN");
    }
}
