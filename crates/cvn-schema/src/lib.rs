//! Schema support for TUFF-CVN.

/// Initial schema version placeholder.
pub const INITIAL_SCHEMA_VERSION: &str = "cvn-v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_defined() {
        assert_eq!(INITIAL_SCHEMA_VERSION, "cvn-v1");
    }
}
