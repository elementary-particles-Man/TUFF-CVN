//! Canonical JSON support for TUFF-CVN.

/// Canonical media type placeholder.
pub const CANONICAL_MEDIA_TYPE: &str = "application/vnd.tuff-cvn+json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_type_is_defined() {
        assert_eq!(CANONICAL_MEDIA_TYPE, "application/vnd.tuff-cvn+json");
    }
}
