//! Package/container support for TUFF-CVN.

/// Default package extension for canonical documents.
pub const DEFAULT_PACKAGE_EXTENSION: &str = "cvn";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_extension_is_defined() {
        assert_eq!(DEFAULT_PACKAGE_EXTENSION, "cvn");
    }
}
