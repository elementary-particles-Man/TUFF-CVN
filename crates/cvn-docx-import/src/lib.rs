//! DOCX import entry point for TUFF-CVN.

/// Returns whether DOCX import is implemented.
pub fn is_implemented() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docx_import_is_not_implemented_in_scaffold() {
        assert!(!is_implemented());
    }
}
