//! DOCX export entry point for TUFF-CVN.

/// Returns whether DOCX export is implemented.
pub fn is_implemented() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docx_export_is_not_implemented_in_scaffold() {
        assert!(!is_implemented());
    }
}
