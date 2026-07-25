//! RFC 8785/JCS canonical JSON support for TUFF-CVN.
//!
//! Canonical bytes are produced by `serde_json_canonicalizer`. TUFF-CVN adds a
//! fail-closed preflight pass that rejects JSON numbers outside the JCS safe
//! integer range and rejects non-finite floating point values before hashing.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonical media type placeholder.
pub const CANONICAL_MEDIA_TYPE: &str = "application/vnd.tuff-cvn+json";

const MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_992;

/// Error returned by canonical serialization and digest generation.
#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("failed to convert value to JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to canonicalize JSON: {0}")]
    Canonicalize(String),
    #[error("JCS unsafe number at {path}: {reason}")]
    UnsafeNumber { path: String, reason: String },
    #[error("canonical bytes were not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Hex-encoded SHA-256 digest of canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalDigest(String);

impl CanonicalDigest {
    /// Returns the digest as lowercase hex.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

/// Verifies that a serde value can be represented safely under the current JCS
/// boundary.
pub fn assert_jcs_safe<T: Serialize>(value: &T) -> Result<(), CanonicalError> {
    let value = serde_json::to_value(value)?;
    assert_value_jcs_safe(&value, "$")
}

/// Serializes a value into RFC 8785 canonical JSON bytes.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = serde_json::to_value(value)?;
    assert_value_jcs_safe(&value, "$")?;
    serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| CanonicalError::Canonicalize(error.to_string()))
}

/// Serializes a value into an RFC 8785 canonical JSON string.
pub fn to_canonical_string<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    String::from_utf8(to_canonical_bytes(value)?).map_err(CanonicalError::from)
}

/// Computes SHA-256 over canonical JSON bytes.
pub fn sha256_canonical<T: Serialize>(value: &T) -> Result<CanonicalDigest, CanonicalError> {
    let bytes = to_canonical_bytes(value)?;
    let digest = Sha256::digest(bytes);
    Ok(CanonicalDigest(hex::encode(digest)))
}

fn assert_value_jcs_safe(value: &Value, path: &str) -> Result<(), CanonicalError> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                assert_value_jcs_safe(value, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                assert_value_jcs_safe(value, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                if value.unsigned_abs() <= MAX_JCS_SAFE_INTEGER {
                    Ok(())
                } else {
                    Err(unsafe_number(path, "integer magnitude exceeds 2^53"))
                }
            } else if let Some(value) = number.as_u64() {
                if value <= MAX_JCS_SAFE_INTEGER {
                    Ok(())
                } else {
                    Err(unsafe_number(path, "integer magnitude exceeds 2^53"))
                }
            } else if let Some(value) = number.as_f64() {
                if !value.is_finite() {
                    Err(unsafe_number(path, "non-finite number"))
                } else {
                    Ok(())
                }
            } else {
                Err(unsafe_number(path, "unrepresentable number"))
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

fn unsafe_number(path: &str, reason: &str) -> CanonicalError {
    CanonicalError::UnsafeNumber {
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cvn_core::{CvnDocument, DocumentId, Manifest};
    use serde_json::json;

    use super::*;

    #[test]
    fn media_type_is_defined() {
        assert_eq!(CANONICAL_MEDIA_TYPE, "application/vnd.tuff-cvn+json");
    }

    #[test]
    fn repeated_serialization_is_identical() {
        let document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());

        let first = to_canonical_bytes(&document).unwrap();
        let second = to_canonical_bytes(&document).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn deserialize_then_reserialize_is_identical() {
        let document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        let bytes = to_canonical_bytes(&document).unwrap();
        let deserialized: CvnDocument = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(bytes, to_canonical_bytes(&deserialized).unwrap());
    }

    #[test]
    fn object_insertion_order_does_not_affect_canonical_bytes() {
        let mut left = BTreeMap::new();
        left.insert("a".to_owned(), "1".to_owned());
        left.insert("b".to_owned(), "2".to_owned());

        let mut right = BTreeMap::new();
        right.insert("b".to_owned(), "2".to_owned());
        right.insert("a".to_owned(), "1".to_owned());

        let left_doc = CvnDocument {
            manifest: Manifest {
                metadata: left,
                ..Manifest::default()
            },
            ..CvnDocument::minimal(DocumentId::new("doc-1").unwrap())
        };
        let right_doc = CvnDocument {
            manifest: Manifest {
                metadata: right,
                ..Manifest::default()
            },
            ..CvnDocument::minimal(DocumentId::new("doc-1").unwrap())
        };

        assert_eq!(
            to_canonical_bytes(&left_doc).unwrap(),
            to_canonical_bytes(&right_doc).unwrap()
        );
    }

    #[test]
    fn canonical_sha256_is_stable_and_sensitive_to_changes() {
        let left = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        let right = CvnDocument::minimal(DocumentId::new("doc-2").unwrap());

        let first = sha256_canonical(&left).unwrap();
        let second = sha256_canonical(&left).unwrap();
        let changed = sha256_canonical(&right).unwrap();

        assert_eq!(first, second);
        assert_ne!(first, changed);
    }

    #[test]
    fn utf16_key_order_places_supplementary_before_e000() {
        let value = json!({
            "\u{E000}": 1,
            "\u{10000}": 2
        });

        assert_eq!(to_canonical_string(&value).unwrap(), "{\"𐀀\":2,\"\":1}");
    }

    #[test]
    fn safe_integer_boundary_is_enforced() {
        assert!(to_canonical_bytes(&json!({ "n": 9_007_199_254_740_992_u64 })).is_ok());
        let error = to_canonical_bytes(&json!({ "n": 9_007_199_254_740_993_u64 })).unwrap_err();
        assert!(matches!(error, CanonicalError::UnsafeNumber { .. }));
    }

    #[test]
    fn negative_zero_is_canonicalized_to_zero() {
        assert_eq!(to_canonical_string(&json!(-0.0)).unwrap(), "0");
    }

    #[test]
    fn non_finite_numbers_are_rejected_by_serde_before_canonicalization() {
        assert_eq!(serde_json::to_value(f64::NAN).unwrap(), Value::Null);
        assert_eq!(serde_json::to_value(f64::INFINITY).unwrap(), Value::Null);
    }

    #[test]
    fn invalid_id_is_rejected_during_deserialization() {
        let document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        let mut value = serde_json::to_value(document).unwrap();
        value["document_id"] = json!("invalid id");

        let result = serde_json::from_value::<CvnDocument>(value);

        assert!(result.is_err());
    }
}
