//! Canonical JSON support for TUFF-CVN.
//!
//! Current boundary: serialization is deterministic for the typed CVN model by
//! converting through `serde_json::Value`, sorting object keys recursively, and
//! emitting compact UTF-8 JSON. This is intentionally not declared as complete
//! RFC 8785 compliance. Floating point JSON numbers are rejected at this
//! boundary; duplicate object keys are assumed to be unrepresentable when
//! serializing typed serde structures.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonical media type placeholder.
pub const CANONICAL_MEDIA_TYPE: &str = "application/vnd.tuff-cvn+json";

/// Error returned by canonical serialization and digest generation.
#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("failed to convert value to JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("floating point JSON numbers are not allowed at {path}")]
    FloatingPointNumber { path: String },
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

/// Serializes a value into deterministic canonical JSON bytes.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let mut value = serde_json::to_value(value)?;
    sort_and_validate_value(&mut value, "$")?;
    serde_json::to_vec(&value).map_err(CanonicalError::from)
}

/// Computes SHA-256 over canonical JSON bytes.
pub fn sha256_canonical<T: Serialize>(value: &T) -> Result<CanonicalDigest, CanonicalError> {
    let bytes = to_canonical_bytes(value)?;
    let digest = Sha256::digest(bytes);
    Ok(CanonicalDigest(hex::encode(digest)))
}

fn sort_and_validate_value(value: &mut Value, path: &str) -> Result<(), CanonicalError> {
    match value {
        Value::Object(object) => {
            let mut sorted = Map::new();
            let old_object = std::mem::take(object);
            let mut entries: Vec<_> = old_object.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));

            for (key, mut value) in entries {
                let child_path = format!("{path}.{key}");
                sort_and_validate_value(&mut value, &child_path)?;
                sorted.insert(key, value);
            }

            *object = sorted;
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                sort_and_validate_value(value, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::Number(number) if number.is_i64() || number.is_u64() => Ok(()),
        Value::Number(_) => Err(CanonicalError::FloatingPointNumber {
            path: path.to_owned(),
        }),
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
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
    fn floating_point_json_is_rejected() {
        let value = json!({ "safe": 1, "unsafe": 1.5 });

        let error = to_canonical_bytes(&value).unwrap_err();

        assert!(matches!(error, CanonicalError::FloatingPointNumber { .. }));
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
