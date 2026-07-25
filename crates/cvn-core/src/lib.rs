//! Shared domain types for TUFF-CVN.
//!
//! The CVN core model intentionally avoids floating point fields. Current
//! numeric fields use bounded integer types; canonicalization additionally
//! rejects JSON floating point numbers at the serialization boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Project name used across crates.
pub const PROJECT_NAME: &str = "TUFF-CVN";

/// Expanded project name.
pub const EXPANDED_NAME: &str = "TUFF Canonical Verifiable Notation";

/// Initial CVN schema version.
pub const CVN_V1: &str = "cvn-v1";

/// Validation error for stable CVN identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdError {
    value: String,
}

impl IdError {
    /// Returns the rejected identifier value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid CVN identifier: {}", self.value)
    }
}

impl std::error::Error for IdError {}

fn validate_id(value: &str) -> Result<(), IdError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));

    if valid {
        Ok(())
    } else {
        Err(IdError {
            value: value.to_owned(),
        })
    }
}

macro_rules! stable_id {
    ($name:ident) => {
        #[doc = concat!("Stable externally supplied CVN identifier: `", stringify!($name), "`.")]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated stable identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_id(&value)?;
                Ok(Self(value))
            }

            /// Returns the identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdVisitor;

                impl Visitor<'_> for IdVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a non-empty stable CVN identifier")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::new(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

stable_id!(DocumentId);
stable_id!(NodeId);
stable_id!(AssetId);
stable_id!(OpaqueId);
stable_id!(RelationId);
stable_id!(ChecksumId);
stable_id!(SourceId);

/// Root CVN document model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvnDocument {
    pub schema_version: String,
    pub document_id: DocumentId,
    pub manifest: Manifest,
    pub content: ContentGraph,
    pub styles: StyleRegistry,
    pub relations: Vec<Relation>,
    pub permissions: PermissionSet,
    pub assets: Vec<AssetEntry>,
    pub opaque: Vec<OpaqueEntry>,
    pub warnings: Vec<CvnWarning>,
    pub checksums: Vec<ChecksumEntry>,
}

impl CvnDocument {
    /// Creates a minimal valid CVN document.
    pub fn minimal(document_id: DocumentId) -> Self {
        Self {
            schema_version: CVN_V1.to_owned(),
            document_id,
            manifest: Manifest::default(),
            content: ContentGraph::default(),
            styles: StyleRegistry::default(),
            relations: Vec::new(),
            permissions: PermissionSet::default(),
            assets: Vec::new(),
            opaque: Vec::new(),
            warnings: Vec::new(),
            checksums: Vec::new(),
        }
    }
}

/// Manifest-level metadata and source descriptors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub sources: Vec<SourceDescriptor>,
    pub metadata: BTreeMap<String, String>,
}

/// Source file or stream descriptor used for source preservation references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDescriptor {
    pub id: SourceId,
    pub format: SourceFormat,
    pub original_name: Option<String>,
    pub media_type: Option<String>,
    pub length: Option<u64>,
    pub digest: Option<String>,
}

/// Vendor-neutral source format classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    Docx,
    Json,
    Binary,
    Text,
    Other(String),
}

/// Source-preservation reference to a source descriptor and optional part/range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePartRef {
    pub source_id: SourceId,
    pub part: Option<String>,
    pub byte_range: Option<SourceByteRange>,
}

/// Byte range in the original source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceByteRange {
    pub start: u64,
    pub length: u64,
}

/// Minimal content graph. Meaningful node semantics are intentionally deferred.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentGraph {
    pub nodes: Vec<ContentNode>,
    pub root_nodes: Vec<NodeId>,
    pub metadata: BTreeMap<String, String>,
}

/// Vendor-neutral content node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentNode {
    pub id: NodeId,
    pub kind: String,
    pub text: Option<String>,
    pub attributes: BTreeMap<String, String>,
    pub source_ref: Option<SourcePartRef>,
    pub opaque_refs: Vec<OpaqueId>,
    pub children: Vec<NodeId>,
}

/// Stable style registry placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StyleRegistry {
    pub styles: BTreeMap<String, StyleEntry>,
}

/// Minimal style entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StyleEntry {
    pub attributes: BTreeMap<String, String>,
}

/// Directed relation between content nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relation {
    pub id: RelationId,
    pub kind: String,
    pub source: NodeId,
    pub target: NodeId,
    pub source_ref: Option<SourcePartRef>,
}

/// Permission model placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    pub entries: BTreeMap<String, String>,
}

/// Asset entry that may reference opaque preserved data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEntry {
    pub id: AssetId,
    pub media_type: String,
    pub original_name: Option<String>,
    pub source_ref: Option<SourcePartRef>,
    pub opaque_ref: Option<OpaqueId>,
    pub content_digest: Option<String>,
    pub length: Option<u64>,
}

/// Preserved uninterpreted data reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueEntry {
    pub id: OpaqueId,
    pub media_type: String,
    pub original_name: Option<String>,
    pub source_ref: Option<SourcePartRef>,
    pub content_digest: String,
    pub length: u64,
    pub preservation_mode: PreservationMode,
}

/// How opaque data is preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationMode {
    ExternalBlob,
    PackageContentAddressed,
}

/// Typed warning emitted during import or normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvnWarning {
    pub code: String,
    pub severity: WarningSeverity,
    pub path: String,
    pub message: String,
    pub source_ref: Option<SourcePartRef>,
}

/// Warning severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningSeverity {
    Info,
    Warning,
    Error,
}

/// Checksum over a named CVN target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumEntry {
    pub id: ChecksumId,
    pub algorithm: ChecksumAlgorithm,
    pub target: String,
    pub digest: String,
}

/// Supported checksum algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChecksumAlgorithm {
    Sha256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_name_is_defined() {
        assert_eq!(PROJECT_NAME, "TUFF-CVN");
    }

    #[test]
    fn minimal_document_is_constructible() {
        let document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());

        assert_eq!(document.schema_version, CVN_V1);
        assert!(document.content.nodes.is_empty());
        assert!(document.opaque.is_empty());
    }

    #[test]
    fn invalid_id_is_rejected() {
        assert!(DocumentId::new("").is_err());
        assert!(DocumentId::new("has space").is_err());
        assert!(DocumentId::new("日本語").is_err());
    }
}
