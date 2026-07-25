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

/// `cvn.json` top-level shape. `payload` is the canonical content being hashed;
/// `integrity` stores the resulting tree without becoming part of the payload
/// digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvnJson {
    pub payload: CvnDocument,
    pub integrity: IntegrityManifest,
}

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
stable_id!(SemanticNodeId);

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
    pub opc: OpcPackageProjection,
    pub semantic: SemanticDocument,
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
            opc: OpcPackageProjection::default(),
            semantic: SemanticDocument::default(),
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

/// Read-only OPC package projection. Raw bytes live in package objects and are
/// referenced by digest; parsed XML projections never replace payload bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcPackageProjection {
    pub parts: Vec<OpcPart>,
    pub content_types: ContentTypesProjection,
    pub relationships: Vec<OpcRelationship>,
}

/// OPC part metadata and content-addressed raw-byte reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcPart {
    pub original_path: String,
    pub content_type: Option<String>,
    pub original_size: u64,
    pub content_digest: String,
    pub compression: ZipEntryMetadata,
}

/// ZIP entry metadata retained for diagnostics and future export choices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZipEntryMetadata {
    pub is_directory: bool,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: String,
}

/// Parsed projection of `[Content_Types].xml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentTypesProjection {
    pub defaults: Vec<ContentTypeDefault>,
    pub overrides: Vec<ContentTypeOverride>,
}

/// Content type default by extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentTypeDefault {
    pub extension: String,
    pub content_type: String,
}

/// Content type override by part name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentTypeOverride {
    pub part_name: String,
    pub content_type: String,
}

/// Read-only OPC relationship projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcRelationship {
    pub source_part: Option<String>,
    pub relationship_id: String,
    pub relationship_type: String,
    pub target: String,
    pub target_mode: TargetMode,
}

/// OPC relationship target mode. External targets are inert strings and must
/// not be resolved as network resources by import, export, or verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetMode {
    Internal,
    External,
}

/// Read-only semantic projection extracted from preserved source parts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDocument {
    pub source_part: String,
    pub blocks: Vec<SemanticBlock>,
    #[serde(default)]
    pub styles: Option<StyleRegistryProjection>,
    #[serde(default)]
    pub numbering: Option<NumberingRegistryProjection>,
    pub unsupported_features: Vec<UnsupportedSemanticFeature>,
}

/// Semantic block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SemanticBlock {
    Paragraph(SemanticParagraph),
    Table(SemanticTable),
}

/// Semantic paragraph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticParagraph {
    pub id: SemanticNodeId,
    pub source_identifier: Option<String>,
    pub source_anchor: SourceAnchor,
    pub properties: ParagraphPropertiesProjection,
    #[serde(default)]
    pub numbering: Option<NumberingReference>,
    #[serde(default)]
    pub resolved_style: Option<ResolvedStyleProjection>,
    pub runs: Vec<SemanticRun>,
}

/// Semantic run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticRun {
    pub id: SemanticNodeId,
    pub source_identifier: Option<String>,
    pub source_anchor: SourceAnchor,
    pub properties: RunPropertiesProjection,
    #[serde(default)]
    pub resolved_style: Option<ResolvedStyleProjection>,
    pub inlines: Vec<SemanticInline>,
}

/// Semantic text inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticText {
    pub value: String,
    pub preserve_space: bool,
}

/// Semantic table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTable {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    pub rows: Vec<SemanticTableRow>,
}

/// Semantic table row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTableRow {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    pub cells: Vec<SemanticTableCell>,
}

/// Semantic table cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTableCell {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    pub grid_span: Option<String>,
    pub v_merge: Option<String>,
    pub blocks: Vec<SemanticBlock>,
}

/// Semantic inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SemanticInline {
    Text(SemanticText),
    Tab,
    LineBreak { break_kind: String },
}

/// Source anchor for semantic nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAnchor {
    pub source_part_path: String,
    pub xml_path: String,
    pub byte_start: Option<u64>,
}

/// Paragraph properties projected without interpreting all OOXML formatting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParagraphPropertiesProjection {
    pub style_id: Option<String>,
}

/// Run properties projected without interpreting all OOXML formatting.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunPropertiesProjection {
    pub run_style_id: Option<String>,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
}

/// Read-only projection of `word/styles.xml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StyleRegistryProjection {
    pub source_part: String,
    pub definitions: Vec<StyleDefinitionProjection>,
    pub diagnostics: Vec<StyleResolutionDiagnostic>,
    pub unsupported_features: Vec<UnsupportedSemanticFeature>,
}

/// A DOCX style definition projected without XML reserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StyleDefinitionProjection {
    pub style_id: String,
    pub style_type: StyleType,
    pub name: Option<String>,
    pub aliases: Vec<String>,
    pub based_on: Option<StyleReference>,
    pub next: Option<StyleReference>,
    pub link: Option<StyleReference>,
    pub is_default: bool,
    pub custom_style: bool,
    pub q_format: bool,
    pub semi_hidden: bool,
    pub unhide_when_used: bool,
    pub ui_priority: Option<String>,
    pub paragraph_properties: ParagraphPropertiesProjection,
    pub run_properties: RunPropertiesProjection,
    pub resolved_style: Option<ResolvedStyleProjection>,
}

/// DOCX style type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StyleType {
    Paragraph,
    Character,
    Table,
    Numbering,
    Unknown,
}

/// Reference to another style definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StyleReference {
    pub style_id: String,
}

/// Deterministic style resolution result. Direct formatting remains separate and
/// takes precedence when consumers interpret the projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedStyleProjection {
    pub style_id: String,
    pub style_type: StyleType,
    pub chain: Vec<String>,
    pub paragraph_properties: ParagraphPropertiesProjection,
    pub run_properties: RunPropertiesProjection,
}

/// Style projection diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StyleResolutionDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Read-only projection of `word/numbering.xml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumberingRegistryProjection {
    pub source_part: String,
    pub abstract_numbers: Vec<AbstractNumberingProjection>,
    pub instances: Vec<NumberingInstanceProjection>,
    pub diagnostics: Vec<NumberingResolutionDiagnostic>,
    pub unsupported_features: Vec<UnsupportedSemanticFeature>,
}

/// Abstract numbering definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractNumberingProjection {
    pub abstract_num_id: String,
    pub levels: Vec<NumberingLevelProjection>,
}

/// Numbering instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumberingInstanceProjection {
    pub num_id: String,
    pub abstract_num_id: Option<String>,
    pub level_overrides: Vec<NumberingLevelProjection>,
}

/// Numbering level projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumberingLevelProjection {
    pub ilvl: String,
    pub start: Option<String>,
    pub start_override: Option<String>,
    pub num_fmt: Option<NumberFormatProjection>,
    pub lvl_text: Option<String>,
    pub suff: Option<String>,
    pub paragraph_style: Option<String>,
    pub lvl_restart: Option<String>,
    pub paragraph_properties: ParagraphPropertiesProjection,
    pub run_properties: RunPropertiesProjection,
}

/// Paragraph numbering reference with optional resolved level projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumberingReference {
    pub num_id: String,
    pub ilvl: Option<String>,
    pub resolved_level: Option<NumberingLevelProjection>,
}

/// Number format token from `w:numFmt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumberFormatProjection {
    pub value: String,
}

/// Numbering projection diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumberingResolutionDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Unsupported or partially projected semantic feature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedSemanticFeature {
    pub code: String,
    pub source_anchor: SourceAnchor,
    pub namespace_uri: Option<String>,
    pub local_name: String,
    pub handling: UnsupportedFeatureHandling,
}

/// Handling strategy for unsupported features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedFeatureHandling {
    PreservedRaw,
    ProjectedPartially,
    IgnoredForSemanticView,
}

/// Package integrity manifest stored alongside the canonical payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub version: String,
    pub algorithm: DigestAlgorithm,
    pub root: IntegrityRoot,
    pub nodes: Vec<IntegrityNode>,
}

/// Integrity root digest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityRoot {
    pub digest: String,
}

/// Integrity tree leaf node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityNode {
    pub kind: IntegrityNodeKind,
    pub digest: String,
}

/// Integrity node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityNodeKind {
    CanonicalPayload,
    PartMap,
    Relations,
    ContentTypes,
    SemanticProjection,
    StyleProjection,
    NumberingProjection,
    Objects,
}

impl IntegrityNodeKind {
    /// Stable name used in root digest child records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalPayload => "canonical_payload",
            Self::PartMap => "part_map",
            Self::Relations => "relations",
            Self::ContentTypes => "content_types",
            Self::SemanticProjection => "semantic_projection",
            Self::StyleProjection => "style_projection",
            Self::NumberingProjection => "numbering_projection",
            Self::Objects => "objects",
        }
    }
}

/// Digest algorithm for integrity manifests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestAlgorithm {
    #[default]
    Sha256,
}

/// Integrity status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    Passed,
    Failed,
}

/// Integrity failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityFailure {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Explicit hash-target projection for the canonical payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalPayloadView<'a> {
    pub payload: &'a CvnDocument,
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
