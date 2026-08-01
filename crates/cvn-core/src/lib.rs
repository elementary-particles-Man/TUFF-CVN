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
    #[serde(default)]
    pub track_changes: Option<TrackChangesProjection>,
    #[serde(default)]
    pub mce: Option<MceProjection>,
    #[serde(default)]
    pub signatures: Option<OpcSignatureRegistryProjection>,
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
            track_changes: None,
            mce: None,
            signatures: None,
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
    #[serde(default)]
    pub stories: Option<StoryRegistryProjection>,
    #[serde(default)]
    pub references: Option<DocumentReferencesProjection>,
    #[serde(default)]
    pub drawings: Option<DrawingRegistryProjection>,
    #[serde(default)]
    pub embedded_visual_objects: Option<EmbeddedVisualObjectsProjection>,
    pub unsupported_features: Vec<UnsupportedSemanticFeature>,
}

/// Read-only projection of DOCX hyperlinks, bookmarks, fields, and cross-references.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentReferencesProjection {
    pub source_part: String,
    pub hyperlinks: Vec<HyperlinkProjection>,
    pub bookmarks: Vec<BookmarkProjection>,
    pub bookmark_ranges: Vec<BookmarkRangeProjection>,
    pub fields: Vec<FieldProjection>,
    pub cross_references: Vec<CrossReferenceProjection>,
    pub diagnostics: Vec<DocumentReferenceDiagnostic>,
}

/// Read-only projection of DOCX DrawingML/VML image references.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingRegistryProjection {
    pub source_part: String,
    pub drawings: Vec<DrawingProjection>,
    pub diagnostics: Vec<DrawingResolutionDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingProjection {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    #[serde(rename = "drawing_kind")]
    pub kind: DrawingKind,
    pub placement: DrawingPlacement,
    pub graphic_data_uri: Option<String>,
    pub metadata: Option<DrawingMetadataProjection>,
    pub geometry: Option<DrawingGeometryProjection>,
    pub targets: Vec<DrawingTarget>,
    pub vml_shape_id: Option<String>,
    pub vml_shape_type: Option<String>,
    pub vml_style_raw: Option<String>,
    #[serde(default)]
    pub vml_style_properties: BTreeMap<String, String>,
    #[serde(default)]
    pub diagnostics: Vec<DrawingResolutionDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrawingKind {
    DrawingmlInlineImage,
    DrawingmlAnchoredImage,
    VmlImage,
    UnsupportedGraphic,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DrawingPlacement {
    Inline,
    Anchor {
        simple_pos: Option<bool>,
        relative_height: Option<String>,
        behind_doc: Option<bool>,
        locked: Option<bool>,
        layout_in_cell: Option<bool>,
        allow_overlap: Option<bool>,
        dist_t: Option<String>,
        dist_b: Option<String>,
        dist_l: Option<String>,
        dist_r: Option<String>,
        position_h: Option<DrawingPositionProjection>,
        position_v: Option<DrawingPositionProjection>,
        wrap: Option<DrawingWrapProjection>,
    },
    Vml,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingTarget {
    pub kind: DrawingTargetKind,
    pub relationship_id: Option<String>,
    pub relationship_type: Option<String>,
    pub target_mode: Option<TargetMode>,
    pub raw_target: Option<String>,
    pub resolved_part_path: Option<String>,
    pub resource: Option<ImageResourceProjection>,
    pub risk_class: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrawingTargetKind {
    EmbeddedPart,
    ExternalRelationship,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingGeometryProjection {
    pub extent: Option<DrawingExtentProjection>,
    pub offset: Option<DrawingOffsetProjection>,
    pub transform: Option<DrawingTransformProjection>,
    pub crop: Option<DrawingCropProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingExtentProjection {
    pub cx: Option<i64>,
    pub cy: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingOffsetProjection {
    pub x: Option<i64>,
    pub y: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingTransformProjection {
    pub rotation: Option<i64>,
    pub flip_h: bool,
    pub flip_v: bool,
    pub offset: Option<DrawingOffsetProjection>,
    pub extent: Option<DrawingExtentProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingCropProjection {
    pub left: Option<i64>,
    pub top: Option<i64>,
    pub right: Option<i64>,
    pub bottom: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingWrapProjection {
    pub kind: String,
    pub dist_t: Option<String>,
    pub dist_b: Option<String>,
    pub dist_l: Option<String>,
    pub dist_r: Option<String>,
    pub raw_polygon_xml: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingPositionProjection {
    pub relative_from: Option<String>,
    pub align: Option<String>,
    pub pos_offset: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingMetadataProjection {
    pub doc_pr_id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub title: Option<String>,
    pub hidden: Option<bool>,
    pub raw_attributes: BTreeMap<String, String>,
    pub vml_title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageResourceProjection {
    pub part_path: Option<String>,
    pub content_type: Option<String>,
    pub object_digest: Option<String>,
    pub length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrawingResolutionDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Read-only projection of charts, diagrams, OLE objects, and embedded
/// packages referenced from semantic content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedVisualObjectsProjection {
    pub source_part: String,
    pub objects: Vec<EmbeddedVisualObjectProjection>,
    pub diagnostics: Vec<EmbeddedVisualObjectDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedVisualObjectProjection {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    #[serde(rename = "object_kind")]
    pub kind: EmbeddedVisualObjectKind,
    pub graphic_data_uri: Option<String>,
    pub chart: Option<ChartProjection>,
    pub diagram: Option<DiagramProjection>,
    pub ole: Option<OleObjectProjection>,
    pub package_resource: Option<EmbeddedResourceProjection>,
    pub targets: Vec<EmbeddedObjectTarget>,
    pub preview_image_relationship_id: Option<String>,
    pub preview_image: Option<EmbeddedResourceProjection>,
    pub risk_class: Option<String>,
    #[serde(default)]
    pub diagnostics: Vec<EmbeddedVisualObjectDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedVisualObjectKind {
    Chart,
    SmartartDiagram,
    OleEmbeddedObject,
    OleLinkedObject,
    EmbeddedPackage,
    ActivexBlocked,
    UnsupportedVisualObject,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedObjectTarget {
    pub kind: EmbeddedObjectTargetKind,
    pub role: Option<String>,
    pub relationship_id: Option<String>,
    pub relationship_type: Option<String>,
    pub target_mode: Option<TargetMode>,
    pub raw_target: Option<String>,
    pub resolved_part_path: Option<String>,
    pub resource: Option<EmbeddedResourceProjection>,
    pub risk_class: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedObjectTargetKind {
    EmbeddedPart,
    InternalPart,
    ExternalRelationship,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedResourceProjection {
    pub part_path: Option<String>,
    pub content_type: Option<String>,
    pub object_digest: Option<String>,
    pub length: Option<u64>,
    pub format_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChartProjection {
    pub part_path: Option<String>,
    pub content_type: Option<String>,
    pub object_digest: Option<String>,
    pub length: Option<u64>,
    pub chart_type: String,
    pub title: Option<ChartTitleProjection>,
    pub series: Vec<ChartSeriesProjection>,
    pub embedded_workbook: Option<EmbeddedResourceProjection>,
    pub external_data: Option<EmbeddedObjectTarget>,
    pub external_data_auto_update: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChartTitleProjection {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChartSeriesProjection {
    pub title: Option<String>,
    pub category_reference: Option<ChartDataReferenceProjection>,
    pub value_reference: Option<ChartDataReferenceProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChartDataReferenceProjection {
    pub formula: Option<String>,
    pub cached_string_values: Vec<String>,
    pub cached_numeric_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagramProjection {
    pub data_part: Option<DiagramPartReferenceProjection>,
    pub layout_part: Option<DiagramPartReferenceProjection>,
    pub style_part: Option<DiagramPartReferenceProjection>,
    pub colors_part: Option<DiagramPartReferenceProjection>,
    pub points: Vec<String>,
    pub connections: Vec<String>,
    pub texts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagramPartReferenceProjection {
    pub role: String,
    pub relationship_id: Option<String>,
    pub part_path: Option<String>,
    pub content_type: Option<String>,
    pub object_digest: Option<String>,
    pub length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OleObjectProjection {
    pub metadata: OleMetadataProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OleMetadataProjection {
    pub object_type: Option<String>,
    pub prog_id: Option<String>,
    pub shape_id: Option<String>,
    pub draw_aspect: Option<String>,
    pub object_id: Option<String>,
    pub update_mode: Option<String>,
    pub raw_attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedVisualObjectDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HyperlinkProjection {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    pub relationship_id: Option<String>,
    pub target: HyperlinkTarget,
    pub anchor: Option<String>,
    pub doc_location: Option<String>,
    pub history: Option<String>,
    pub target_frame: Option<String>,
    pub tooltip: Option<String>,
    pub children: Vec<SemanticInline>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HyperlinkTarget {
    pub kind: HyperlinkTargetKind,
    pub raw_target: Option<String>,
    pub resolved_part_path: Option<String>,
    pub relationship_type: Option<String>,
    pub risk_class: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HyperlinkTargetKind {
    ExternalRelationship,
    InternalAnchor,
    InternalPart,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkProjection {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    pub bookmark_id: String,
    pub name: Option<String>,
    pub column_first: Option<String>,
    pub column_last: Option<String>,
    pub boundary_kind: BookmarkBoundaryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookmarkBoundaryKind {
    Start,
    End,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkRangeProjection {
    pub source_part: String,
    pub bookmark_id: String,
    pub name: Option<String>,
    pub start: Option<SourceAnchor>,
    pub end: Option<SourceAnchor>,
    pub markers: Vec<SemanticNodeId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldProjection {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    pub field_kind: FieldKind,
    pub instruction: FieldInstructionProjection,
    pub result: FieldResultProjection,
    pub character_markers: Vec<FieldCharacterKindProjection>,
    pub field_lock: Option<String>,
    pub dirty: Option<String>,
    pub cross_reference: Option<CrossReferenceProjection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Ref,
    Pageref,
    Noteref,
    Hyperlink,
    Page,
    Numpages,
    Date,
    Time,
    Toc,
    Seq,
    Symbol,
    IncludeText,
    IncludePicture,
    Link,
    Dde,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldInstructionProjection {
    pub raw: String,
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldResultProjection {
    pub children: Vec<SemanticInline>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldCharacterKind {
    Begin,
    Separate,
    End,
    Simple,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldCharacterKindProjection {
    pub kind: FieldCharacterKind,
    pub source_anchor: SourceAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossReferenceProjection {
    pub field_id: SemanticNodeId,
    pub field_kind: FieldKind,
    pub target_bookmark_name: Option<String>,
    pub resolved_bookmark_id: Option<String>,
    pub hyperlink_target: Option<HyperlinkTarget>,
    pub source_anchor: SourceAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentReferenceDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Read-only projection of MCE AlternateContent and compatibility metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceProjection {
    pub source_part: String,
    pub capability_version: String,
    pub capabilities: MceCapabilities,
    pub alternate_contents: Vec<MceAlternateContentProjection>,
    pub diagnostics: Vec<MceResolutionDiagnostic>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceCapabilities {
    pub version: String,
    pub supported_namespaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceAlternateContentProjection {
    pub id: SemanticNodeId,
    pub source_anchor: SourceAnchor,
    pub branch_kind: MceSelection,
    pub branches: Vec<MceBranchProjection>,
    pub compatibility: Option<MceCompatibilityAttributes>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceBranchProjection {
    pub kind: MceBranchKind,
    pub requires_raw: Option<String>,
    pub requires: Vec<MceNamespaceRequirement>,
    pub selected: bool,
    pub raw_digest: String,
    pub raw_content: String,
    pub content: Vec<SemanticBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MceBranchKind {
    Choice,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MceSelection {
    SelectedChoice,
    SelectedFallback,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceNamespaceRequirement {
    pub prefix: String,
    pub namespace_uri: Option<String>,
    pub supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceCompatibilityAttributes {
    pub ignorable_raw: Option<String>,
    pub ignorable_namespaces: Vec<String>,
    pub process_content: Vec<MceQualifiedName>,
    pub preserve_elements: Vec<MceQualifiedName>,
    pub preserve_attributes: Vec<MceQualifiedName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceQualifiedName {
    pub raw: String,
    pub namespace_uri: Option<String>,
    pub local_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceResolutionDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcSignatureRegistryProjection {
    pub source_part: String,
    pub origins: Vec<OpcSignatureOriginProjection>,
    pub signatures: Vec<OpcSignatureProjection>,
    pub diagnostics: Vec<SignatureDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcSignatureOriginProjection {
    pub relationship_id: String,
    pub origin_part_path: String,
    pub source_anchor: SourceAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcSignatureProjection {
    pub signature_part_path: String,
    pub origin_part_path: String,
    pub relationship_id: String,
    pub xml_signature: XmlSignatureProjection,
    pub verification: SignatureVerificationReport,
    pub source_anchor: SourceAnchor,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlSignatureProjection {
    pub signed_info: SignedInfoProjection,
    pub signature_value: String,
    pub key_info: SignatureKeyInfoProjection,
    pub office_info: Option<OfficeSignatureInfoProjection>,
    pub object_digests: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInfoProjection {
    pub canonicalization_method: String,
    pub signature_method: String,
    pub canonicalized_digest: Option<String>,
    pub references: Vec<SignatureReferenceProjection>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureReferenceProjection {
    pub uri: String,
    pub digest_method: String,
    pub digest_value: String,
    pub transforms: Vec<SignatureTransformProjection>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureTransformProjection {
    pub algorithm: String,
    pub relationship_references: Vec<String>,
    pub relationship_group_references: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureKeyInfoProjection {
    pub key_value_rsa: Option<RsaKeyValueProjection>,
    pub x509_certificates: Vec<X509CertificateProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaKeyValueProjection {
    pub modulus_b64: String,
    pub exponent_b64: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509CertificateProjection {
    pub der_sha256: String,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub public_key_algorithm: Option<String>,
    #[serde(default)]
    pub rsa_public_key: Option<RsaKeyValueProjection>,
    pub malformed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeSignatureInfoProjection {
    pub setup_id: Option<String>,
    pub signature_comments: Option<String>,
    pub signature_provider_id: Option<String>,
    pub signature_provider_url: Option<String>,
    pub signature_type: Option<String>,
    pub unknown_object_digests: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationReport {
    pub status: SignatureVerificationStatus,
    pub cryptographic_validity: SignatureVerificationStatus,
    pub certificate_trust: SignatureVerificationStatus,
    pub signature_value_status: SignatureVerificationStatus,
    #[serde(default)]
    pub key_source: Option<SignatureKeySource>,
    #[serde(default)]
    pub certificate_index: Option<usize>,
    #[serde(default)]
    pub public_key_fingerprint: Option<String>,
    pub key_fingerprint: Option<String>,
    pub signed_info_digest: Option<String>,
    pub references: Vec<SignatureReferenceVerification>,
    pub diagnostics: Vec<SignatureDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKeySource {
    RsaKeyValue,
    X509Certificate,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureVerificationStatus {
    Valid,
    Invalid,
    UnsupportedAlgorithm,
    UnsupportedTransform,
    MissingKey,
    Malformed,
    #[default]
    UnassessedTrust,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureReferenceVerification {
    pub uri: String,
    pub status: SignatureVerificationStatus,
    pub expected_digest: String,
    pub actual_digest: Option<String>,
    pub target_part_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Read-only projection of tracked changes across a DOCX story part.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackChangesProjection {
    pub source_part: String,
    pub changes: Vec<TrackedChange>,
    pub move_ranges: Vec<MoveRangeProjection>,
    pub diagnostics: Vec<TrackChangeResolutionDiagnostic>,
    pub unsupported_features: Vec<UnsupportedSemanticFeature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedChange {
    pub id: TrackedChangeId,
    pub kind: TrackedChangeKind,
    pub metadata: TrackedChangeMetadata,
    pub content: TrackedContent,
    pub source_anchor: SourceAnchor,
    pub semantic_node_id: SemanticNodeId,
    #[serde(default)]
    pub references: Vec<TrackChangeReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrackedChangeId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackedChangeKind {
    Insertion,
    Deletion,
    MoveFrom,
    MoveTo,
    ParagraphProperties,
    RunProperties,
    TableProperties,
    TableRowProperties,
    TableCellProperties,
    SectionProperties,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrackedChangeMetadata {
    pub change_id: Option<String>,
    pub author: Option<String>,
    pub date_raw: Option<String>,
    pub date_utc_raw: Option<String>,
    pub date: Option<String>,
    pub date_utc: Option<String>,
    pub rsid_r: Option<String>,
    pub rsid_del: Option<String>,
    pub rsid_p: Option<String>,
    pub rsid_rpr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TrackedContent {
    Inline {
        items: Vec<SemanticInline>,
    },
    Block {
        blocks: Vec<SemanticBlock>,
    },
    PropertyChange {
        properties: PropertyChangeProjection,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveRangeProjection {
    pub change_id: String,
    pub start: Option<SourceAnchor>,
    pub end: Option<SourceAnchor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyChangeProjection {
    pub kind: PropertyChangeKind,
    pub source_anchor: SourceAnchor,
    pub previous: Option<Box<PropertyChangeSnapshot>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropertyChangeKind {
    ParagraphProperties,
    RunProperties,
    TableProperties,
    TableRowProperties,
    TableCellProperties,
    SectionProperties,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyChangeSnapshot {
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackChangeReference {
    pub kind: String,
    pub change_id: String,
    pub source_anchor: SourceAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackChangeResolutionDiagnostic {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Semantic block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SemanticBlock {
    Paragraph(SemanticParagraph),
    Table(SemanticTable),
    TrackedChange(TrackedChange),
    MceSelectedContent(MceSelectedContent),
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
    #[serde(default)]
    pub section_story_references: Vec<HeaderFooterReferenceProjection>,
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
    Hyperlink(HyperlinkProjection),
    BookmarkStart(BookmarkProjection),
    BookmarkEnd(BookmarkProjection),
    Field(FieldProjection),
    Drawing(DrawingProjection),
    EmbeddedVisualObject(EmbeddedVisualObjectProjection),
    Tab,
    LineBreak {
        break_kind: String,
    },
    FootnoteReference {
        note_id: String,
        resolved_part_path: Option<String>,
    },
    EndnoteReference {
        note_id: String,
        resolved_part_path: Option<String>,
    },
    CommentReference {
        comment_id: String,
        resolved_part_path: Option<String>,
    },
    CommentRangeStart {
        comment_id: String,
    },
    CommentRangeEnd {
        comment_id: String,
    },
    TrackedChange {
        change: Box<TrackedChange>,
    },
    MceSelectedContent(MceSelectedContent),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MceSelectedContent {
    pub projection: MceAlternateContentProjection,
    pub projection_id: SemanticNodeId,
    pub selected_branch_index: Option<usize>,
    pub selected_branch_kind: MceSelection,
    #[serde(default)]
    pub blocks: Vec<SemanticBlock>,
    #[serde(default)]
    pub inlines: Vec<SemanticInline>,
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

/// Read-only projection of headers, footers, notes, and comments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoryRegistryProjection {
    pub source_part: String,
    pub parts: Vec<StoryPartProjection>,
    pub references: Vec<StoryReference>,
    pub diagnostics: Vec<StoryResolutionDiagnostic>,
    pub unsupported_features: Vec<UnsupportedSemanticFeature>,
}

/// Projected story part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoryPartProjection {
    pub id: SemanticNodeId,
    pub kind: StoryPartKind,
    pub source_part: String,
    pub source_anchor: SourceAnchor,
    #[serde(default)]
    pub section_story_references: Vec<HeaderFooterReferenceProjection>,
    pub blocks: Vec<SemanticBlock>,
    #[serde(default)]
    pub notes: Vec<NoteProjection>,
    #[serde(default)]
    pub comments: Vec<CommentProjection>,
    #[serde(default)]
    pub references: Vec<StoryReference>,
    pub diagnostics: Vec<StoryResolutionDiagnostic>,
    pub unsupported_features: Vec<UnsupportedSemanticFeature>,
}

/// Story part kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoryPartKind {
    MainDocument,
    HeaderDefault,
    HeaderFirst,
    HeaderEven,
    FooterDefault,
    FooterFirst,
    FooterEven,
    Footnotes,
    Endnotes,
    Comments,
}

/// Relationship or note/comment reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoryReference {
    pub kind: StoryReferenceKind,
    pub source_anchor: SourceAnchor,
    #[serde(default)]
    pub source_identifier: Option<String>,
    #[serde(default)]
    pub relationship_id: Option<String>,
    #[serde(default)]
    pub relationship_type: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub target_mode: Option<TargetMode>,
    #[serde(default)]
    pub resolved_part_path: Option<String>,
}

/// Story reference kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoryReferenceKind {
    HeaderReference,
    FooterReference,
    FootnoteReference,
    EndnoteReference,
    CommentReference,
    CommentRangeStart,
    CommentRangeEnd,
}

/// Header/footer reference projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderFooterReferenceProjection {
    pub section_index: u64,
    pub kind: StoryPartKind,
    pub relationship_id: String,
    pub relationship_type: String,
    pub target: String,
    #[serde(default)]
    pub resolved_part_path: Option<String>,
    pub source_anchor: SourceAnchor,
}

/// Footnote or endnote projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteProjection {
    pub note_id: String,
    pub is_reserved: bool,
    pub source_anchor: SourceAnchor,
    pub blocks: Vec<SemanticBlock>,
    #[serde(default)]
    pub references: Vec<StoryReference>,
    pub diagnostics: Vec<StoryResolutionDiagnostic>,
}

/// Comment projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentProjection {
    pub comment_id: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub initials: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    pub source_anchor: SourceAnchor,
    pub blocks: Vec<SemanticBlock>,
    #[serde(default)]
    pub ranges: Vec<CommentRangeProjection>,
    pub diagnostics: Vec<StoryResolutionDiagnostic>,
}

/// Comment range marker projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentRangeProjection {
    pub comment_id: String,
    pub kind: StoryReferenceKind,
    pub source_anchor: SourceAnchor,
}

/// Story projection diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoryResolutionDiagnostic {
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
    StoryProjection,
    TrackChangesProjection,
    MceProjection,
    OpcSignatureProjection,
    DocumentReferencesProjection,
    DrawingImageProjection,
    EmbeddedVisualObjectsProjection,
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
            Self::StoryProjection => "story_projection",
            Self::TrackChangesProjection => "track_changes_projection",
            Self::MceProjection => "mce_projection",
            Self::OpcSignatureProjection => "opc_signature_projection",
            Self::DocumentReferencesProjection => "document_references_projection",
            Self::DrawingImageProjection => "drawing_image_projection",
            Self::EmbeddedVisualObjectsProjection => "embedded_visual_objects_projection",
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
