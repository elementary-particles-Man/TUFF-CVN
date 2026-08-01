//! DOCX import entry point for TUFF-CVN.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use base64::Engine;
use cvn_core::{
    AbstractNumberingProjection, BookmarkBoundaryKind, BookmarkProjection, BookmarkRangeProjection,
    ChartDataReferenceProjection, ChartProjection, ChartSeriesProjection, ChartTitleProjection,
    CommentProjection, CommentRangeProjection, ContentTypeDefault, ContentTypeOverride,
    ContentTypesProjection, CrossReferenceProjection, CvnDocument, DiagramPartReferenceProjection,
    DiagramProjection, DocumentId, DocumentReferenceDiagnostic, DocumentReferencesProjection,
    DrawingCropProjection, DrawingExtentProjection, DrawingGeometryProjection, DrawingKind,
    DrawingMetadataProjection, DrawingOffsetProjection, DrawingPlacement,
    DrawingPositionProjection, DrawingProjection, DrawingRegistryProjection,
    DrawingResolutionDiagnostic, DrawingTarget, DrawingTargetKind, DrawingTransformProjection,
    DrawingWrapProjection, EmbeddedObjectTarget, EmbeddedObjectTargetKind,
    EmbeddedResourceProjection, EmbeddedVisualObjectDiagnostic, EmbeddedVisualObjectKind,
    EmbeddedVisualObjectProjection, EmbeddedVisualObjectsProjection, FieldCharacterKind,
    FieldCharacterKindProjection, FieldInstructionProjection, FieldKind, FieldProjection,
    FieldResultProjection, HeaderFooterReferenceProjection, HyperlinkProjection, HyperlinkTarget,
    HyperlinkTargetKind, ImageResourceProjection, MceAlternateContentProjection, MceBranchKind,
    MceBranchProjection, MceCapabilities, MceCompatibilityAttributes, MceNamespaceRequirement,
    MceProjection, MceQualifiedName, MceResolutionDiagnostic, MceSelectedContent, MceSelection,
    NoteProjection, NumberFormatProjection, NumberingInstanceProjection, NumberingLevelProjection,
    NumberingReference, NumberingRegistryProjection, NumberingResolutionDiagnostic,
    OfficeSignatureInfoProjection, OleMetadataProjection, OleObjectProjection, OpaqueEntry,
    OpcPackageProjection, OpcPart, OpcRelationship, OpcSignatureOriginProjection,
    OpcSignatureProjection, OpcSignatureRegistryProjection, ParagraphPropertiesProjection,
    PreservationMode, ResolvedStyleProjection, RsaKeyValueProjection, RunPropertiesProjection,
    SemanticBlock, SemanticDocument, SemanticInline, SemanticNodeId, SemanticParagraph,
    SemanticRun, SemanticTable, SemanticTableCell, SemanticTableRow, SemanticText,
    SignatureDiagnostic, SignatureKeyInfoProjection, SignatureKeySource,
    SignatureReferenceProjection, SignatureReferenceVerification, SignatureTransformProjection,
    SignatureVerificationReport, SignatureVerificationStatus, SignedInfoProjection, SourceAnchor,
    SourceDescriptor, SourceFormat, StoryPartKind, StoryPartProjection, StoryReference,
    StoryReferenceKind, StoryRegistryProjection, StoryResolutionDiagnostic,
    StyleDefinitionProjection, StyleReference, StyleRegistryProjection, StyleResolutionDiagnostic,
    StyleType, TargetMode, TrackChangesProjection, TrackedChange, TrackedChangeId,
    TrackedChangeKind, TrackedChangeMetadata, TrackedContent, UnsupportedFeatureHandling,
    UnsupportedSemanticFeature, X509CertificateProjection, ZipEntryMetadata,
};
use cvn_package::{sha256_hex, write_package, CvnPackage, PackageObject};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use quick_xml::Writer;
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;
use zip::read::ZipArchive;

/// DOCX import limits.
#[derive(Debug, Clone, Copy)]
pub struct ImportLimits {
    pub max_entries: usize,
    pub max_total_uncompressed_size: u64,
    pub max_single_entry_uncompressed_size: u64,
    pub max_compression_ratio: u64,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_total_uncompressed_size: 512 * 1024 * 1024,
            max_single_entry_uncompressed_size: 128 * 1024 * 1024,
            max_compression_ratio: 200,
        }
    }
}

/// DOCX import error.
#[derive(Debug, Error)]
pub enum DocxImportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("package error: {0}")]
    Package(#[from] cvn_package::PackageError),
    #[error("XML error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("invalid OPC path: {0}")]
    InvalidPath(String),
    #[error("duplicate ZIP entry: {0}")]
    DuplicateEntry(String),
    #[error("unsupported ZIP entry type: {0}")]
    UnsupportedEntry(String),
    #[error("ZIP entry count limit exceeded: {actual} > {limit}")]
    EntryCountLimit { actual: usize, limit: usize },
    #[error("ZIP entry uncompressed size limit exceeded for {path}: {size} > {limit}")]
    EntrySizeLimit { path: String, size: u64, limit: u64 },
    #[error("ZIP total uncompressed size limit exceeded: {size} > {limit}")]
    TotalSizeLimit { size: u64, limit: u64 },
    #[error("ZIP compression ratio limit exceeded for {path}")]
    CompressionRatioLimit { path: String },
    #[error("missing required [Content_Types].xml part")]
    MissingContentTypes,
    #[error("DOCTYPE is not allowed in OPC XML projection: {path}")]
    DoctypeNotAllowed { path: String },
    #[error("semantic ID collision: {0}")]
    SemanticIdCollision(String),
}

/// Returns whether DOCX import is implemented.
pub fn is_implemented() -> bool {
    true
}

const MCE_CAPABILITY_VERSION: &str = "cvn-mce-capabilities-v1";
const MC_NAMESPACE: &str = "http://schemas.openxmlformats.org/markup-compatibility/2006";
const WML_TRANSITIONAL_NAMESPACE: &str =
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const WML_STRICT_NAMESPACE: &str = "http://purl.oclc.org/ooxml/wordprocessingml/main";
const WP_NAMESPACE: &str = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing";
const DRAWINGML_MAIN_NAMESPACE: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
const DRAWINGML_PICTURE_NAMESPACE: &str =
    "http://schemas.openxmlformats.org/drawingml/2006/picture";
const DRAWINGML_CHART_NAMESPACE: &str = "http://schemas.openxmlformats.org/drawingml/2006/chart";
const DRAWINGML_DIAGRAM_NAMESPACE: &str =
    "http://schemas.openxmlformats.org/drawingml/2006/diagram";
const VML_NAMESPACE: &str = "urn:schemas-microsoft-com:vml";
const OFFICE_NAMESPACE: &str = "urn:schemas-microsoft-com:office:office";
const IMAGE_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image";
const CHART_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart";
const OLE_OBJECT_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject";
const PACKAGE_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/package";
const CONTROL_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/control";
const DIAGRAM_DATA_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramData";
const DIAGRAM_LAYOUT_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramLayout";
const DIAGRAM_STYLE_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramQuickStyle";
const DIAGRAM_COLORS_RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramColors";

fn mce_capabilities() -> MceCapabilities {
    MceCapabilities {
        version: MCE_CAPABILITY_VERSION.to_owned(),
        supported_namespaces: vec![
            WML_STRICT_NAMESPACE.to_owned(),
            WML_TRANSITIONAL_NAMESPACE.to_owned(),
        ],
    }
}

/// Imports a DOCX into an in-memory CVN preservation package.
pub fn import_docx(path: impl AsRef<Path>) -> Result<CvnPackage, DocxImportError> {
    import_docx_with_limits(path, ImportLimits::default())
}

/// Imports a DOCX into a CVN preservation package directory.
pub fn import_docx_to_package(
    input_docx: impl AsRef<Path>,
    output_cvn: impl AsRef<Path>,
) -> Result<CvnDocument, DocxImportError> {
    let package = import_docx(input_docx)?;
    let document = package.document.clone();
    write_package(output_cvn, &package)?;
    Ok(document)
}

/// Imports a DOCX with explicit safety limits.
pub fn import_docx_with_limits(
    path: impl AsRef<Path>,
    limits: ImportLimits,
) -> Result<CvnPackage, DocxImportError> {
    let mut archive = ZipArchive::new(File::open(path.as_ref())?)?;
    if archive.len() > limits.max_entries {
        return Err(DocxImportError::EntryCountLimit {
            actual: archive.len(),
            limit: limits.max_entries,
        });
    }

    let mut seen_paths = BTreeSet::new();
    let mut raw_parts = Vec::new();
    let mut objects_by_digest = BTreeMap::<String, Vec<u8>>::new();
    let mut total_uncompressed_size = 0_u64;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let is_directory = entry.is_dir();
        let normalized_path = normalize_opc_path(entry.name(), is_directory)?;
        if !seen_paths.insert(normalized_path.clone()) {
            return Err(DocxImportError::DuplicateEntry(normalized_path));
        }

        reject_special_entry(&entry, &normalized_path)?;

        let uncompressed_size = entry.size();
        let compressed_size = entry.compressed_size();
        if uncompressed_size > limits.max_single_entry_uncompressed_size {
            return Err(DocxImportError::EntrySizeLimit {
                path: normalized_path,
                size: uncompressed_size,
                limit: limits.max_single_entry_uncompressed_size,
            });
        }
        total_uncompressed_size = total_uncompressed_size.saturating_add(uncompressed_size);
        if total_uncompressed_size > limits.max_total_uncompressed_size {
            return Err(DocxImportError::TotalSizeLimit {
                size: total_uncompressed_size,
                limit: limits.max_total_uncompressed_size,
            });
        }
        if compressed_size > 0
            && uncompressed_size / compressed_size.max(1) > limits.max_compression_ratio
        {
            return Err(DocxImportError::CompressionRatioLimit {
                path: normalized_path,
            });
        }

        if is_directory {
            continue;
        }

        let mut bytes = Vec::with_capacity(uncompressed_size as usize);
        entry.read_to_end(&mut bytes)?;
        let digest = sha256_hex(&bytes);
        if let Some(existing) = objects_by_digest.get(&digest) {
            if existing != &bytes {
                return Err(DocxImportError::Package(
                    cvn_package::PackageError::DigestCollision(digest),
                ));
            }
        } else {
            objects_by_digest.insert(digest.clone(), bytes);
        }

        raw_parts.push(RawPart {
            path: normalized_path,
            original_size: uncompressed_size,
            digest,
            metadata: ZipEntryMetadata {
                is_directory,
                compressed_size,
                uncompressed_size,
                compression_method: format!("{:?}", entry.compression()),
            },
        });
    }

    if !raw_parts
        .iter()
        .any(|part| part.path == "[Content_Types].xml")
    {
        return Err(DocxImportError::MissingContentTypes);
    }

    raw_parts.sort_by(|left, right| left.path.cmp(&right.path));

    let content_types_bytes =
        object_bytes_for_part(&raw_parts, &objects_by_digest, "[Content_Types].xml")
            .ok_or(DocxImportError::MissingContentTypes)?;
    let content_types = parse_content_types(content_types_bytes)?;
    let mut relationships = Vec::new();
    for part in &raw_parts {
        if part.path.ends_with(".rels") {
            if let Some(bytes) = objects_by_digest.get(&part.digest) {
                relationships.extend(parse_relationships(&part.path, bytes)?);
            }
        }
    }
    relationships.sort_by(|left, right| {
        left.source_part
            .cmp(&right.source_part)
            .then(left.relationship_id.cmp(&right.relationship_id))
    });

    let parts = raw_parts
        .iter()
        .map(|part| OpcPart {
            original_path: part.path.clone(),
            content_type: resolve_content_type(&content_types, &part.path),
            original_size: part.original_size,
            content_digest: part.digest.clone(),
            compression: part.metadata.clone(),
        })
        .collect::<Vec<_>>();

    let mut document =
        CvnDocument::minimal(DocumentId::new("docx-preservation").expect("valid id"));
    document.manifest.sources.push(SourceDescriptor {
        id: cvn_core::SourceId::new("source-1").expect("valid id"),
        format: SourceFormat::Docx,
        original_name: path
            .as_ref()
            .file_name()
            .map(|name| name.to_string_lossy().into_owned()),
        media_type: Some(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_owned(),
        ),
        length: Some(total_uncompressed_size),
        digest: None,
    });
    document.opaque = objects_by_digest
        .iter()
        .map(|(digest, bytes)| OpaqueEntry {
            id: cvn_core::OpaqueId::new(format!("sha256:{digest}")).expect("valid digest id"),
            media_type: "application/octet-stream".to_owned(),
            original_name: None,
            source_ref: None,
            content_digest: digest.clone(),
            length: bytes.len() as u64,
            preservation_mode: PreservationMode::PackageContentAddressed,
        })
        .collect();
    document.opc = OpcPackageProjection {
        parts,
        content_types,
        relationships,
    };
    document.signatures = Some(build_signature_registry_projection(
        &document.opc,
        &raw_parts,
        &objects_by_digest,
    )?);
    let mce_projection =
        build_mce_projection(&document.document_id, &raw_parts, &objects_by_digest)?;
    if let Some(bytes) = object_bytes_for_part(&raw_parts, &objects_by_digest, "word/document.xml")
    {
        let (semantic, track_changes) =
            parse_semantic_document(&document.document_id, "word/document.xml", bytes)?;
        document.semantic = semantic;
        document.track_changes = track_changes;
    }
    if let Some(bytes) = object_bytes_for_part(&raw_parts, &objects_by_digest, "word/styles.xml") {
        document.semantic.styles = Some(parse_styles(bytes)?);
    }
    if let Some(bytes) = object_bytes_for_part(&raw_parts, &objects_by_digest, "word/numbering.xml")
    {
        document.semantic.numbering = Some(parse_numbering(bytes)?);
    }
    let (stories, story_track_changes) = build_story_registry(
        &document.document_id,
        &raw_parts,
        &objects_by_digest,
        &document.semantic.blocks,
    )?;
    document.semantic.stories = stories;
    document.mce = Some(mce_projection);
    if let Some(mut projection) = document.track_changes.take() {
        for child in story_track_changes {
            projection.changes.extend(child.changes);
            projection.move_ranges.extend(child.move_ranges);
            projection.diagnostics.extend(child.diagnostics);
            projection
                .unsupported_features
                .extend(child.unsupported_features);
        }
        document.track_changes = Some(projection);
    } else if !story_track_changes.is_empty() {
        let mut projection = TrackChangesProjection {
            source_part: "docx-track-changes".to_owned(),
            changes: Vec::new(),
            move_ranges: Vec::new(),
            diagnostics: Vec::new(),
            unsupported_features: Vec::new(),
        };
        for child in story_track_changes {
            projection.changes.extend(child.changes);
            projection.move_ranges.extend(child.move_ranges);
            projection.diagnostics.extend(child.diagnostics);
            projection
                .unsupported_features
                .extend(child.unsupported_features);
        }
        document.track_changes = Some(projection);
    }
    resolve_semantic_references(
        &mut document.semantic,
        &document.opc.relationships,
        &document.opc.content_types,
        &document.opc.parts,
        &objects_by_digest,
    );

    let objects = objects_by_digest
        .into_iter()
        .map(|(digest, bytes)| PackageObject { digest, bytes })
        .collect();

    Ok(CvnPackage { document, objects })
}

#[derive(Debug, Clone)]
struct RawPart {
    path: String,
    original_size: u64,
    digest: String,
    metadata: ZipEntryMetadata,
}

/// Rebuilds the read-only OPC XML signature projection from a CVN document and
/// its content-addressed objects. This is used by verification to avoid trusting
/// the stored projection.
pub fn rebuild_signature_registry_projection(
    document: &CvnDocument,
    objects: &[PackageObject],
) -> Result<OpcSignatureRegistryProjection, DocxImportError> {
    let raw_parts = document
        .opc
        .parts
        .iter()
        .map(|part| RawPart {
            path: part.original_path.clone(),
            original_size: part.original_size,
            digest: part.content_digest.clone(),
            metadata: part.compression.clone(),
        })
        .collect::<Vec<_>>();
    let objects_by_digest = objects
        .iter()
        .map(|object| (object.digest.clone(), object.bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    build_signature_registry_projection(&document.opc, &raw_parts, &objects_by_digest)
}

fn object_bytes_for_part<'a>(
    parts: &[RawPart],
    objects: &'a BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Option<&'a [u8]> {
    let digest = &parts.iter().find(|part| part.path == path)?.digest;
    objects.get(digest).map(Vec::as_slice)
}

fn build_story_registry(
    document_id: &DocumentId,
    raw_parts: &[RawPart],
    objects_by_digest: &BTreeMap<String, Vec<u8>>,
    semantic_blocks: &[SemanticBlock],
) -> Result<(Option<StoryRegistryProjection>, Vec<TrackChangesProjection>), DocxImportError> {
    let mut registry = StoryRegistryProjection {
        source_part: "docx-story-registry".to_owned(),
        ..StoryRegistryProjection::default()
    };
    let mut has_candidates = contains_story_references(semantic_blocks);
    let mut story_id_set = BTreeSet::new();
    let mut diagnostics = Vec::new();
    let mut track_changes = Vec::new();

    for part in raw_parts {
        if let Some(kind) = classify_story_part(&part.path) {
            match kind {
                StoryPartKind::HeaderDefault
                | StoryPartKind::HeaderFirst
                | StoryPartKind::HeaderEven
                | StoryPartKind::FooterDefault
                | StoryPartKind::FooterFirst
                | StoryPartKind::FooterEven => {
                    has_candidates = true;
                    if let Some(bytes) = objects_by_digest.get(&part.digest) {
                        let (semantic, track_change) =
                            parse_semantic_document(document_id, &part.path, bytes)?;
                        if let Some(track_change) = track_change {
                            track_changes.push(track_change);
                        }
                        let id = semantic_id(
                            document_id,
                            &part.path,
                            "story-part",
                            None,
                            "/",
                            &part.digest,
                            &mut story_id_set,
                        )?;
                        registry.parts.push(StoryPartProjection {
                            id,
                            kind,
                            source_part: part.path.clone(),
                            source_anchor: SourceAnchor {
                                source_part_path: part.path.clone(),
                                xml_path: "/".to_owned(),
                                byte_start: Some(0),
                            },
                            section_story_references: Vec::new(),
                            blocks: semantic.blocks,
                            notes: Vec::new(),
                            comments: Vec::new(),
                            references: Vec::new(),
                            diagnostics: Vec::new(),
                            unsupported_features: semantic.unsupported_features,
                        });
                    }
                }
                StoryPartKind::Footnotes => {
                    has_candidates = true;
                    if let Some(bytes) = objects_by_digest.get(&part.digest) {
                        let (semantic, track_change) =
                            parse_semantic_document(document_id, &part.path, bytes)?;
                        if let Some(track_change) = track_change {
                            track_changes.push(track_change);
                        }
                        let items = collect_note_items(
                            document_id,
                            &part.path,
                            bytes,
                            "footnote",
                            "CVN_FOOTNOTE_DUPLICATE_ID",
                            &mut diagnostics,
                        )?;
                        let id = semantic_id(
                            document_id,
                            &part.path,
                            "story-part",
                            None,
                            "/",
                            &part.digest,
                            &mut story_id_set,
                        )?;
                        let blocks = semantic.blocks;
                        registry.parts.push(StoryPartProjection {
                            id,
                            kind,
                            source_part: part.path.clone(),
                            source_anchor: SourceAnchor {
                                source_part_path: part.path.clone(),
                                xml_path: "/".to_owned(),
                                byte_start: Some(0),
                            },
                            section_story_references: Vec::new(),
                            blocks: Vec::new(),
                            notes: items
                                .into_iter()
                                .map(|item| NoteProjection {
                                    note_id: item.note_id,
                                    is_reserved: item.is_reserved,
                                    source_anchor: item.source_anchor,
                                    blocks: blocks_with_prefix(&blocks, &item.xml_path),
                                    references: Vec::new(),
                                    diagnostics: Vec::new(),
                                })
                                .collect(),
                            comments: Vec::new(),
                            references: Vec::new(),
                            diagnostics: Vec::new(),
                            unsupported_features: semantic.unsupported_features,
                        });
                    }
                }
                StoryPartKind::Endnotes => {
                    has_candidates = true;
                    if let Some(bytes) = objects_by_digest.get(&part.digest) {
                        let (semantic, track_change) =
                            parse_semantic_document(document_id, &part.path, bytes)?;
                        if let Some(track_change) = track_change {
                            track_changes.push(track_change);
                        }
                        let items = collect_note_items(
                            document_id,
                            &part.path,
                            bytes,
                            "endnote",
                            "CVN_ENDNOTE_DUPLICATE_ID",
                            &mut diagnostics,
                        )?;
                        let id = semantic_id(
                            document_id,
                            &part.path,
                            "story-part",
                            None,
                            "/",
                            &part.digest,
                            &mut story_id_set,
                        )?;
                        let blocks = semantic.blocks;
                        registry.parts.push(StoryPartProjection {
                            id,
                            kind,
                            source_part: part.path.clone(),
                            source_anchor: SourceAnchor {
                                source_part_path: part.path.clone(),
                                xml_path: "/".to_owned(),
                                byte_start: Some(0),
                            },
                            section_story_references: Vec::new(),
                            blocks: Vec::new(),
                            notes: items
                                .into_iter()
                                .map(|item| NoteProjection {
                                    note_id: item.note_id,
                                    is_reserved: item.is_reserved,
                                    source_anchor: item.source_anchor,
                                    blocks: blocks_with_prefix(&blocks, &item.xml_path),
                                    references: Vec::new(),
                                    diagnostics: Vec::new(),
                                })
                                .collect(),
                            comments: Vec::new(),
                            references: Vec::new(),
                            diagnostics: Vec::new(),
                            unsupported_features: semantic.unsupported_features,
                        });
                    }
                }
                StoryPartKind::Comments => {
                    has_candidates = true;
                    if let Some(bytes) = objects_by_digest.get(&part.digest) {
                        let (semantic, track_change) =
                            parse_semantic_document(document_id, &part.path, bytes)?;
                        if let Some(track_change) = track_change {
                            track_changes.push(track_change);
                        }
                        let items = collect_comment_items(
                            document_id,
                            &part.path,
                            bytes,
                            &mut diagnostics,
                        )?;
                        let id = semantic_id(
                            document_id,
                            &part.path,
                            "story-part",
                            None,
                            "/",
                            &part.digest,
                            &mut story_id_set,
                        )?;
                        let blocks = semantic.blocks;
                        registry.parts.push(StoryPartProjection {
                            id,
                            kind,
                            source_part: part.path.clone(),
                            source_anchor: SourceAnchor {
                                source_part_path: part.path.clone(),
                                xml_path: "/".to_owned(),
                                byte_start: Some(0),
                            },
                            section_story_references: Vec::new(),
                            blocks: Vec::new(),
                            notes: Vec::new(),
                            comments: items
                                .into_iter()
                                .map(|item| CommentProjection {
                                    comment_id: item.comment_id,
                                    author: item.author,
                                    initials: item.initials,
                                    date: item.date,
                                    source_anchor: item.source_anchor,
                                    blocks: blocks_with_prefix(&blocks, &item.xml_path),
                                    ranges: Vec::new(),
                                    diagnostics: Vec::new(),
                                })
                                .collect(),
                            references: Vec::new(),
                            diagnostics: Vec::new(),
                            unsupported_features: semantic.unsupported_features,
                        });
                    }
                }
                StoryPartKind::MainDocument => {}
            }
        }
    }

    if !has_candidates {
        return Ok((None, track_changes));
    }

    registry.parts.sort_by(|left, right| {
        left.source_part
            .cmp(&right.source_part)
            .then(left.kind.cmp(&right.kind))
    });
    Ok((Some(registry), track_changes))
}

fn blocks_with_prefix(blocks: &[SemanticBlock], prefix: &str) -> Vec<SemanticBlock> {
    blocks
        .iter()
        .filter(|block| story_block_has_prefix(block, prefix))
        .cloned()
        .collect()
}

fn story_block_has_prefix(block: &SemanticBlock, prefix: &str) -> bool {
    match block {
        SemanticBlock::Paragraph(paragraph) => paragraph.source_anchor.xml_path.starts_with(prefix),
        SemanticBlock::Table(table) => table.source_anchor.xml_path.starts_with(prefix),
        SemanticBlock::TrackedChange(change) => change.source_anchor.xml_path.starts_with(prefix),
        SemanticBlock::MceSelectedContent(content) => content
            .projection
            .source_anchor
            .xml_path
            .starts_with(prefix),
    }
}

#[derive(Debug, Clone)]
struct StoryItemProjection {
    note_id: String,
    is_reserved: bool,
    author: Option<String>,
    initials: Option<String>,
    date: Option<String>,
    source_anchor: SourceAnchor,
    xml_path: String,
    comment_id: String,
}

fn collect_note_items(
    document_id: &DocumentId,
    source_part: &str,
    bytes: &[u8],
    item_local_name: &str,
    duplicate_code: &str,
    diagnostics: &mut Vec<StoryResolutionDiagnostic>,
) -> Result<Vec<StoryItemProjection>, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = vec![dsig_scope()];
    let mut path_stack: Vec<String> = Vec::new();
    let mut child_counts: Vec<BTreeMap<String, usize>> = vec![BTreeMap::new()];
    let mut seen = BTreeSet::new();
    let mut items = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                if name.local_name == item_local_name && name.is_wordprocessingml() {
                    let note_id = attr_named(&attrs, "id")
                        .cloned()
                        .or_else(|| attrs.get("w:id").cloned())
                        .unwrap_or_default();
                    if seen.insert(note_id.clone()) {
                        items.push(StoryItemProjection {
                            note_id: note_id.clone(),
                            is_reserved: is_reserved_note_id(&note_id),
                            author: None,
                            initials: None,
                            date: None,
                            source_anchor: SourceAnchor {
                                source_part_path: source_part.to_owned(),
                                xml_path: path.clone(),
                                byte_start: Some(reader.buffer_position()),
                            },
                            xml_path: path,
                            comment_id: note_id,
                        });
                    } else {
                        diagnostics.push(story_diag(
                            duplicate_code,
                            &path,
                            format!("story note `{note_id}` is defined more than once"),
                        ));
                    }
                }
            }
            Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                if name.local_name == item_local_name && name.is_wordprocessingml() {
                    let note_id = attr_named(&attrs, "id")
                        .cloned()
                        .or_else(|| attrs.get("w:id").cloned())
                        .unwrap_or_default();
                    if seen.insert(note_id.clone()) {
                        items.push(StoryItemProjection {
                            note_id: note_id.clone(),
                            is_reserved: is_reserved_note_id(&note_id),
                            author: None,
                            initials: None,
                            date: None,
                            source_anchor: SourceAnchor {
                                source_part_path: source_part.to_owned(),
                                xml_path: path.clone(),
                                byte_start: Some(reader.buffer_position()),
                            },
                            xml_path: path,
                            comment_id: note_id,
                        });
                    } else {
                        diagnostics.push(story_diag(
                            duplicate_code,
                            &path,
                            format!("story note `{note_id}` is defined more than once"),
                        ));
                    }
                }
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::End(_) => {
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    let _ = document_id;
    Ok(items)
}

fn collect_comment_items(
    document_id: &DocumentId,
    source_part: &str,
    bytes: &[u8],
    diagnostics: &mut Vec<StoryResolutionDiagnostic>,
) -> Result<Vec<StoryItemProjection>, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = vec![dsig_scope()];
    let mut path_stack: Vec<String> = Vec::new();
    let mut child_counts: Vec<BTreeMap<String, usize>> = vec![BTreeMap::new()];
    let mut seen = BTreeSet::new();
    let mut items = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                if name.local_name == "comment" && name.is_wordprocessingml() {
                    let comment_id = attr_named(&attrs, "id")
                        .cloned()
                        .or_else(|| attrs.get("w:id").cloned())
                        .unwrap_or_default();
                    if seen.insert(comment_id.clone()) {
                        items.push(StoryItemProjection {
                            note_id: comment_id.clone(),
                            is_reserved: false,
                            author: attr_named(&attrs, "author").cloned(),
                            initials: attr_named(&attrs, "initials").cloned(),
                            date: attr_named(&attrs, "date").cloned(),
                            source_anchor: SourceAnchor {
                                source_part_path: source_part.to_owned(),
                                xml_path: path.clone(),
                                byte_start: Some(reader.buffer_position()),
                            },
                            xml_path: path,
                            comment_id,
                        });
                    } else {
                        diagnostics.push(story_diag(
                            "CVN_COMMENT_DUPLICATE_ID",
                            &path,
                            format!("comment `{comment_id}` is defined more than once"),
                        ));
                    }
                }
            }
            Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                if name.local_name == "comment" && name.is_wordprocessingml() {
                    let comment_id = attr_named(&attrs, "id")
                        .cloned()
                        .or_else(|| attrs.get("w:id").cloned())
                        .unwrap_or_default();
                    if seen.insert(comment_id.clone()) {
                        items.push(StoryItemProjection {
                            note_id: comment_id.clone(),
                            is_reserved: false,
                            author: attr_named(&attrs, "author").cloned(),
                            initials: attr_named(&attrs, "initials").cloned(),
                            date: attr_named(&attrs, "date").cloned(),
                            source_anchor: SourceAnchor {
                                source_part_path: source_part.to_owned(),
                                xml_path: path.clone(),
                                byte_start: Some(reader.buffer_position()),
                            },
                            xml_path: path,
                            comment_id,
                        });
                    } else {
                        diagnostics.push(story_diag(
                            "CVN_COMMENT_DUPLICATE_ID",
                            &path,
                            format!("comment `{comment_id}` is defined more than once"),
                        ));
                    }
                }
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::End(_) => {
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    let _ = document_id;
    Ok(items)
}

fn contains_story_references(blocks: &[SemanticBlock]) -> bool {
    for block in blocks {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                if !paragraph.section_story_references.is_empty() {
                    return true;
                }
                for run in &paragraph.runs {
                    for inline in &run.inlines {
                        match inline {
                            SemanticInline::FootnoteReference { .. }
                            | SemanticInline::EndnoteReference { .. }
                            | SemanticInline::CommentReference { .. }
                            | SemanticInline::CommentRangeStart { .. }
                            | SemanticInline::CommentRangeEnd { .. } => return true,
                            SemanticInline::TrackedChange { change } => {
                                if tracked_change_contains_story_references(change) {
                                    return true;
                                }
                            }
                            SemanticInline::MceSelectedContent(content) => {
                                if contains_story_references(&content.blocks)
                                    || mce_inlines_contain_story_references(&content.inlines)
                                {
                                    return true;
                                }
                            }
                            SemanticInline::Hyperlink(hyperlink) => {
                                if mce_inlines_contain_story_references(&hyperlink.children) {
                                    return true;
                                }
                            }
                            SemanticInline::Field(field) => {
                                if mce_inlines_contain_story_references(&field.result.children) {
                                    return true;
                                }
                            }
                            SemanticInline::Text(_)
                            | SemanticInline::BookmarkStart(_)
                            | SemanticInline::BookmarkEnd(_)
                            | SemanticInline::Drawing(_)
                            | SemanticInline::EmbeddedVisualObject(_)
                            | SemanticInline::Tab
                            | SemanticInline::LineBreak { .. } => {}
                        }
                    }
                }
            }
            SemanticBlock::Table(table) => {
                if contains_story_references_in_table(table) {
                    return true;
                }
            }
            SemanticBlock::TrackedChange(change) => {
                if tracked_change_contains_story_references(change) {
                    return true;
                }
            }
            SemanticBlock::MceSelectedContent(content) => {
                if contains_story_references(&content.blocks)
                    || mce_inlines_contain_story_references(&content.inlines)
                {
                    return true;
                }
            }
        }
    }
    false
}

fn mce_inlines_contain_story_references(inlines: &[SemanticInline]) -> bool {
    inlines.iter().any(|inline| match inline {
        SemanticInline::FootnoteReference { .. }
        | SemanticInline::EndnoteReference { .. }
        | SemanticInline::CommentReference { .. }
        | SemanticInline::CommentRangeStart { .. }
        | SemanticInline::CommentRangeEnd { .. } => true,
        SemanticInline::TrackedChange { change } => {
            tracked_change_contains_story_references(change)
        }
        SemanticInline::MceSelectedContent(content) => {
            contains_story_references(&content.blocks)
                || mce_inlines_contain_story_references(&content.inlines)
        }
        SemanticInline::Hyperlink(hyperlink) => {
            mce_inlines_contain_story_references(&hyperlink.children)
        }
        SemanticInline::Field(field) => {
            mce_inlines_contain_story_references(&field.result.children)
        }
        SemanticInline::Text(_)
        | SemanticInline::BookmarkStart(_)
        | SemanticInline::BookmarkEnd(_)
        | SemanticInline::Drawing(_)
        | SemanticInline::EmbeddedVisualObject(_)
        | SemanticInline::Tab
        | SemanticInline::LineBreak { .. } => false,
    })
}

fn tracked_change_contains_story_references(change: &TrackedChange) -> bool {
    match &change.content {
        TrackedContent::Inline { items } => items.iter().any(|inline| {
            matches!(
                inline,
                SemanticInline::FootnoteReference { .. }
                    | SemanticInline::EndnoteReference { .. }
                    | SemanticInline::CommentReference { .. }
                    | SemanticInline::CommentRangeStart { .. }
                    | SemanticInline::CommentRangeEnd { .. }
            )
        }),
        TrackedContent::Block { blocks } => contains_story_references(blocks),
        TrackedContent::PropertyChange { .. } => false,
    }
}

fn contains_story_references_in_table(table: &SemanticTable) -> bool {
    for row in &table.rows {
        for cell in &row.cells {
            if contains_story_references(&cell.blocks) {
                return true;
            }
        }
    }
    false
}

fn classify_story_part(path: &str) -> Option<StoryPartKind> {
    match path {
        p if p.starts_with("word/header") && p.ends_with(".xml") => {
            Some(StoryPartKind::HeaderDefault)
        }
        p if p.starts_with("word/footer") && p.ends_with(".xml") => {
            Some(StoryPartKind::FooterDefault)
        }
        "word/footnotes.xml" => Some(StoryPartKind::Footnotes),
        "word/endnotes.xml" => Some(StoryPartKind::Endnotes),
        "word/comments.xml" => Some(StoryPartKind::Comments),
        _ => None,
    }
}

fn story_part_kind_from_header_footer_type(value: &str, is_header: bool) -> StoryPartKind {
    match (is_header, value) {
        (true, "first") => StoryPartKind::HeaderFirst,
        (true, "even") => StoryPartKind::HeaderEven,
        (false, "first") => StoryPartKind::FooterFirst,
        (false, "even") => StoryPartKind::FooterEven,
        (true, _) => StoryPartKind::HeaderDefault,
        (false, _) => StoryPartKind::FooterDefault,
    }
}

fn is_reserved_note_id(note_id: &str) -> bool {
    matches!(note_id, "-1" | "0" | "1" | "2")
}

fn resolve_internal_target_path(source_part: &str, target: &str) -> Option<String> {
    if target.starts_with('/') || target.starts_with('\\') {
        return None;
    }
    let parent = Path::new(source_part).parent()?;
    let candidate = parent.join(target);
    let mut normalized = Vec::new();
    for component in candidate.components() {
        use std::path::Component;
        match component {
            Component::Normal(part) => normalized.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop()?;
            }
            _ => return None,
        }
    }
    Some(normalized.join("/"))
}

fn normalize_opc_path(path: &str, is_directory: bool) -> Result<String, DocxImportError> {
    let path = if is_directory {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };

    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.as_bytes().contains(&0)
    {
        return Err(DocxImportError::InvalidPath(path.to_owned()));
    }

    let mut normalized = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(DocxImportError::InvalidPath(path.to_owned()));
        }
        normalized.push(segment);
    }

    Ok(normalized.join("/"))
}

fn reject_special_entry(entry: &zip::read::ZipFile<'_>, path: &str) -> Result<(), DocxImportError> {
    if let Some(mode) = entry.unix_mode() {
        let file_type = mode & 0o170000;
        if file_type == 0o120000
            || (file_type != 0 && file_type != 0o100000 && file_type != 0o040000)
        {
            return Err(DocxImportError::UnsupportedEntry(path.to_owned()));
        }
    }
    Ok(())
}

fn parse_content_types(bytes: &[u8]) -> Result<ContentTypesProjection, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut projection = ContentTypesProjection::default();

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Empty(event) | Event::Start(event) => match event.name().as_ref() {
                b"Default" => {
                    let attrs = attributes(&reader, &event)?;
                    if let (Some(extension), Some(content_type)) =
                        (attrs.get("Extension"), attrs.get("ContentType"))
                    {
                        projection.defaults.push(ContentTypeDefault {
                            extension: extension.clone(),
                            content_type: content_type.clone(),
                        });
                    }
                }
                b"Override" => {
                    let attrs = attributes(&reader, &event)?;
                    if let (Some(part_name), Some(content_type)) =
                        (attrs.get("PartName"), attrs.get("ContentType"))
                    {
                        projection.overrides.push(ContentTypeOverride {
                            part_name: part_name.trim_start_matches('/').to_owned(),
                            content_type: content_type.clone(),
                        });
                    }
                }
                _ => {}
            },
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: "[Content_Types].xml".to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    projection
        .defaults
        .sort_by(|left, right| left.extension.cmp(&right.extension));
    projection
        .overrides
        .sort_by(|left, right| left.part_name.cmp(&right.part_name));
    Ok(projection)
}

fn parse_relationships(
    rels_path: &str,
    bytes: &[u8],
) -> Result<Vec<OpcRelationship>, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let source_part = relationship_source_part(rels_path);
    let mut relationships = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Empty(event) | Event::Start(event)
                if event.name().as_ref() == b"Relationship" =>
            {
                let attrs = attributes(&reader, &event)?;
                if let (Some(id), Some(relationship_type), Some(target)) =
                    (attrs.get("Id"), attrs.get("Type"), attrs.get("Target"))
                {
                    let target_mode = match attrs.get("TargetMode").map(String::as_str) {
                        Some("External") => TargetMode::External,
                        _ => TargetMode::Internal,
                    };
                    relationships.push(OpcRelationship {
                        source_part: source_part.clone(),
                        relationship_id: id.clone(),
                        relationship_type: relationship_type.clone(),
                        target: target.clone(),
                        target_mode,
                    });
                }
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: rels_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    Ok(relationships)
}

const DSIG_NAMESPACE: &str = "http://www.w3.org/2000/09/xmldsig#";
const OPC_SIGNATURE_ORIGIN_REL_TYPE: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";
const OPC_SIGNATURE_REL_TYPE: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";
const RELATIONSHIP_TRANSFORM: &str =
    "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
const CONTENT_TYPE_TRANSFORM: &str =
    "http://schemas.openxmlformats.org/package/2006/ContentTypeTransform";
const C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const C14N_10_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const EXCLUSIVE_C14N_10: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const SHA1_DIGEST: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384_DIGEST: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA512_DIGEST: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

fn build_signature_registry_projection(
    opc: &OpcPackageProjection,
    parts: &[RawPart],
    objects: &BTreeMap<String, Vec<u8>>,
) -> Result<OpcSignatureRegistryProjection, DocxImportError> {
    let mut origins = Vec::new();
    let mut signatures = Vec::new();
    let mut diagnostics = Vec::new();

    for relationship in opc.relationships.iter().filter(|relationship| {
        relationship.source_part.is_none()
            && relationship.relationship_type == OPC_SIGNATURE_ORIGIN_REL_TYPE
    }) {
        if relationship.target_mode == TargetMode::External {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_ORIGIN_RELATIONSHIP_INVALID",
                "$.opc.relationships",
                "signature origin relationship target is external",
            ));
            continue;
        }
        let origin_part_path = match resolve_relationship_target(None, &relationship.target) {
            Some(path) => path,
            None => {
                diagnostics.push(signature_diag(
                    "CVN_SIGNATURE_ORIGIN_RELATIONSHIP_INVALID",
                    "$.opc.relationships",
                    "signature origin relationship target is not a valid package part",
                ));
                continue;
            }
        };
        if object_bytes_for_part(parts, objects, &origin_part_path).is_none() {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_ORIGIN_MISSING",
                &origin_part_path,
                "signature origin part is missing",
            ));
        }
        origins.push(OpcSignatureOriginProjection {
            relationship_id: relationship.relationship_id.clone(),
            origin_part_path: origin_part_path.clone(),
            source_anchor: SourceAnchor {
                source_part_path: "_rels/.rels".to_owned(),
                xml_path: format!(
                    "/Relationships/Relationship[@Id='{}']",
                    relationship.relationship_id
                ),
                byte_start: None,
            },
        });

        let mut signature_relationships = opc
            .relationships
            .iter()
            .filter(|candidate| {
                candidate.source_part.as_deref() == Some(origin_part_path.as_str())
                    && candidate.relationship_type == OPC_SIGNATURE_REL_TYPE
            })
            .collect::<Vec<_>>();
        signature_relationships
            .sort_by(|left, right| left.relationship_id.cmp(&right.relationship_id));
        for signature_relationship in signature_relationships {
            if signature_relationship.target_mode == TargetMode::External {
                diagnostics.push(signature_diag(
                    "CVN_SIGNATURE_PART_MISSING",
                    &origin_part_path,
                    "external signature target is not resolved",
                ));
                continue;
            }
            let Some(signature_part_path) = resolve_relationship_target(
                Some(&origin_part_path),
                &signature_relationship.target,
            ) else {
                diagnostics.push(signature_diag(
                    "CVN_SIGNATURE_PART_MISSING",
                    &origin_part_path,
                    "signature relationship target is not a valid package part",
                ));
                continue;
            };
            let Some(signature_bytes) = object_bytes_for_part(parts, objects, &signature_part_path)
            else {
                diagnostics.push(signature_diag(
                    "CVN_SIGNATURE_PART_MISSING",
                    &signature_part_path,
                    "signature part is missing",
                ));
                continue;
            };
            let mut signature_diagnostics = Vec::new();
            let xml_signature = parse_xml_signature(
                &signature_part_path,
                signature_bytes,
                &mut signature_diagnostics,
            )?;
            let verification = verify_xml_signature(
                opc,
                parts,
                objects,
                &signature_part_path,
                signature_bytes,
                &xml_signature,
                signature_diagnostics.clone(),
            );
            diagnostics.extend(signature_diagnostics);
            signatures.push(OpcSignatureProjection {
                signature_part_path: signature_part_path.clone(),
                origin_part_path: origin_part_path.clone(),
                relationship_id: signature_relationship.relationship_id.clone(),
                xml_signature,
                verification,
                source_anchor: SourceAnchor {
                    source_part_path: signature_part_path,
                    xml_path: "/Signature[1]".to_owned(),
                    byte_start: Some(0),
                },
            });
        }
    }

    origins.sort_by(|left, right| {
        left.origin_part_path
            .cmp(&right.origin_part_path)
            .then(left.relationship_id.cmp(&right.relationship_id))
    });
    signatures.sort_by(|left, right| {
        left.signature_part_path
            .cmp(&right.signature_part_path)
            .then(left.relationship_id.cmp(&right.relationship_id))
    });
    diagnostics.sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    Ok(OpcSignatureRegistryProjection {
        source_part: "opc-signature-registry".to_owned(),
        origins,
        signatures,
        diagnostics,
    })
}

fn parse_xml_signature(
    source_part_path: &str,
    bytes: &[u8],
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> Result<cvn_core::XmlSignatureProjection, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = vec![dsig_scope()];
    let mut signed_info = SignedInfoProjection::default();
    let mut signature_value = String::new();
    let mut key_info = SignatureKeyInfoProjection::default();
    let mut office_info = None;
    let mut object_digests = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) if is_ds_event(&event, &namespace_stack, "SignedInfo") => {
                namespace_stack.push(namespace_declarations(&event)?);
                signed_info = parse_signed_info(source_part_path, &mut reader, diagnostics)?;
                namespace_stack.pop();
            }
            Event::Start(event) if is_ds_event(&event, &namespace_stack, "SignatureValue") => {
                signature_value = read_text_until(&mut reader, "SignatureValue", source_part_path)?;
            }
            Event::Start(event) if is_ds_event(&event, &namespace_stack, "KeyInfo") => {
                let key_info_xml = read_element_xml(&event, &mut reader, source_part_path)?;
                key_info = parse_key_info_xml(&key_info_xml, source_part_path, diagnostics);
            }
            Event::Start(event) if is_ds_event(&event, &namespace_stack, "Object") => {
                let object_xml = read_element_xml(&event, &mut reader, source_part_path)?;
                object_digests.push(sha256_hex(object_xml.as_bytes()));
                if office_info.is_none() {
                    office_info = parse_office_signature_info(&object_xml)?;
                }
            }
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
            }
            Event::Empty(event) if is_ds_event(&event, &namespace_stack, "Object") => {
                let object_xml = empty_event_xml(&event)?;
                object_digests.push(sha256_hex(object_xml.as_bytes()));
            }
            Event::End(_) => {
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    Ok(cvn_core::XmlSignatureProjection {
        signed_info,
        signature_value,
        key_info,
        office_info,
        object_digests,
    })
}

fn parse_signed_info(
    source_part_path: &str,
    reader: &mut Reader<Cursor<&[u8]>>,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> Result<SignedInfoProjection, DocxImportError> {
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = vec![dsig_scope()];
    let mut signed_info = SignedInfoProjection::default();
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Empty(event) | Event::Start(event)
                if is_ds_event(&event, &namespace_stack, "CanonicalizationMethod") =>
            {
                let attrs = attributes(reader, &event)?;
                signed_info.canonicalization_method =
                    attrs.get("Algorithm").cloned().unwrap_or_default();
                if !is_supported_canonicalization(&signed_info.canonicalization_method) {
                    diagnostics.push(signature_diag(
                        "CVN_SIGNATURE_CANONICALIZATION_UNSUPPORTED",
                        source_part_path,
                        "SignedInfo canonicalization method is not supported",
                    ));
                }
            }
            Event::Empty(event) | Event::Start(event)
                if is_ds_event(&event, &namespace_stack, "SignatureMethod") =>
            {
                let attrs = attributes(reader, &event)?;
                signed_info.signature_method = attrs.get("Algorithm").cloned().unwrap_or_default();
                if signature_digest_for_method(&signed_info.signature_method).is_none() {
                    diagnostics.push(signature_diag(
                        "CVN_SIGNATURE_METHOD_UNSUPPORTED",
                        source_part_path,
                        "SignatureMethod algorithm is not supported",
                    ));
                }
            }
            Event::Start(event) if is_ds_event(&event, &namespace_stack, "Reference") => {
                signed_info.references.push(parse_signature_reference(
                    source_part_path,
                    reader,
                    &event,
                    diagnostics,
                )?);
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if name.namespace_uri.as_deref() == Some(DSIG_NAMESPACE)
                    && name.local_name == "SignedInfo"
                {
                    break;
                }
                namespace_stack.pop();
            }
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(signed_info)
}

fn parse_signature_reference(
    source_part_path: &str,
    reader: &mut Reader<Cursor<&[u8]>>,
    event: &BytesStart<'_>,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> Result<SignatureReferenceProjection, DocxImportError> {
    let attrs = attributes(reader, event)?;
    let mut reference = SignatureReferenceProjection {
        uri: attrs.get("URI").cloned().unwrap_or_default(),
        ..SignatureReferenceProjection::default()
    };
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = vec![dsig_scope()];
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) if is_ds_event(&event, &namespace_stack, "Transforms") => {
                reference.transforms = parse_signature_transforms(source_part_path, reader)?;
            }
            Event::Empty(event) | Event::Start(event)
                if is_ds_event(&event, &namespace_stack, "DigestMethod") =>
            {
                let attrs = attributes(reader, &event)?;
                reference.digest_method = attrs.get("Algorithm").cloned().unwrap_or_default();
                if digest_bytes_for_method(&reference.digest_method, b"").is_none() {
                    diagnostics.push(signature_diag(
                        "CVN_SIGNATURE_DIGEST_ALGORITHM_UNSUPPORTED",
                        source_part_path,
                        "DigestMethod algorithm is not supported",
                    ));
                }
            }
            Event::Start(event) if is_ds_event(&event, &namespace_stack, "DigestValue") => {
                reference.digest_value = read_text_until(reader, "DigestValue", source_part_path)?;
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if name.namespace_uri.as_deref() == Some(DSIG_NAMESPACE)
                    && name.local_name == "Reference"
                {
                    break;
                }
                namespace_stack.pop();
            }
            Event::Start(event) => namespace_stack.push(namespace_declarations(&event)?),
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(reference)
}

fn parse_signature_transforms(
    source_part_path: &str,
    reader: &mut Reader<Cursor<&[u8]>>,
) -> Result<Vec<SignatureTransformProjection>, DocxImportError> {
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut transforms = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Empty(event) if is_ds_event(&event, &namespace_stack, "Transform") => {
                let attrs = attributes(reader, &event)?;
                transforms.push(SignatureTransformProjection {
                    algorithm: attrs.get("Algorithm").cloned().unwrap_or_default(),
                    ..SignatureTransformProjection::default()
                });
            }
            Event::Start(event) if is_ds_event(&event, &namespace_stack, "Transform") => {
                let attrs = attributes(reader, &event)?;
                let mut transform = SignatureTransformProjection {
                    algorithm: attrs.get("Algorithm").cloned().unwrap_or_default(),
                    ..SignatureTransformProjection::default()
                };
                read_transform_children(source_part_path, reader, &mut transform)?;
                transforms.push(transform);
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if name.namespace_uri.as_deref() == Some(DSIG_NAMESPACE)
                    && name.local_name == "Transforms"
                {
                    break;
                }
                namespace_stack.pop();
            }
            Event::Start(event) => namespace_stack.push(namespace_declarations(&event)?),
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(transforms)
}

fn read_transform_children(
    source_part_path: &str,
    reader: &mut Reader<Cursor<&[u8]>>,
    transform: &mut SignatureTransformProjection,
) -> Result<(), DocxImportError> {
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Empty(event) | Event::Start(event) => {
                let attrs = attributes(reader, &event)?;
                let name = qname(event.name().as_ref(), &namespace_stack);
                match name.local_name.as_str() {
                    "RelationshipReference" => {
                        if let Some(source_id) = attrs.get("SourceId") {
                            transform.relationship_references.push(source_id.clone());
                        }
                    }
                    "RelationshipsGroupReference" => {
                        if let Some(source_type) = attrs.get("SourceType") {
                            transform
                                .relationship_group_references
                                .push(source_type.clone());
                        }
                    }
                    _ => {}
                }
                if !event.is_empty() {
                    skip_element(reader, &name.local_name)?;
                }
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if name.namespace_uri.as_deref() == Some(DSIG_NAMESPACE)
                    && name.local_name == "Transform"
                {
                    break;
                }
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(())
}

fn parse_key_info_xml(
    xml: &str,
    source_part_path: &str,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> SignatureKeyInfoProjection {
    let mut key_info = SignatureKeyInfoProjection::default();
    if let (Some(modulus_b64), Some(exponent_b64)) = (
        text_between_local(xml, "Modulus"),
        text_between_local(xml, "Exponent"),
    ) {
        let fingerprint = sha256_hex(format!("{modulus_b64}:{exponent_b64}").as_bytes());
        key_info.key_value_rsa = Some(RsaKeyValueProjection {
            modulus_b64,
            exponent_b64,
            fingerprint,
        });
    }
    let mut rest = xml;
    while let Some((start, tag_len)) = rest
        .find("<ds:X509Certificate>")
        .map(|start| (start, "<ds:X509Certificate>".len()))
        .or_else(|| {
            rest.find("<X509Certificate>")
                .map(|start| (start, "<X509Certificate>".len()))
        })
    {
        let content_start = start + tag_len;
        let Some(end) = rest[content_start..].find("</") else {
            break;
        };
        let value = &rest[content_start..content_start + end];
        key_info
            .x509_certificates
            .push(parse_x509_certificate_projection(
                value,
                source_part_path,
                diagnostics,
            ));
        rest = &rest[content_start + end..];
    }
    key_info
}

fn parse_x509_certificate_projection(
    b64: &str,
    source_part_path: &str,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> X509CertificateProjection {
    let cleaned = b64.split_whitespace().collect::<String>();
    let decoded = base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes());
    let Ok(der) = decoded else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_CERTIFICATE_MALFORMED",
            source_part_path,
            "X509Certificate is not valid base64 DER",
        ));
        return malformed_certificate();
    };
    let der_sha256 = sha256_hex(&der);
    match X509Certificate::from_der(&der) {
        Ok((_, certificate)) => {
            let rsa_public_key =
                x509_rsa_public_key_projection(&certificate, source_part_path, diagnostics);
            X509CertificateProjection {
                der_sha256,
                subject: Some(certificate.subject().to_string()),
                issuer: Some(certificate.issuer().to_string()),
                serial: Some(certificate.raw_serial_as_string()),
                not_before: certificate.validity().not_before.to_rfc2822().ok(),
                not_after: certificate.validity().not_after.to_rfc2822().ok(),
                public_key_algorithm: Some(
                    certificate.public_key().algorithm.algorithm.to_string(),
                ),
                rsa_public_key,
                malformed: false,
            }
        }
        Err(_) => {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_CERTIFICATE_MALFORMED",
                source_part_path,
                "X509Certificate DER cannot be parsed",
            ));
            let mut projection = malformed_certificate();
            projection.der_sha256 = der_sha256;
            projection
        }
    }
}

fn malformed_certificate() -> X509CertificateProjection {
    X509CertificateProjection {
        der_sha256: String::new(),
        subject: None,
        issuer: None,
        serial: None,
        not_before: None,
        not_after: None,
        public_key_algorithm: None,
        rsa_public_key: None,
        malformed: true,
    }
}

fn x509_rsa_public_key_projection(
    certificate: &X509Certificate<'_>,
    source_part_path: &str,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> Option<RsaKeyValueProjection> {
    let spki = certificate.public_key();
    let algorithm = spki.algorithm.algorithm.to_string();
    if algorithm != "1.2.840.113549.1.1.1" {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_CERTIFICATE_KEY_ALGORITHM_UNSUPPORTED",
            source_part_path,
            "X.509 SubjectPublicKeyInfo algorithm is not rsaEncryption",
        ));
        return None;
    }
    match spki.parsed() {
        Ok(PublicKey::RSA(rsa_key)) => {
            let modulus = unsigned_integer_bytes(rsa_key.modulus)?;
            let exponent = unsigned_integer_bytes(rsa_key.exponent)?;
            let exponent_value = rsa_key.try_exponent().ok();
            if exponent_value.is_none_or(|value| value <= 1 || value % 2 == 0) {
                diagnostics.push(signature_diag(
                    "CVN_SIGNATURE_CERTIFICATE_RSA_EXPONENT_INVALID",
                    source_part_path,
                    "X.509 RSA public exponent is invalid",
                ));
                return None;
            }
            if modulus.is_empty() || exponent.is_empty() {
                diagnostics.push(signature_diag(
                    "CVN_SIGNATURE_CERTIFICATE_RSA_KEY_MALFORMED",
                    source_part_path,
                    "X.509 RSA public key has empty modulus or exponent",
                ));
                return None;
            }
            let modulus_b64 = base64::engine::general_purpose::STANDARD.encode(&modulus);
            let exponent_b64 = base64::engine::general_purpose::STANDARD.encode(&exponent);
            let fingerprint = sha256_hex(format!("{modulus_b64}:{exponent_b64}").as_bytes());
            Some(RsaKeyValueProjection {
                modulus_b64,
                exponent_b64,
                fingerprint,
            })
        }
        Ok(_) => {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_CERTIFICATE_KEY_ALGORITHM_UNSUPPORTED",
                source_part_path,
                "X.509 SubjectPublicKeyInfo parsed as a non-RSA key",
            ));
            None
        }
        Err(_) => {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_CERTIFICATE_RSA_KEY_MALFORMED",
                source_part_path,
                "X.509 RSA SubjectPublicKeyInfo is malformed",
            ));
            None
        }
    }
}

fn unsigned_integer_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = bytes;
    if value[0] == 0 {
        value = &value[1..];
    } else if value[0] & 0x80 != 0 {
        return None;
    }
    if value.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(value.to_vec())
}

fn parse_office_signature_info(
    xml: &str,
) -> Result<Option<OfficeSignatureInfoProjection>, DocxImportError> {
    if !xml.contains("SignatureInfoV1") {
        return Ok(None);
    }
    let mut projection = OfficeSignatureInfoProjection::default();
    projection.setup_id = text_between_local(xml, "SetupID");
    projection.signature_comments = text_between_local(xml, "SignatureComments");
    projection.signature_provider_id = text_between_local(xml, "SignatureProviderId");
    projection.signature_provider_url = text_between_local(xml, "SignatureProviderUrl");
    projection.signature_type = text_between_local(xml, "SignatureType");
    Ok(Some(projection))
}

fn text_between_local(xml: &str, local: &str) -> Option<String> {
    let start_suffix = format!("{local}>");
    let end_suffix = format!("</");
    let start = xml.find(&start_suffix)? + start_suffix.len();
    let rest = &xml[start..];
    let end = rest.find(&end_suffix)?;
    Some(rest[..end].to_owned())
}

fn verify_xml_signature(
    opc: &OpcPackageProjection,
    parts: &[RawPart],
    objects: &BTreeMap<String, Vec<u8>>,
    signature_part_path: &str,
    signature_bytes: &[u8],
    xml_signature: &cvn_core::XmlSignatureProjection,
    mut diagnostics: Vec<SignatureDiagnostic>,
) -> SignatureVerificationReport {
    let mut references = Vec::new();
    let mut overall_status = SignatureVerificationStatus::Valid;
    for reference in &xml_signature.signed_info.references {
        let verification = verify_signature_reference(
            opc,
            parts,
            objects,
            signature_part_path,
            signature_bytes,
            reference,
            &mut diagnostics,
        );
        if verification.status != SignatureVerificationStatus::Valid {
            overall_status = combine_signature_status(overall_status, verification.status);
        }
        references.push(verification);
    }

    let signed_info_bytes =
        match signed_info_canonical_bytes(signature_bytes, &xml_signature.signed_info) {
            Ok(bytes) => bytes,
            Err(code) => {
                diagnostics.push(signature_diag(
                    code,
                    signature_part_path,
                    "SignedInfo canonicalization failed or is unsupported",
                ));
                overall_status = combine_signature_status(
                    overall_status,
                    SignatureVerificationStatus::UnsupportedAlgorithm,
                );
                Vec::new()
            }
        };
    let signed_info_digest = if signed_info_bytes.is_empty() {
        None
    } else {
        Some(sha256_hex(&signed_info_bytes))
    };
    let signature_value_result = verify_signature_value(
        &xml_signature.signed_info.signature_method,
        &signed_info_bytes,
        &xml_signature.signature_value,
        &xml_signature.key_info,
        signature_part_path,
        &mut diagnostics,
    );
    let signature_value_status = signature_value_result.status;
    if signature_value_status != SignatureVerificationStatus::Valid {
        overall_status = combine_signature_status(overall_status, signature_value_status);
    }
    if xml_signature.signed_info.signature_method == RSA_SHA1
        || xml_signature
            .signed_info
            .references
            .iter()
            .any(|reference| reference.digest_method == SHA1_DIGEST)
    {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_LEGACY_SHA1",
            signature_part_path,
            "SHA-1 is verification-only legacy signature material",
        ));
    }
    diagnostics.push(signature_diag(
        "CVN_SIGNATURE_TRUST_UNASSESSED",
        signature_part_path,
        "certificate trust chain, revocation, and timestamp trust are outside P0-CVN-09",
    ));

    SignatureVerificationReport {
        status: overall_status,
        cryptographic_validity: overall_status,
        certificate_trust: SignatureVerificationStatus::UnassessedTrust,
        signature_value_status,
        key_source: signature_value_result.key_source,
        certificate_index: signature_value_result.certificate_index,
        public_key_fingerprint: signature_value_result.fingerprint.clone(),
        key_fingerprint: signature_value_result.fingerprint,
        signed_info_digest,
        references,
        diagnostics,
    }
}

fn verify_signature_reference(
    opc: &OpcPackageProjection,
    parts: &[RawPart],
    objects: &BTreeMap<String, Vec<u8>>,
    signature_part_path: &str,
    signature_bytes: &[u8],
    reference: &SignatureReferenceProjection,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> SignatureReferenceVerification {
    let expected_digest = reference.digest_value.clone();
    let mut target_part_path = None;
    let target_bytes = match resolve_reference_bytes(
        opc,
        parts,
        objects,
        signature_part_path,
        signature_bytes,
        reference,
        &mut target_part_path,
        diagnostics,
    ) {
        ReferenceBytes::Bytes(bytes) => bytes,
        ReferenceBytes::Unsupported(status) => {
            return SignatureReferenceVerification {
                uri: reference.uri.clone(),
                status,
                expected_digest,
                actual_digest: None,
                target_part_path,
            }
        }
    };
    let Some(actual_digest_bytes) =
        digest_bytes_for_method(&reference.digest_method, &target_bytes)
    else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_DIGEST_ALGORITHM_UNSUPPORTED",
            signature_part_path,
            "Reference DigestMethod is unsupported",
        ));
        return SignatureReferenceVerification {
            uri: reference.uri.clone(),
            status: SignatureVerificationStatus::UnsupportedAlgorithm,
            expected_digest,
            actual_digest: None,
            target_part_path,
        };
    };
    let actual_digest = base64::engine::general_purpose::STANDARD.encode(&actual_digest_bytes);
    let status = if constant_time_eq(actual_digest.as_bytes(), expected_digest.as_bytes()) {
        SignatureVerificationStatus::Valid
    } else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_REFERENCE_DIGEST_MISMATCH",
            signature_part_path,
            "Reference DigestValue does not match recalculated digest",
        ));
        SignatureVerificationStatus::Invalid
    };
    SignatureReferenceVerification {
        uri: reference.uri.clone(),
        status,
        expected_digest,
        actual_digest: Some(actual_digest),
        target_part_path,
    }
}

enum ReferenceBytes {
    Bytes(Vec<u8>),
    Unsupported(SignatureVerificationStatus),
}

#[allow(clippy::too_many_arguments)]
fn resolve_reference_bytes(
    opc: &OpcPackageProjection,
    parts: &[RawPart],
    objects: &BTreeMap<String, Vec<u8>>,
    signature_part_path: &str,
    signature_bytes: &[u8],
    reference: &SignatureReferenceProjection,
    target_part_path: &mut Option<String>,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> ReferenceBytes {
    if reference.uri.starts_with("http://") || reference.uri.starts_with("https://") {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_REFERENCE_EXTERNAL_UNSUPPORTED",
            signature_part_path,
            "External Reference URI is not resolved",
        ));
        return ReferenceBytes::Unsupported(SignatureVerificationStatus::UnsupportedTransform);
    }
    if reference
        .transforms
        .iter()
        .any(|transform| transform.algorithm.contains("xslt"))
    {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_TRANSFORM_UNSUPPORTED",
            signature_part_path,
            "XSLT transform is not executed",
        ));
        return ReferenceBytes::Unsupported(SignatureVerificationStatus::UnsupportedTransform);
    }
    if reference
        .transforms
        .iter()
        .any(|transform| transform.algorithm == RELATIONSHIP_TRANSFORM)
    {
        let Some(path) = part_path_from_reference(signature_part_path, &reference.uri) else {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_REFERENCE_TARGET_MISSING",
                signature_part_path,
                "relationship transform target cannot be resolved",
            ));
            return ReferenceBytes::Unsupported(SignatureVerificationStatus::Malformed);
        };
        *target_part_path = Some(path.clone());
        return relationship_transform_bytes(opc, &path, reference, diagnostics)
            .map(ReferenceBytes::Bytes)
            .unwrap_or(ReferenceBytes::Unsupported(
                SignatureVerificationStatus::UnsupportedTransform,
            ));
    }
    if reference
        .transforms
        .iter()
        .any(|transform| transform.algorithm == CONTENT_TYPE_TRANSFORM)
    {
        *target_part_path = Some("[Content_Types].xml".to_owned());
        return ReferenceBytes::Bytes(content_type_transform_bytes(opc));
    }
    if let Some(fragment) = reference.uri.strip_prefix('#') {
        if let Some(object_xml) = same_document_object(signature_bytes, fragment) {
            return ReferenceBytes::Bytes(object_xml.into_bytes());
        }
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_REFERENCE_TARGET_MISSING",
            signature_part_path,
            "same-document Reference target is missing",
        ));
        return ReferenceBytes::Unsupported(SignatureVerificationStatus::Malformed);
    }
    let Some(path) = part_path_from_reference(signature_part_path, &reference.uri) else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_REFERENCE_TARGET_MISSING",
            signature_part_path,
            "Reference URI cannot be resolved to a package part",
        ));
        return ReferenceBytes::Unsupported(SignatureVerificationStatus::Malformed);
    };
    *target_part_path = Some(path.clone());
    let Some(bytes) = object_bytes_for_part(parts, objects, &path) else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_REFERENCE_TARGET_MISSING",
            &path,
            "Reference target part is missing",
        ));
        return ReferenceBytes::Unsupported(SignatureVerificationStatus::Malformed);
    };
    ReferenceBytes::Bytes(bytes.to_vec())
}

fn relationship_transform_bytes(
    opc: &OpcPackageProjection,
    rels_path: &str,
    reference: &SignatureReferenceProjection,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> Option<Vec<u8>> {
    let source_part = relationship_source_part(rels_path);
    let mut selected = Vec::new();
    for transform in &reference.transforms {
        for source_id in &transform.relationship_references {
            selected.extend(opc.relationships.iter().filter(|relationship| {
                relationship.source_part == source_part
                    && relationship.relationship_id == *source_id
                    && relationship.relationship_type != OPC_SIGNATURE_ORIGIN_REL_TYPE
                    && relationship.relationship_type != OPC_SIGNATURE_REL_TYPE
            }));
        }
        for source_type in &transform.relationship_group_references {
            selected.extend(opc.relationships.iter().filter(|relationship| {
                relationship.source_part == source_part
                    && relationship.relationship_type == *source_type
                    && relationship.relationship_type != OPC_SIGNATURE_ORIGIN_REL_TYPE
                    && relationship.relationship_type != OPC_SIGNATURE_REL_TYPE
            }));
        }
    }
    if selected.is_empty() {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_TRANSFORM_UNSUPPORTED",
            rels_path,
            "relationship transform selected no supported relationships",
        ));
        return None;
    }
    selected.sort_by(|left, right| left.relationship_id.cmp(&right.relationship_id));
    selected.dedup_by(|left, right| left.relationship_id == right.relationship_id);
    let mut xml = String::from(
        r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for relationship in selected {
        xml.push_str("<Relationship");
        xml.push_str(&format!(
            r#" Id="{}" Type="{}" Target="{}""#,
            escape_xml_attr(&relationship.relationship_id),
            escape_xml_attr(&relationship.relationship_type),
            escape_xml_attr(&relationship.target)
        ));
        if relationship.target_mode == TargetMode::External {
            xml.push_str(r#" TargetMode="External""#);
        }
        xml.push_str("/>");
    }
    xml.push_str("</Relationships>");
    Some(xml.into_bytes())
}

fn content_type_transform_bytes(opc: &OpcPackageProjection) -> Vec<u8> {
    let mut xml = String::from(
        r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">"#,
    );
    let mut defaults = opc.content_types.defaults.clone();
    defaults.sort_by(|left, right| left.extension.cmp(&right.extension));
    for default in defaults {
        xml.push_str(&format!(
            r#"<Default Extension="{}" ContentType="{}"/>"#,
            escape_xml_attr(&default.extension),
            escape_xml_attr(&default.content_type)
        ));
    }
    let mut overrides = opc.content_types.overrides.clone();
    overrides.sort_by(|left, right| left.part_name.cmp(&right.part_name));
    for override_entry in overrides {
        xml.push_str(&format!(
            r#"<Override PartName="/{}" ContentType="{}"/>"#,
            escape_xml_attr(&override_entry.part_name),
            escape_xml_attr(&override_entry.content_type)
        ));
    }
    xml.push_str("</Types>");
    xml.into_bytes()
}

fn verify_signature_value(
    signature_method: &str,
    signed_info_bytes: &[u8],
    signature_value: &str,
    key_info: &SignatureKeyInfoProjection,
    signature_part_path: &str,
    diagnostics: &mut Vec<SignatureDiagnostic>,
) -> SignatureValueVerificationResult {
    if signed_info_bytes.is_empty() {
        return SignatureValueVerificationResult::status(SignatureVerificationStatus::Malformed);
    }
    if signature_digest_for_method(signature_method).is_none() {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_METHOD_UNSUPPORTED",
            signature_part_path,
            "SignatureMethod is unsupported",
        ));
        return SignatureValueVerificationResult::status(
            SignatureVerificationStatus::UnsupportedAlgorithm,
        );
    }
    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(
        signature_value
            .split_whitespace()
            .collect::<String>()
            .as_bytes(),
    ) {
        Ok(bytes) => bytes,
        Err(_) => {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_VALUE_MISMATCH",
                signature_part_path,
                "SignatureValue is not valid base64",
            ));
            return SignatureValueVerificationResult::status(SignatureVerificationStatus::Invalid);
        }
    };
    let candidates =
        public_key_candidates_from_key_info(key_info, diagnostics, signature_part_path);
    if candidates.is_empty() {
        if diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "CVN_SIGNATURE_CERTIFICATE_KEY_ALGORITHM_UNSUPPORTED"
        }) {
            return SignatureValueVerificationResult::status(
                SignatureVerificationStatus::UnsupportedAlgorithm,
            );
        }
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_KEY_MISSING",
            signature_part_path,
            "no supported RSA public key is available",
        ));
        return SignatureValueVerificationResult::status(SignatureVerificationStatus::MissingKey);
    };
    let Ok(signature) = RsaPkcs1v15Signature::try_from(signature_bytes.as_slice()) else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_VALUE_MISMATCH",
            signature_part_path,
            "SignatureValue length is invalid for RSA",
        ));
        return SignatureValueVerificationResult::status(SignatureVerificationStatus::Invalid);
    };
    let mut last_fingerprint = None;
    for candidate in candidates {
        last_fingerprint = Some(candidate.fingerprint.clone());
        let verified = match signature_method {
            RSA_SHA1 => VerifyingKey::<Sha1>::new(candidate.public_key)
                .verify(signed_info_bytes, &signature),
            RSA_SHA256 => VerifyingKey::<Sha256>::new(candidate.public_key)
                .verify(signed_info_bytes, &signature),
            RSA_SHA384 => VerifyingKey::<Sha384>::new(candidate.public_key)
                .verify(signed_info_bytes, &signature),
            RSA_SHA512 => VerifyingKey::<Sha512>::new(candidate.public_key)
                .verify(signed_info_bytes, &signature),
            _ => unreachable!("checked earlier"),
        };
        if verified.is_ok() {
            return SignatureValueVerificationResult {
                status: SignatureVerificationStatus::Valid,
                key_source: Some(candidate.source),
                certificate_index: candidate.certificate_index,
                fingerprint: Some(candidate.fingerprint),
            };
        }
    }
    diagnostics.push(signature_diag(
        "CVN_SIGNATURE_VALUE_MISMATCH",
        signature_part_path,
        "SignatureValue does not verify against any KeyInfo public key candidate",
    ));
    diagnostics.push(signature_diag(
        "CVN_SIGNATURE_KEY_CANDIDATES_EXHAUSTED",
        signature_part_path,
        "all supported KeyInfo public key candidates were tried",
    ));
    SignatureValueVerificationResult {
        status: SignatureVerificationStatus::Invalid,
        key_source: None,
        certificate_index: None,
        fingerprint: last_fingerprint,
    }
}

struct SignatureValueVerificationResult {
    status: SignatureVerificationStatus,
    key_source: Option<SignatureKeySource>,
    certificate_index: Option<usize>,
    fingerprint: Option<String>,
}

impl SignatureValueVerificationResult {
    fn status(status: SignatureVerificationStatus) -> Self {
        Self {
            status,
            key_source: None,
            certificate_index: None,
            fingerprint: None,
        }
    }
}

struct PublicKeyCandidate {
    public_key: RsaPublicKey,
    fingerprint: String,
    source: SignatureKeySource,
    certificate_index: Option<usize>,
}

fn public_key_candidates_from_key_info(
    key_info: &SignatureKeyInfoProjection,
    diagnostics: &mut Vec<SignatureDiagnostic>,
    signature_part_path: &str,
) -> Vec<PublicKeyCandidate> {
    let mut candidates = Vec::new();
    let mut seen_fingerprints = BTreeSet::new();
    if let Some(key_value) = &key_info.key_value_rsa {
        if let Some(key) = rsa_public_key_from_projection(key_value) {
            if seen_fingerprints.insert(key_value.fingerprint.clone()) {
                candidates.push(PublicKeyCandidate {
                    public_key: key,
                    fingerprint: key_value.fingerprint.clone(),
                    source: SignatureKeySource::RsaKeyValue,
                    certificate_index: None,
                });
            }
        } else {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_CERTIFICATE_RSA_KEY_MALFORMED",
                signature_part_path,
                "RSAKeyValue public key is malformed",
            ));
        }
    }
    for (index, certificate) in key_info.x509_certificates.iter().enumerate() {
        if certificate.malformed {
            continue;
        }
        let Some(key_value) = certificate.rsa_public_key.as_ref() else {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_CERTIFICATE_PUBLIC_KEY_MISSING",
                signature_part_path,
                "X.509 certificate has no supported RSA public key candidate",
            ));
            continue;
        };
        let Some(key) = rsa_public_key_from_projection(key_value) else {
            diagnostics.push(signature_diag(
                "CVN_SIGNATURE_CERTIFICATE_RSA_KEY_MALFORMED",
                signature_part_path,
                "X.509 RSA public key projection is malformed",
            ));
            continue;
        };
        if seen_fingerprints.insert(key_value.fingerprint.clone()) {
            candidates.push(PublicKeyCandidate {
                public_key: key,
                fingerprint: key_value.fingerprint.clone(),
                source: SignatureKeySource::X509Certificate,
                certificate_index: Some(index),
            });
        }
    }
    candidates
}

fn rsa_public_key_from_projection(key_value: &RsaKeyValueProjection) -> Option<RsaPublicKey> {
    let modulus = base64::engine::general_purpose::STANDARD
        .decode(
            key_value
                .modulus_b64
                .split_whitespace()
                .collect::<String>()
                .as_bytes(),
        )
        .ok()?;
    let exponent = base64::engine::general_purpose::STANDARD
        .decode(
            key_value
                .exponent_b64
                .split_whitespace()
                .collect::<String>()
                .as_bytes(),
        )
        .ok()?;
    RsaPublicKey::new(
        BigUint::from_bytes_be(&modulus),
        BigUint::from_bytes_be(&exponent),
    )
    .ok()
}

fn signed_info_canonical_bytes(
    signature_bytes: &[u8],
    signed_info: &SignedInfoProjection,
) -> Result<Vec<u8>, &'static str> {
    if !is_supported_canonicalization(&signed_info.canonicalization_method) {
        return Err("CVN_SIGNATURE_CANONICALIZATION_UNSUPPORTED");
    }
    let xml = String::from_utf8_lossy(signature_bytes);
    let Some(start) = xml
        .find("<ds:SignedInfo")
        .or_else(|| xml.find("<SignedInfo"))
    else {
        return Err("CVN_SIGNATURE_XML_MALFORMED");
    };
    let Some(relative_end) = xml[start..]
        .find("</ds:SignedInfo>")
        .or_else(|| xml[start..].find("</SignedInfo>"))
    else {
        return Err("CVN_SIGNATURE_XML_MALFORMED");
    };
    let end_tag = if xml[start + relative_end..].starts_with("</ds:SignedInfo>") {
        "</ds:SignedInfo>"
    } else {
        "</SignedInfo>"
    };
    let end = start + relative_end + end_tag.len();
    Ok(xml[start..end].as_bytes().to_vec())
}

fn digest_bytes_for_method(method: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    match method {
        SHA1_DIGEST => Some(Sha1::digest(bytes).to_vec()),
        SHA256_DIGEST => Some(Sha256::digest(bytes).to_vec()),
        SHA384_DIGEST => Some(Sha384::digest(bytes).to_vec()),
        SHA512_DIGEST => Some(Sha512::digest(bytes).to_vec()),
        _ => None,
    }
}

fn signature_digest_for_method(method: &str) -> Option<&'static str> {
    match method {
        RSA_SHA1 => Some(SHA1_DIGEST),
        RSA_SHA256 => Some(SHA256_DIGEST),
        RSA_SHA384 => Some(SHA384_DIGEST),
        RSA_SHA512 => Some(SHA512_DIGEST),
        _ => None,
    }
}

fn is_supported_canonicalization(method: &str) -> bool {
    matches!(method, C14N_10 | C14N_10_COMMENTS | EXCLUSIVE_C14N_10)
}

fn combine_signature_status(
    current: SignatureVerificationStatus,
    next: SignatureVerificationStatus,
) -> SignatureVerificationStatus {
    use SignatureVerificationStatus::{
        Invalid, Malformed, MissingKey, UnsupportedAlgorithm, UnsupportedTransform, Valid,
    };
    match (current, next) {
        (Invalid, _) | (_, Invalid) => Invalid,
        (UnsupportedAlgorithm, _) | (_, UnsupportedAlgorithm) => UnsupportedAlgorithm,
        (UnsupportedTransform, _) | (_, UnsupportedTransform) => UnsupportedTransform,
        (MissingKey, _) | (_, MissingKey) => MissingKey,
        (Malformed, _) | (_, Malformed) => Malformed,
        (Valid, status) => status,
        (status, Valid) => status,
        (status, _) => status,
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn part_path_from_reference(signature_part_path: &str, uri: &str) -> Option<String> {
    let path = uri.strip_prefix('/').unwrap_or(uri);
    if path.is_empty() {
        return None;
    }
    if path.contains("://") || path.split('/').any(|segment| segment == "..") {
        return None;
    }
    if uri.starts_with('/') {
        return Some(path.to_owned());
    }
    let base = signature_part_path
        .rsplit_once('/')
        .map(|(base, _)| base)
        .unwrap_or("");
    normalize_relative_part_path(base, path)
}

fn resolve_relationship_target(source_part: Option<&str>, target: &str) -> Option<String> {
    let target = target.strip_prefix('/').unwrap_or(target);
    if target.contains("://") || target.split('/').any(|segment| segment == "..") {
        return None;
    }
    if target.starts_with('/') {
        return Some(target.trim_start_matches('/').to_owned());
    }
    let base = source_part
        .and_then(|part| part.rsplit_once('/').map(|(base, _)| base))
        .unwrap_or("");
    normalize_relative_part_path(base, target)
}

fn normalize_relative_part_path(base: &str, target: &str) -> Option<String> {
    let mut segments = Vec::new();
    if !base.is_empty() {
        segments.extend(
            base.split('/')
                .filter(|segment| !segment.is_empty())
                .map(str::to_owned),
        );
    }
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            value => segments.push(percent_decode_unreserved(value)?),
        }
    }
    Some(segments.join("/"))
}

fn percent_decode_unreserved(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            let byte = u8::from_str_radix(hex, 16).ok()?;
            output.push(byte);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn same_document_object(signature_bytes: &[u8], fragment: &str) -> Option<String> {
    let xml = String::from_utf8_lossy(signature_bytes);
    let needle = format!(r#"Id="{fragment}""#);
    let id_pos = xml.find(&needle)?;
    let start = xml[..id_pos].rfind('<')?;
    let name_end = xml[start + 1..]
        .find(|ch: char| ch.is_whitespace() || ch == '>')
        .map(|offset| start + 1 + offset)?;
    let raw_name = &xml[start + 1..name_end];
    let end_tag = format!("</{raw_name}>");
    let relative_end = xml[name_end..].find(&end_tag)?;
    let end = name_end + relative_end + end_tag.len();
    Some(xml[start..end].to_owned())
}

fn read_text_until(
    reader: &mut Reader<Cursor<&[u8]>>,
    local_name: &str,
    source_part_path: &str,
) -> Result<String, DocxImportError> {
    let mut buffer = Vec::new();
    let mut text = String::new();
    let mut depth = 0_usize;
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(_) => depth += 1,
            Event::Text(event) => text.push_str(&String::from_utf8_lossy(event.as_ref())),
            Event::CData(event) => text.push_str(&String::from_utf8_lossy(event.as_ref())),
            Event::End(event) => {
                let raw = String::from_utf8_lossy(event.name().as_ref()).into_owned();
                let local = raw.rsplit(':').next().unwrap_or(raw.as_str());
                if depth == 0 && local == local_name {
                    break;
                }
                depth = depth.saturating_sub(1);
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(text)
}

fn read_element_xml(
    event: &BytesStart<'_>,
    reader: &mut Reader<Cursor<&[u8]>>,
    _source_part_path: &str,
) -> Result<String, DocxImportError> {
    let raw_name = String::from_utf8_lossy(event.name().as_ref()).into_owned();
    Ok(format!(
        "{}{}{}",
        start_event_xml(event)?,
        read_branch_xml(reader, raw_name.rsplit(':').next().unwrap_or(&raw_name))?,
        format!("</{raw_name}>")
    ))
}

fn read_element_xml_with_scope(
    event: &BytesStart<'_>,
    scope: &BTreeMap<String, String>,
    reader: &mut Reader<Cursor<&[u8]>>,
    _source_part_path: &str,
) -> Result<String, DocxImportError> {
    let raw_name = String::from_utf8_lossy(event.name().as_ref()).into_owned();
    Ok(format!(
        "{}{}{}",
        start_event_xml_with_scope(event, scope)?,
        read_branch_xml(reader, raw_name.rsplit(':').next().unwrap_or(&raw_name))?,
        format!("</{raw_name}>")
    ))
}

fn parse_xml_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" | "t" | "on" => Some(true),
        "0" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

fn parse_xml_i64(value: &str) -> Option<i64> {
    value.parse::<i64>().ok()
}

fn drawing_diag(code: &str, path: &str, message: impl Into<String>) -> DrawingResolutionDiagnostic {
    DrawingResolutionDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.into(),
    }
}

fn ensure_drawing_geometry(projection: &mut DrawingProjection) -> &mut DrawingGeometryProjection {
    projection
        .geometry
        .get_or_insert(DrawingGeometryProjection {
            extent: None,
            offset: None,
            transform: None,
            crop: None,
        })
}

fn ensure_drawing_transform(projection: &mut DrawingProjection) -> &mut DrawingTransformProjection {
    ensure_drawing_geometry(projection)
        .transform
        .get_or_insert(DrawingTransformProjection {
            rotation: None,
            flip_h: false,
            flip_v: false,
            offset: None,
            extent: None,
        })
}

fn parse_vml_style(
    style: &str,
    path: &str,
    diagnostics: &mut Vec<DrawingResolutionDiagnostic>,
) -> BTreeMap<String, String> {
    let mut properties = BTreeMap::new();
    for token in style.split(';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let Some((key, value)) = token.split_once(':') else {
            diagnostics.push(drawing_diag(
                "CVN_DRAWING_VML_STYLE_INVALID",
                path,
                format!("invalid VML style token `{token}`"),
            ));
            continue;
        };
        properties.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    properties
}

fn parse_i64_attr_or_diag(
    attrs: &BTreeMap<String, String>,
    keys: &[&str],
    path: &str,
    name: &str,
    diagnostics: &mut Vec<DrawingResolutionDiagnostic>,
) -> Option<i64> {
    let value = keys
        .iter()
        .find_map(|key| attrs.get(*key).or_else(|| attr_named(attrs, key)));
    match value {
        Some(value) => match parse_xml_i64(value) {
            Some(parsed) => Some(parsed),
            None => {
                diagnostics.push(drawing_diag(
                    "CVN_DRAWING_GEOMETRY_INVALID",
                    path,
                    format!("invalid integer `{value}` for `{name}`"),
                ));
                None
            }
        },
        None => None,
    }
}

fn append_visual_inline(
    document_id: &DocumentId,
    source_part_path: &str,
    document_digest: &str,
    container_kind: VisualInlineContainerKind,
    anchor: SourceAnchor,
    raw_xml: &str,
    id_set: &mut BTreeSet<String>,
    paragraph_stack: &mut [ParagraphBuilder],
    run_stack: &mut [RunBuilder],
    active_change: &mut Option<TrackedChangeBuilder>,
    hyperlink_stack: &mut [HyperlinkBuilder],
    field_stack: &mut [FieldBuilder],
) -> Result<(), DocxImportError> {
    let mut drawing = parse_drawing_projection(
        document_id,
        source_part_path,
        document_digest,
        anchor,
        raw_xml,
        id_set,
    )?;
    if container_kind == VisualInlineContainerKind::Drawing {
        if let Some(object) = parse_embedded_visual_object_projection(
            document_id,
            source_part_path,
            document_digest,
            drawing.source_anchor.clone(),
            raw_xml,
            id_set,
        )? {
            if matches!(
                object.kind,
                EmbeddedVisualObjectKind::Chart | EmbeddedVisualObjectKind::SmartartDiagram
            ) {
                drawing.embedded_visual_objects.push(object);
            }
        }
    }
    append_inline(
        paragraph_stack,
        run_stack,
        active_change,
        hyperlink_stack,
        field_stack,
        SemanticInline::Drawing(drawing),
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisualInlineContainerKind {
    Drawing,
    Pict,
}

fn parse_embedded_visual_object_projection(
    document_id: &DocumentId,
    source_part_path: &str,
    document_digest: &str,
    anchor: SourceAnchor,
    raw_xml: &str,
    id_set: &mut BTreeSet<String>,
) -> Result<Option<EmbeddedVisualObjectProjection>, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(raw_xml.as_bytes()));
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let id = semantic_id(
        document_id,
        source_part_path,
        "embedded-visual-object",
        None,
        &anchor.xml_path,
        document_digest,
        id_set,
    )?;
    let mut projection = EmbeddedVisualObjectProjection {
        id,
        source_anchor: anchor,
        kind: EmbeddedVisualObjectKind::Unresolved,
        graphic_data_uri: None,
        chart: None,
        diagram: None,
        ole: None,
        package_resource: None,
        targets: Vec::new(),
        preview_image_relationship_id: None,
        preview_image: None,
        risk_class: None,
        diagnostics: Vec::new(),
    };
    let mut saw_object = false;

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) | Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                match name.local_name.as_str() {
                    "graphicData" => {
                        projection.graphic_data_uri = attrs.get("uri").cloned();
                        match projection.graphic_data_uri.as_deref() {
                            Some(DRAWINGML_CHART_NAMESPACE) => {
                                projection.kind = EmbeddedVisualObjectKind::Chart;
                                saw_object = true;
                            }
                            Some(DRAWINGML_DIAGRAM_NAMESPACE) => {
                                projection.kind = EmbeddedVisualObjectKind::SmartartDiagram;
                                saw_object = true;
                            }
                            _ => {}
                        }
                    }
                    "chart" => {
                        if projection.kind == EmbeddedVisualObjectKind::Chart {
                            saw_object = true;
                            if let Some(relationship_id) = attrs
                                .get("r:id")
                                .cloned()
                                .or_else(|| attrs.get("id").cloned())
                            {
                                projection.targets.push(EmbeddedObjectTarget {
                                    kind: EmbeddedObjectTargetKind::InternalPart,
                                    role: Some("chart_part".to_owned()),
                                    relationship_id: Some(relationship_id),
                                    relationship_type: None,
                                    target_mode: None,
                                    raw_target: None,
                                    resolved_part_path: None,
                                    resource: None,
                                    risk_class: None,
                                });
                            }
                        }
                    }
                    "relIds" => {
                        projection.kind = EmbeddedVisualObjectKind::SmartartDiagram;
                        saw_object = true;
                        for (attribute_name, role) in [
                            ("r:dm", "diagram_data"),
                            ("r:lo", "diagram_layout"),
                            ("r:qs", "diagram_style"),
                            ("r:cs", "diagram_colors"),
                        ] {
                            if let Some(relationship_id) =
                                attrs.get(attribute_name).cloned().or_else(|| {
                                    attribute_name
                                        .split_once(':')
                                        .and_then(|(_, local)| attrs.get(local).cloned())
                                })
                            {
                                projection.targets.push(EmbeddedObjectTarget {
                                    kind: EmbeddedObjectTargetKind::InternalPart,
                                    role: Some(role.to_owned()),
                                    relationship_id: Some(relationship_id),
                                    relationship_type: None,
                                    target_mode: None,
                                    raw_target: None,
                                    resolved_part_path: None,
                                    resource: None,
                                    risk_class: None,
                                });
                            }
                        }
                    }
                    "OLEObject" => {
                        saw_object = true;
                        let metadata = OleMetadataProjection {
                            object_type: attrs.get("Type").cloned(),
                            prog_id: attrs.get("ProgID").cloned(),
                            shape_id: attrs
                                .get("ShapeID")
                                .cloned()
                                .or_else(|| attrs.get("ShapeID").cloned()),
                            draw_aspect: attrs.get("DrawAspect").cloned(),
                            object_id: attrs.get("ObjectID").cloned(),
                            update_mode: attrs.get("UpdateMode").cloned(),
                            raw_attributes: attrs.clone(),
                        };
                        let object_kind = if metadata
                            .prog_id
                            .as_deref()
                            .map(|value| value.eq_ignore_ascii_case("Package"))
                            .unwrap_or(false)
                        {
                            EmbeddedVisualObjectKind::EmbeddedPackage
                        } else if metadata
                            .prog_id
                            .as_deref()
                            .map(|value| value.to_ascii_lowercase().contains("forms."))
                            .unwrap_or(false)
                        {
                            EmbeddedVisualObjectKind::ActivexBlocked
                        } else if metadata.object_type.as_deref() == Some("Link") {
                            EmbeddedVisualObjectKind::OleLinkedObject
                        } else {
                            EmbeddedVisualObjectKind::OleEmbeddedObject
                        };
                        if object_kind == EmbeddedVisualObjectKind::ActivexBlocked {
                            projection.diagnostics.push(embedded_object_diag(
                                "CVN_EMBEDDED_OBJECT_ACTIVEX_BLOCKED",
                                &projection.source_anchor.xml_path,
                                "ActiveX content is preserved but blocked",
                            ));
                        }
                        if let Some(relationship_id) = attrs
                            .get("r:id")
                            .cloned()
                            .or_else(|| attrs.get("id").cloned())
                        {
                            projection.targets.push(EmbeddedObjectTarget {
                                kind: EmbeddedObjectTargetKind::Unresolved,
                                role: Some("object".to_owned()),
                                relationship_id: Some(relationship_id),
                                relationship_type: None,
                                target_mode: None,
                                raw_target: None,
                                resolved_part_path: None,
                                resource: None,
                                risk_class: None,
                            });
                        }
                        projection.risk_class = Some(match object_kind {
                            EmbeddedVisualObjectKind::EmbeddedPackage => {
                                "embedded_office_package".to_owned()
                            }
                            EmbeddedVisualObjectKind::OleLinkedObject => {
                                "linked_external_object".to_owned()
                            }
                            EmbeddedVisualObjectKind::ActivexBlocked => "activex".to_owned(),
                            _ => "embedded_binary_object".to_owned(),
                        });
                        projection.ole = Some(OleObjectProjection { metadata });
                        projection.kind = object_kind;
                    }
                    "imagedata" => {
                        projection.preview_image_relationship_id = attrs
                            .get("r:id")
                            .cloned()
                            .or_else(|| attrs.get("id").cloned());
                    }
                    "control" => {
                        saw_object = true;
                        projection.kind = EmbeddedVisualObjectKind::ActivexBlocked;
                        projection.risk_class = Some("activex".to_owned());
                        projection.diagnostics.push(embedded_object_diag(
                            "CVN_EMBEDDED_OBJECT_ACTIVEX_BLOCKED",
                            &projection.source_anchor.xml_path,
                            "ActiveX control is preserved but blocked",
                        ));
                    }
                    _ => {}
                }
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    if !saw_object {
        return Ok(None);
    }
    if projection.kind == EmbeddedVisualObjectKind::Unresolved {
        projection.kind = EmbeddedVisualObjectKind::UnsupportedVisualObject;
        projection.diagnostics.push(embedded_object_diag(
            "CVN_EMBEDDED_OBJECT_UNSUPPORTED",
            &projection.source_anchor.xml_path,
            "visual object is preserved but not semantically projected further",
        ));
    }
    Ok(Some(projection))
}

fn embedded_object_diag(
    code: &str,
    path: &str,
    message: impl Into<String>,
) -> EmbeddedVisualObjectDiagnostic {
    EmbeddedVisualObjectDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.into(),
    }
}

fn parse_drawing_projection(
    document_id: &DocumentId,
    source_part_path: &str,
    document_digest: &str,
    anchor: SourceAnchor,
    raw_xml: &str,
    id_set: &mut BTreeSet<String>,
) -> Result<DrawingProjection, DocxImportError> {
    let id = semantic_id(
        document_id,
        source_part_path,
        "drawing",
        None,
        &anchor.xml_path,
        document_digest,
        id_set,
    )?;
    let mut projection = DrawingProjection {
        id,
        source_anchor: anchor.clone(),
        kind: DrawingKind::Unresolved,
        placement: DrawingPlacement::Unsupported,
        graphic_data_uri: None,
        metadata: None,
        geometry: None,
        targets: Vec::new(),
        vml_shape_id: None,
        vml_shape_type: None,
        vml_style_raw: None,
        vml_style_properties: BTreeMap::new(),
        embedded_visual_objects: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut reader = Reader::from_reader(Cursor::new(raw_xml.as_bytes()));
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut axis_stack: Vec<&'static str> = Vec::new();
    let mut position_text_target: Option<(&'static str, &'static str)> = None;
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                parse_drawing_event(
                    &name,
                    &attrs,
                    &mut projection,
                    &mut axis_stack,
                    &mut position_text_target,
                );
            }
            Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                parse_drawing_event(
                    &name,
                    &attrs,
                    &mut projection,
                    &mut axis_stack,
                    &mut position_text_target,
                );
                namespace_stack.pop();
            }
            Event::Text(text) => {
                if let Some((axis, target)) = position_text_target {
                    let value = String::from_utf8_lossy(text.as_ref()).into_owned();
                    if let DrawingPlacement::Anchor {
                        position_h,
                        position_v,
                        ..
                    } = &mut projection.placement
                    {
                        let slot = if axis == "h" { position_h } else { position_v };
                        if let Some(position) = slot.as_mut() {
                            if target == "align" {
                                position.align = Some(value);
                            } else {
                                match parse_xml_i64(&value) {
                                    Some(offset) => position.pos_offset = Some(offset),
                                    None => projection.diagnostics.push(drawing_diag(
                                        "CVN_DRAWING_GEOMETRY_INVALID",
                                        &projection.source_anchor.xml_path,
                                        format!("invalid position offset `{value}`"),
                                    )),
                                }
                            }
                        }
                    }
                }
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if matches!(name.local_name.as_str(), "positionH" | "positionV") {
                    axis_stack.pop();
                }
                if matches!(name.local_name.as_str(), "align" | "posOffset") {
                    position_text_target = None;
                }
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if projection.kind == DrawingKind::Unresolved {
        projection.kind = if raw_xml.contains(":imagedata") {
            DrawingKind::VmlImage
        } else {
            DrawingKind::UnsupportedGraphic
        };
    }
    Ok(projection)
}

fn parse_drawing_event(
    name: &XmlName,
    attrs: &BTreeMap<String, String>,
    projection: &mut DrawingProjection,
    axis_stack: &mut Vec<&'static str>,
    position_text_target: &mut Option<(&'static str, &'static str)>,
) {
    match (name.namespace_uri.as_deref(), name.local_name.as_str()) {
        (Some(WP_NAMESPACE), "inline") => {
            projection.kind = DrawingKind::DrawingmlInlineImage;
            projection.placement = DrawingPlacement::Inline;
        }
        (Some(WP_NAMESPACE), "anchor") => {
            projection.kind = DrawingKind::DrawingmlAnchoredImage;
            projection.placement = DrawingPlacement::Anchor {
                simple_pos: attrs
                    .get("simplePos")
                    .and_then(|value| parse_xml_bool(value)),
                relative_height: attrs.get("relativeHeight").cloned(),
                behind_doc: attrs
                    .get("behindDoc")
                    .and_then(|value| parse_xml_bool(value)),
                locked: attrs.get("locked").and_then(|value| parse_xml_bool(value)),
                layout_in_cell: attrs
                    .get("layoutInCell")
                    .and_then(|value| parse_xml_bool(value)),
                allow_overlap: attrs
                    .get("allowOverlap")
                    .and_then(|value| parse_xml_bool(value)),
                dist_t: attrs.get("distT").cloned(),
                dist_b: attrs.get("distB").cloned(),
                dist_l: attrs.get("distL").cloned(),
                dist_r: attrs.get("distR").cloned(),
                position_h: None,
                position_v: None,
                wrap: None,
            };
        }
        (Some(WP_NAMESPACE), "extent") => {
            let path = projection.source_anchor.xml_path.clone();
            let cx =
                parse_i64_attr_or_diag(attrs, &["cx"], &path, "cx", &mut projection.diagnostics);
            let cy =
                parse_i64_attr_or_diag(attrs, &["cy"], &path, "cy", &mut projection.diagnostics);
            let geometry = ensure_drawing_geometry(projection);
            geometry.extent = Some(DrawingExtentProjection { cx, cy });
        }
        (Some(WP_NAMESPACE), "docPr") => {
            projection.metadata = Some(DrawingMetadataProjection {
                doc_pr_id: attrs.get("id").cloned(),
                name: attrs.get("name").cloned(),
                description: attrs.get("descr").cloned(),
                title: attrs.get("title").cloned(),
                hidden: attrs.get("hidden").and_then(|value| parse_xml_bool(value)),
                raw_attributes: attrs.clone(),
                vml_title: None,
            });
        }
        (Some(WP_NAMESPACE), "positionH") => {
            axis_stack.push("h");
            if let DrawingPlacement::Anchor { position_h, .. } = &mut projection.placement {
                *position_h = Some(DrawingPositionProjection {
                    relative_from: attrs.get("relativeFrom").cloned(),
                    align: None,
                    pos_offset: None,
                });
            }
        }
        (Some(WP_NAMESPACE), "positionV") => {
            axis_stack.push("v");
            if let DrawingPlacement::Anchor { position_v, .. } = &mut projection.placement {
                *position_v = Some(DrawingPositionProjection {
                    relative_from: attrs.get("relativeFrom").cloned(),
                    align: None,
                    pos_offset: None,
                });
            }
        }
        (Some(WP_NAMESPACE), "align") => {
            if let Some(axis) = axis_stack.last().copied() {
                *position_text_target = Some((axis, "align"));
            }
        }
        (Some(WP_NAMESPACE), "posOffset") => {
            if let Some(axis) = axis_stack.last().copied() {
                *position_text_target = Some((axis, "offset"));
            }
        }
        (
            Some(WP_NAMESPACE),
            "wrapNone" | "wrapSquare" | "wrapTight" | "wrapThrough" | "wrapTopAndBottom",
        ) => {
            if let DrawingPlacement::Anchor { wrap, .. } = &mut projection.placement {
                *wrap = Some(DrawingWrapProjection {
                    kind: name.local_name.clone(),
                    dist_t: attrs.get("distT").cloned(),
                    dist_b: attrs.get("distB").cloned(),
                    dist_l: attrs.get("distL").cloned(),
                    dist_r: attrs.get("distR").cloned(),
                    raw_polygon_xml: None,
                });
            }
        }
        (Some(DRAWINGML_MAIN_NAMESPACE), "graphicData") => {
            projection.graphic_data_uri = attrs.get("uri").cloned();
            if projection.graphic_data_uri.as_deref() != Some(DRAWINGML_PICTURE_NAMESPACE) {
                projection.kind = DrawingKind::UnsupportedGraphic;
                projection.diagnostics.push(drawing_diag(
                    "CVN_DRAWING_GRAPHIC_DATA_UNSUPPORTED",
                    &projection.source_anchor.xml_path,
                    format!(
                        "graphicData uri `{}` is not projected as an image",
                        projection
                            .graphic_data_uri
                            .as_deref()
                            .unwrap_or("<missing>")
                    ),
                ));
            }
        }
        (Some(DRAWINGML_MAIN_NAMESPACE), "blip") => {
            if let Some(relationship_id) = attrs.get("r:embed").cloned() {
                projection.targets.push(DrawingTarget {
                    kind: DrawingTargetKind::EmbeddedPart,
                    relationship_id: Some(relationship_id),
                    relationship_type: None,
                    target_mode: None,
                    raw_target: None,
                    resolved_part_path: None,
                    resource: None,
                    risk_class: None,
                });
            }
            if let Some(relationship_id) = attrs.get("r:link").cloned() {
                projection.targets.push(DrawingTarget {
                    kind: DrawingTargetKind::Unresolved,
                    relationship_id: Some(relationship_id),
                    relationship_type: None,
                    target_mode: None,
                    raw_target: None,
                    resolved_part_path: None,
                    resource: None,
                    risk_class: None,
                });
            }
        }
        (Some(DRAWINGML_MAIN_NAMESPACE), "srcRect") => {
            let path = projection.source_anchor.xml_path.clone();
            let left =
                parse_i64_attr_or_diag(attrs, &["l"], &path, "l", &mut projection.diagnostics);
            let top =
                parse_i64_attr_or_diag(attrs, &["t"], &path, "t", &mut projection.diagnostics);
            let right =
                parse_i64_attr_or_diag(attrs, &["r"], &path, "r", &mut projection.diagnostics);
            let bottom =
                parse_i64_attr_or_diag(attrs, &["b"], &path, "b", &mut projection.diagnostics);
            let geometry = ensure_drawing_geometry(projection);
            geometry.crop = Some(DrawingCropProjection {
                left,
                top,
                right,
                bottom,
            });
        }
        (Some(DRAWINGML_MAIN_NAMESPACE), "xfrm") => {
            let path = projection.source_anchor.xml_path.clone();
            let rotation =
                parse_i64_attr_or_diag(attrs, &["rot"], &path, "rot", &mut projection.diagnostics);
            let transform = ensure_drawing_transform(projection);
            transform.rotation = rotation;
            transform.flip_h = attrs
                .get("flipH")
                .and_then(|value| parse_xml_bool(value))
                .unwrap_or(false);
            transform.flip_v = attrs
                .get("flipV")
                .and_then(|value| parse_xml_bool(value))
                .unwrap_or(false);
        }
        (Some(DRAWINGML_MAIN_NAMESPACE), "off") => {
            let path = projection.source_anchor.xml_path.clone();
            let x = parse_i64_attr_or_diag(attrs, &["x"], &path, "x", &mut projection.diagnostics);
            let y = parse_i64_attr_or_diag(attrs, &["y"], &path, "y", &mut projection.diagnostics);
            let transform = ensure_drawing_transform(projection);
            transform.offset = Some(DrawingOffsetProjection { x, y });
            ensure_drawing_geometry(projection).offset = transform.offset.clone();
        }
        (Some(DRAWINGML_MAIN_NAMESPACE), "ext") => {
            let path = projection.source_anchor.xml_path.clone();
            let cx =
                parse_i64_attr_or_diag(attrs, &["cx"], &path, "cx", &mut projection.diagnostics);
            let cy =
                parse_i64_attr_or_diag(attrs, &["cy"], &path, "cy", &mut projection.diagnostics);
            let transform = ensure_drawing_transform(projection);
            transform.extent = Some(DrawingExtentProjection { cx, cy });
        }
        (Some(VML_NAMESPACE), "shape") => {
            projection.kind = DrawingKind::VmlImage;
            projection.placement = DrawingPlacement::Vml;
            projection.vml_shape_id = attrs.get("id").cloned();
            projection.vml_shape_type = attrs.get("type").cloned();
            projection.vml_style_raw = attrs.get("style").cloned();
            if let Some(style) = projection.vml_style_raw.as_ref() {
                projection.vml_style_properties = parse_vml_style(
                    style,
                    &projection.source_anchor.xml_path,
                    &mut projection.diagnostics,
                );
            }
        }
        (Some(VML_NAMESPACE), "imagedata") => {
            projection.kind = DrawingKind::VmlImage;
            if let Some(relationship_id) = attrs
                .get("r:id")
                .cloned()
                .or_else(|| attrs.get("id").cloned())
            {
                projection.targets.push(DrawingTarget {
                    kind: DrawingTargetKind::EmbeddedPart,
                    relationship_id: Some(relationship_id),
                    relationship_type: None,
                    target_mode: None,
                    raw_target: None,
                    resolved_part_path: None,
                    resource: None,
                    risk_class: None,
                });
            }
            let metadata = projection
                .metadata
                .get_or_insert(DrawingMetadataProjection {
                    doc_pr_id: None,
                    name: None,
                    description: None,
                    title: None,
                    hidden: None,
                    raw_attributes: BTreeMap::new(),
                    vml_title: None,
                });
            metadata.vml_title = attrs
                .get("o:title")
                .cloned()
                .or_else(|| attrs.get("title").cloned());
            metadata.raw_attributes.extend(attrs.clone());
        }
        (Some(OFFICE_NAMESPACE), "OLEObject" | "lock") | (Some(VML_NAMESPACE), "textbox") => {
            projection.kind = DrawingKind::UnsupportedGraphic;
            projection.diagnostics.push(drawing_diag(
                "CVN_DRAWING_ACTIVE_OBJECT_BLOCKED",
                &projection.source_anchor.xml_path,
                format!(
                    "active object `{}` is preserved but not executed",
                    name.local_name
                ),
            ));
        }
        _ => {}
    }
}

fn is_ds_event(
    event: &BytesStart<'_>,
    namespace_stack: &[BTreeMap<String, String>],
    local_name: &str,
) -> bool {
    let mut stack = namespace_stack.to_vec();
    if let Ok(declarations) = namespace_declarations(event) {
        stack.push(declarations);
    }
    let name = qname(event.name().as_ref(), &stack);
    name.namespace_uri.as_deref() == Some(DSIG_NAMESPACE) && name.local_name == local_name
}

fn dsig_scope() -> BTreeMap<String, String> {
    BTreeMap::from([("ds".to_owned(), DSIG_NAMESPACE.to_owned())])
}

fn escape_xml_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn signature_diag(code: &str, path: &str, message: &str) -> SignatureDiagnostic {
    SignatureDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

fn attributes(
    reader: &Reader<Cursor<&[u8]>>,
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<BTreeMap<String, String>, quick_xml::Error> {
    let mut attrs = BTreeMap::new();
    for attr in event.attributes() {
        let attr = attr?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = attr
            .decode_and_unescape_value(reader.decoder())?
            .into_owned();
        if let Some((_, local_name)) = key.split_once(':') {
            attrs.entry(local_name.to_owned()).or_insert(value.clone());
        }
        attrs.insert(key, value);
    }
    Ok(attrs)
}

fn namespace_declarations(
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<BTreeMap<String, String>, quick_xml::Error> {
    let mut declarations = BTreeMap::new();
    for attr in event.attributes() {
        let attr = attr?;
        let key = String::from_utf8_lossy(attr.key.as_ref());
        let value = attr.unescape_value()?.into_owned();
        if key == "xmlns" {
            declarations.insert(String::new(), value);
        } else if let Some(prefix) = key.strip_prefix("xmlns:") {
            declarations.insert(prefix.to_owned(), value);
        }
    }
    Ok(declarations)
}

fn relationship_source_part(rels_path: &str) -> Option<String> {
    if rels_path == "_rels/.rels" {
        return None;
    }

    let (prefix, file_name) = rels_path.rsplit_once("/_rels/")?;
    let part_name = file_name.strip_suffix(".rels")?;
    Some(format!("{prefix}/{part_name}"))
}

fn resolve_content_type(content_types: &ContentTypesProjection, path: &str) -> Option<String> {
    for override_entry in &content_types.overrides {
        if override_entry.part_name == path {
            return Some(override_entry.content_type.clone());
        }
    }

    let extension = path.rsplit_once('.')?.1;
    content_types
        .defaults
        .iter()
        .find(|default| default.extension == extension)
        .map(|default| default.content_type.clone())
}

fn build_mce_projection(
    document_id: &DocumentId,
    parts: &[RawPart],
    objects: &BTreeMap<String, Vec<u8>>,
) -> Result<MceProjection, DocxImportError> {
    let mut alternate_contents = Vec::new();
    let mut diagnostics = Vec::new();
    let mut id_set = BTreeSet::new();
    for part in parts
        .iter()
        .filter(|part| part.path == "word/document.xml" || is_story_xml_part(&part.path))
    {
        if let Some(bytes) = objects.get(&part.digest) {
            scan_mce_part(
                document_id,
                &part.path,
                bytes,
                &mut alternate_contents,
                &mut diagnostics,
                &mut id_set,
            )?;
        }
    }
    alternate_contents.sort_by(|left, right| {
        left.source_anchor
            .source_part_path
            .cmp(&right.source_anchor.source_part_path)
            .then(
                left.source_anchor
                    .xml_path
                    .cmp(&right.source_anchor.xml_path),
            )
    });
    diagnostics.sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    Ok(MceProjection {
        source_part: "docx-mce".to_owned(),
        capability_version: MCE_CAPABILITY_VERSION.to_owned(),
        capabilities: mce_capabilities(),
        alternate_contents,
        diagnostics,
    })
}

fn is_story_xml_part(path: &str) -> bool {
    path.starts_with("word/")
        && path.ends_with(".xml")
        && (path.contains("header")
            || path.contains("footer")
            || path.contains("footnote")
            || path.contains("endnote")
            || path.contains("comment"))
}

fn scan_mce_part(
    document_id: &DocumentId,
    source_part_path: &str,
    bytes: &[u8],
    alternate_contents: &mut Vec<MceAlternateContentProjection>,
    diagnostics: &mut Vec<MceResolutionDiagnostic>,
    id_set: &mut BTreeSet<String>,
) -> Result<(), DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let document_digest = sha256_hex(bytes);
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut path_stack: Vec<String> = Vec::new();
    let mut child_counts: Vec<BTreeMap<String, usize>> = vec![BTreeMap::new()];
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                if name.namespace_uri.as_deref() == Some(MC_NAMESPACE)
                    && name.local_name == "AlternateContent"
                {
                    let anchor = SourceAnchor {
                        source_part_path: source_part_path.to_owned(),
                        xml_path: path.clone(),
                        byte_start: Some(reader.buffer_position()),
                    };
                    let projection = read_alternate_content(
                        document_id,
                        source_part_path,
                        &document_digest,
                        anchor,
                        &attrs,
                        &namespace_context(&namespace_stack),
                        &mut reader,
                        diagnostics,
                        id_set,
                    )?;
                    alternate_contents.push(projection);
                    path_stack.pop();
                    child_counts.pop();
                    namespace_stack.pop();
                }
            }
            Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let _path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::End(_) => {
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(())
}

fn selected_branch_raw(projection: &MceAlternateContentProjection) -> Option<&str> {
    projection
        .branches
        .iter()
        .find(|branch| branch.selected)
        .map(|branch| branch.raw_content.as_str())
}

fn selected_branch_index(projection: &MceAlternateContentProjection) -> Option<usize> {
    projection
        .branches
        .iter()
        .position(|branch| branch.selected)
}

fn build_mce_selected_content(
    document_id: &DocumentId,
    source_part_path: &str,
    projection: MceAlternateContentProjection,
) -> Result<MceSelectedContent, DocxImportError> {
    let selected_raw = selected_branch_raw(&projection).unwrap_or("");
    let blocks = if selected_raw.is_empty() {
        Vec::new()
    } else {
        parse_semantic_document(document_id, source_part_path, selected_raw.as_bytes())?
            .0
            .blocks
    };
    let inlines = if selected_raw.is_empty() {
        Vec::new()
    } else {
        parse_mce_inline_children(document_id, source_part_path, selected_raw.as_bytes())?
    };
    Ok(MceSelectedContent {
        projection_id: projection.id.clone(),
        selected_branch_index: selected_branch_index(&projection),
        selected_branch_kind: projection.branch_kind,
        projection,
        blocks,
        inlines,
    })
}

fn parse_mce_inline_children(
    document_id: &DocumentId,
    source_part_path: &str,
    bytes: &[u8],
) -> Result<Vec<SemanticInline>, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let document_digest = sha256_hex(bytes);
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut path_stack: Vec<String> = Vec::new();
    let mut child_counts: Vec<BTreeMap<String, usize>> = vec![BTreeMap::new()];
    let mut id_set = BTreeSet::new();
    let mut inlines = Vec::new();
    let mut text_preserve_stack: Vec<bool> = Vec::new();
    let mut active_change: Option<TrackedChangeBuilder> = None;
    let mut diagnostics = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                let anchor = SourceAnchor {
                    source_part_path: source_part_path.to_owned(),
                    xml_path: path.clone(),
                    byte_start: Some(reader.buffer_position()),
                };
                if name.namespace_uri.as_deref() == Some(MC_NAMESPACE)
                    && name.local_name == "AlternateContent"
                {
                    let projection = read_alternate_content(
                        document_id,
                        source_part_path,
                        &document_digest,
                        anchor,
                        &attrs,
                        &namespace_context(&namespace_stack),
                        &mut reader,
                        &mut diagnostics,
                        &mut id_set,
                    )?;
                    let content =
                        build_mce_selected_content(document_id, source_part_path, projection)?;
                    inlines.push(SemanticInline::MceSelectedContent(content.clone()));
                    if let Some(change) = active_change.as_mut() {
                        change
                            .inline_items
                            .push(SemanticInline::MceSelectedContent(content));
                    }
                    path_stack.pop();
                    child_counts.pop();
                    namespace_stack.pop();
                } else if matches!(
                    name.local_name.as_str(),
                    "ins" | "del" | "moveFrom" | "moveTo"
                ) && name.is_wordprocessingml()
                {
                    active_change = Some(TrackedChangeBuilder::new(
                        source_part_path,
                        &name.local_name,
                        &attrs,
                        anchor,
                    ));
                } else {
                    match name.local_name.as_str() {
                        "t" if name.is_wordprocessingml() => text_preserve_stack.push(
                            attrs
                                .get("xml:space")
                                .map(|value| value == "preserve")
                                .unwrap_or(false),
                        ),
                        "tab" if name.is_wordprocessingml() => {
                            inlines.push(SemanticInline::Tab);
                            if let Some(change) = active_change.as_mut() {
                                change.inline_items.push(SemanticInline::Tab);
                            }
                        }
                        "br" | "cr" if name.is_wordprocessingml() => {
                            let inline = SemanticInline::LineBreak {
                                break_kind: name.local_name.clone(),
                            };
                            inlines.push(inline.clone());
                            if let Some(change) = active_change.as_mut() {
                                change.inline_items.push(inline);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let _path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                match name.local_name.as_str() {
                    "t" if name.is_wordprocessingml() => {
                        let preserve = attrs
                            .get("xml:space")
                            .map(|value| value == "preserve")
                            .unwrap_or(false);
                        let inline = SemanticInline::Text(SemanticText {
                            value: String::new(),
                            preserve_space: preserve,
                        });
                        inlines.push(inline.clone());
                        if let Some(change) = active_change.as_mut() {
                            change.inline_items.push(inline);
                        }
                    }
                    "tab" if name.is_wordprocessingml() => {
                        inlines.push(SemanticInline::Tab);
                        if let Some(change) = active_change.as_mut() {
                            change.inline_items.push(SemanticInline::Tab);
                        }
                    }
                    "br" | "cr" if name.is_wordprocessingml() => {
                        let inline = SemanticInline::LineBreak {
                            break_kind: name.local_name.clone(),
                        };
                        inlines.push(inline.clone());
                        if let Some(change) = active_change.as_mut() {
                            change.inline_items.push(inline);
                        }
                    }
                    _ => {}
                }
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::Text(text) => {
                let preserve = text_preserve_stack.last().copied().unwrap_or(false);
                let inline = SemanticInline::Text(SemanticText {
                    value: String::from_utf8_lossy(text.as_ref()).into_owned(),
                    preserve_space: preserve,
                });
                inlines.push(inline.clone());
                if let Some(change) = active_change.as_mut() {
                    change.inline_items.push(inline);
                }
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if name.local_name == "t" && name.is_wordprocessingml() {
                    text_preserve_stack.pop();
                }
                if matches!(
                    name.local_name.as_str(),
                    "ins" | "del" | "moveFrom" | "moveTo"
                ) && name.is_wordprocessingml()
                {
                    if let Some(change) = active_change.take() {
                        inlines.push(SemanticInline::TrackedChange {
                            change: Box::new(change.finish(
                                document_id,
                                &name.local_name,
                                source_part_path,
                                &document_digest,
                                &mut id_set,
                            )?),
                        });
                    }
                }
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(inlines)
}

#[allow(clippy::too_many_arguments)]
fn read_alternate_content(
    document_id: &DocumentId,
    source_part_path: &str,
    document_digest: &str,
    anchor: SourceAnchor,
    attrs: &BTreeMap<String, String>,
    ac_scope: &BTreeMap<String, String>,
    reader: &mut Reader<Cursor<&[u8]>>,
    diagnostics: &mut Vec<MceResolutionDiagnostic>,
    id_set: &mut BTreeSet<String>,
) -> Result<MceAlternateContentProjection, DocxImportError> {
    let mut buffer = Vec::new();
    let mut branches = Vec::new();
    let mut saw_fallback = false;
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                let mut branch_scope = ac_scope.clone();
                branch_scope.extend(namespace_declarations(&event)?);
                let name = qname_from_scope(event.name().as_ref(), &branch_scope);
                if name.namespace_uri.as_deref() == Some(MC_NAMESPACE)
                    && matches!(name.local_name.as_str(), "Choice" | "Fallback")
                {
                    if name.local_name == "Choice" && saw_fallback {
                        diagnostics.push(mce_diag(
                            "CVN_MCE_CHOICE_AFTER_FALLBACK",
                            &anchor.source_anchor_path(),
                            "mc:Choice appears after mc:Fallback",
                        ));
                    }
                    if name.local_name == "Fallback" {
                        if saw_fallback {
                            diagnostics.push(mce_diag(
                                "CVN_MCE_MULTIPLE_FALLBACK",
                                &anchor.source_anchor_path(),
                                "multiple mc:Fallback branches are present",
                            ));
                        }
                        saw_fallback = true;
                    }
                    let branch_attrs = attributes(reader, &event)?;
                    let raw_name = String::from_utf8_lossy(event.name().as_ref()).into_owned();
                    let raw = format!(
                        "{}{}{raw_name_end}",
                        start_event_xml_with_scope(&event, &branch_scope)?,
                        read_branch_xml(reader, &name.local_name)?,
                        raw_name_end = format!("</{raw_name}>")
                    );
                    branches.push(build_mce_branch(
                        if name.local_name == "Choice" {
                            MceBranchKind::Choice
                        } else {
                            MceBranchKind::Fallback
                        },
                        &branch_attrs,
                        &branch_scope,
                        &raw,
                        &anchor,
                        diagnostics,
                    ));
                } else {
                    skip_element(reader, &name.local_name)?;
                    diagnostics.push(mce_diag(
                        "CVN_MCE_INVALID_BRANCH_ORDER",
                        &anchor.source_anchor_path(),
                        "mc:AlternateContent contains a non-branch child",
                    ));
                }
            }
            Event::Empty(event) => {
                let mut branch_scope = ac_scope.clone();
                branch_scope.extend(namespace_declarations(&event)?);
                let name = qname_from_scope(event.name().as_ref(), &branch_scope);
                if name.namespace_uri.as_deref() == Some(MC_NAMESPACE)
                    && matches!(name.local_name.as_str(), "Choice" | "Fallback")
                {
                    let branch_attrs = attributes(reader, &event)?;
                    let raw = empty_event_xml_with_scope(&event, &branch_scope)?;
                    branches.push(build_mce_branch(
                        if name.local_name == "Choice" {
                            MceBranchKind::Choice
                        } else {
                            MceBranchKind::Fallback
                        },
                        &branch_attrs,
                        &branch_scope,
                        &raw,
                        &anchor,
                        diagnostics,
                    ));
                    if name.local_name == "Fallback" {
                        if saw_fallback {
                            diagnostics.push(mce_diag(
                                "CVN_MCE_MULTIPLE_FALLBACK",
                                &anchor.source_anchor_path(),
                                "multiple mc:Fallback branches are present",
                            ));
                        }
                        saw_fallback = true;
                    }
                }
            }
            Event::End(event) => {
                let name = qname_from_scope(event.name().as_ref(), ac_scope);
                if name.namespace_uri.as_deref() == Some(MC_NAMESPACE)
                    && name.local_name == "AlternateContent"
                {
                    break;
                }
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    select_branch(&mut branches, &anchor, diagnostics);
    let branch_kind = if branches
        .iter()
        .any(|branch| branch.selected && branch.kind == MceBranchKind::Choice)
    {
        MceSelection::SelectedChoice
    } else if branches
        .iter()
        .any(|branch| branch.selected && branch.kind == MceBranchKind::Fallback)
    {
        MceSelection::SelectedFallback
    } else {
        MceSelection::Unresolved
    };
    let id = semantic_id(
        document_id,
        source_part_path,
        "mce",
        None,
        &anchor.xml_path,
        document_digest,
        id_set,
    )?;
    Ok(MceAlternateContentProjection {
        id,
        source_anchor: anchor.clone(),
        branch_kind,
        branches,
        compatibility: parse_mce_compatibility(attrs, ac_scope, &anchor, diagnostics),
    })
}

fn build_mce_branch(
    kind: MceBranchKind,
    attrs: &BTreeMap<String, String>,
    scope: &BTreeMap<String, String>,
    raw_xml: &str,
    anchor: &SourceAnchor,
    diagnostics: &mut Vec<MceResolutionDiagnostic>,
) -> MceBranchProjection {
    let requires_raw = attrs.get("Requires").cloned();
    let requires = requires_raw
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|prefix| resolve_requirement(prefix, scope, anchor, diagnostics))
        .collect::<Vec<_>>();
    MceBranchProjection {
        kind,
        requires_raw,
        requires,
        selected: false,
        raw_digest: sha256_hex(raw_xml.as_bytes()),
        raw_content: raw_xml.to_owned(),
        content: Vec::new(),
    }
}

fn resolve_requirement(
    prefix: &str,
    scope: &BTreeMap<String, String>,
    anchor: &SourceAnchor,
    diagnostics: &mut Vec<MceResolutionDiagnostic>,
) -> MceNamespaceRequirement {
    let namespace_uri = scope.get(prefix).cloned();
    let supported = namespace_uri
        .as_ref()
        .map(|uri| {
            mce_capabilities()
                .supported_namespaces
                .iter()
                .any(|supported| supported == uri)
        })
        .unwrap_or(false);
    if namespace_uri.is_none() {
        diagnostics.push(mce_diag(
            "CVN_MCE_REQUIRES_PREFIX_UNRESOLVED",
            &anchor.source_anchor_path(),
            &format!("Requires prefix `{prefix}` is not defined"),
        ));
    } else if !supported {
        diagnostics.push(mce_diag(
            "CVN_MCE_REQUIRES_NAMESPACE_UNSUPPORTED",
            &anchor.source_anchor_path(),
            &format!("Requires namespace for prefix `{prefix}` is not supported"),
        ));
    }
    MceNamespaceRequirement {
        prefix: prefix.to_owned(),
        namespace_uri,
        supported,
    }
}

fn select_branch(
    branches: &mut [MceBranchProjection],
    anchor: &SourceAnchor,
    diagnostics: &mut Vec<MceResolutionDiagnostic>,
) {
    if let Some(index) = branches.iter().position(|branch| {
        branch.kind == MceBranchKind::Choice
            && !branch.requires.is_empty()
            && branch
                .requires
                .iter()
                .all(|requirement| requirement.supported)
    }) {
        branches[index].selected = true;
        return;
    }
    if let Some(index) = branches
        .iter()
        .position(|branch| branch.kind == MceBranchKind::Fallback)
    {
        branches[index].selected = true;
    } else {
        diagnostics.push(mce_diag(
            "CVN_MCE_FALLBACK_MISSING",
            &anchor.source_anchor_path(),
            "no supported mc:Choice and no mc:Fallback branch",
        ));
    }
}

fn parse_mce_compatibility(
    attrs: &BTreeMap<String, String>,
    scope: &BTreeMap<String, String>,
    anchor: &SourceAnchor,
    diagnostics: &mut Vec<MceResolutionDiagnostic>,
) -> Option<MceCompatibilityAttributes> {
    let ignorable_raw = attrs.get("Ignorable").cloned();
    let process_content = qname_list(attrs.get("ProcessContent"), scope, anchor, diagnostics);
    let preserve_elements = qname_list(attrs.get("PreserveElements"), scope, anchor, diagnostics);
    let preserve_attributes =
        qname_list(attrs.get("PreserveAttributes"), scope, anchor, diagnostics);
    let ignorable_namespaces = ignorable_raw
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|prefix| {
            let namespace = scope.get(prefix).cloned();
            if namespace.is_none() {
                diagnostics.push(mce_diag(
                    "CVN_MCE_QNAME_UNRESOLVED",
                    &anchor.source_anchor_path(),
                    &format!("Ignorable prefix `{prefix}` is not defined"),
                ));
            }
            namespace
        })
        .collect::<Vec<_>>();
    if ignorable_raw.is_none()
        && process_content.is_empty()
        && preserve_elements.is_empty()
        && preserve_attributes.is_empty()
    {
        return None;
    }
    Some(MceCompatibilityAttributes {
        ignorable_raw,
        ignorable_namespaces,
        process_content,
        preserve_elements,
        preserve_attributes,
    })
}

fn qname_list(
    raw: Option<&String>,
    scope: &BTreeMap<String, String>,
    anchor: &SourceAnchor,
    diagnostics: &mut Vec<MceResolutionDiagnostic>,
) -> Vec<MceQualifiedName> {
    raw.map(|value| {
        value
            .split_whitespace()
            .map(|qname| {
                let (prefix, local_name) = qname
                    .split_once(':')
                    .map(|(prefix, local)| (prefix, local))
                    .unwrap_or(("", qname));
                let namespace_uri = scope.get(prefix).cloned();
                if namespace_uri.is_none() && !prefix.is_empty() {
                    diagnostics.push(mce_diag(
                        "CVN_MCE_QNAME_UNRESOLVED",
                        &anchor.source_anchor_path(),
                        &format!("QName prefix `{prefix}` is not defined"),
                    ));
                }
                MceQualifiedName {
                    raw: qname.to_owned(),
                    namespace_uri,
                    local_name: local_name.to_owned(),
                }
            })
            .collect()
    })
    .unwrap_or_default()
}

fn read_branch_xml(
    reader: &mut Reader<Cursor<&[u8]>>,
    branch_local_name: &str,
) -> Result<String, DocxImportError> {
    let mut writer = Writer::new(Vec::new());
    let mut buffer = Vec::new();
    let mut depth = 0_usize;
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                depth += 1;
                writer.write_event(Event::Start(event.into_owned()))?;
            }
            Event::Empty(event) => writer.write_event(Event::Empty(event.into_owned()))?,
            Event::End(event) => {
                let raw = String::from_utf8_lossy(event.name().as_ref()).into_owned();
                let local = raw.rsplit(':').next().unwrap_or(raw.as_str());
                if depth == 0 && local == branch_local_name {
                    break;
                }
                depth = depth.saturating_sub(1);
                writer.write_event(Event::End(event.into_owned()))?;
            }
            Event::Text(event) => writer.write_event(Event::Text(event.into_owned()))?,
            Event::CData(event) => writer.write_event(Event::CData(event.into_owned()))?,
            Event::Comment(event) => writer.write_event(Event::Comment(event.into_owned()))?,
            Event::PI(event) => writer.write_event(Event::PI(event.into_owned()))?,
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: "mce-branch".to_owned(),
                });
            }
            Event::Eof => break,
            event => writer.write_event(event.into_owned())?,
        }
        buffer.clear();
    }
    Ok(String::from_utf8_lossy(&writer.into_inner()).into_owned())
}

fn start_event_xml(event: &BytesStart<'_>) -> Result<String, DocxImportError> {
    let mut writer = Writer::new(Vec::new());
    writer.write_event(Event::Start(event.to_owned()))?;
    Ok(String::from_utf8_lossy(&writer.into_inner()).into_owned())
}

fn start_event_xml_with_scope(
    event: &BytesStart<'_>,
    scope: &BTreeMap<String, String>,
) -> Result<String, DocxImportError> {
    let mut event = event.to_owned();
    add_missing_namespace_declarations(&mut event, scope)?;
    start_event_xml(&event)
}

fn empty_event_xml(event: &BytesStart<'_>) -> Result<String, DocxImportError> {
    let mut writer = Writer::new(Vec::new());
    writer.write_event(Event::Empty(event.to_owned()))?;
    Ok(String::from_utf8_lossy(&writer.into_inner()).into_owned())
}

fn empty_event_xml_with_scope(
    event: &BytesStart<'_>,
    scope: &BTreeMap<String, String>,
) -> Result<String, DocxImportError> {
    let mut event = event.to_owned();
    add_missing_namespace_declarations(&mut event, scope)?;
    empty_event_xml(&event)
}

fn add_missing_namespace_declarations(
    event: &mut BytesStart<'_>,
    scope: &BTreeMap<String, String>,
) -> Result<(), quick_xml::Error> {
    let existing = namespace_declarations(event)?;
    for (prefix, uri) in scope {
        if existing.contains_key(prefix) {
            continue;
        }
        if prefix.is_empty() {
            event.push_attribute(("xmlns", uri.as_str()));
        } else {
            let key = format!("xmlns:{prefix}");
            event.push_attribute((key.as_str(), uri.as_str()));
        }
    }
    Ok(())
}

fn skip_element(
    reader: &mut Reader<Cursor<&[u8]>>,
    local_name: &str,
) -> Result<(), DocxImportError> {
    let mut buffer = Vec::new();
    let mut depth = 0_usize;
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(_) => depth += 1,
            Event::End(event) => {
                let raw = String::from_utf8_lossy(event.name().as_ref()).into_owned();
                let local = raw.rsplit(':').next().unwrap_or(raw.as_str());
                if depth == 0 && local == local_name {
                    break;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Eof => break,
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: "mce-skip".to_owned(),
                });
            }
            _ => {}
        }
        buffer.clear();
    }
    Ok(())
}

fn namespace_context(namespace_stack: &[BTreeMap<String, String>]) -> BTreeMap<String, String> {
    let mut context = BTreeMap::new();
    for scope in namespace_stack {
        context.extend(scope.clone());
    }
    context
}

fn qname_from_scope(name: &[u8], scope: &BTreeMap<String, String>) -> XmlName {
    let raw = String::from_utf8_lossy(name);
    let (prefix, local_name) = raw
        .split_once(':')
        .map(|(prefix, local)| (prefix, local))
        .unwrap_or(("", raw.as_ref()));
    XmlName {
        local_name: local_name.to_owned(),
        namespace_uri: scope.get(prefix).cloned(),
    }
}

fn mce_diag(code: &str, path: &str, message: &str) -> MceResolutionDiagnostic {
    MceResolutionDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

trait SourceAnchorPath {
    fn source_anchor_path(&self) -> String;
}

impl SourceAnchorPath for SourceAnchor {
    fn source_anchor_path(&self) -> String {
        format!("{}{}", self.source_part_path, self.xml_path)
    }
}

fn parse_semantic_document(
    document_id: &DocumentId,
    source_part_path: &str,
    bytes: &[u8],
) -> Result<(SemanticDocument, Option<TrackChangesProjection>), DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let document_digest = sha256_hex(bytes);
    let mut buffer = Vec::new();
    let mut path_stack: Vec<String> = Vec::new();
    let mut child_counts: Vec<BTreeMap<String, usize>> = vec![BTreeMap::new()];
    let mut unsupported_features = Vec::new();
    let mut blocks = Vec::new();
    let mut paragraph_stack: Vec<ParagraphBuilder> = Vec::new();
    let mut run_stack: Vec<RunBuilder> = Vec::new();
    let mut table_stack: Vec<TableBuilder> = Vec::new();
    let mut tracked_changes: Vec<TrackedChange> = Vec::new();
    let mut active_change: Option<TrackedChangeBuilder> = None;
    let mut hyperlink_stack: Vec<HyperlinkBuilder> = Vec::new();
    let mut field_stack: Vec<FieldBuilder> = Vec::new();
    let mut text_preserve_stack: Vec<bool> = Vec::new();
    let mut instr_text_stack: Vec<()> = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut id_set = BTreeSet::new();
    let mut section_index = 0_u64;
    let mut mce_diagnostics = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                let anchor = SourceAnchor {
                    source_part_path: source_part_path.to_owned(),
                    xml_path: path.clone(),
                    byte_start: Some(reader.buffer_position()),
                };

                if name.namespace_uri.as_deref() == Some(MC_NAMESPACE)
                    && name.local_name == "AlternateContent"
                {
                    let projection = read_alternate_content(
                        document_id,
                        source_part_path,
                        &document_digest,
                        anchor,
                        &attrs,
                        &namespace_context(&namespace_stack),
                        &mut reader,
                        &mut mce_diagnostics,
                        &mut id_set,
                    )?;
                    let content =
                        build_mce_selected_content(document_id, source_part_path, projection)?;
                    if !run_stack.is_empty()
                        || !hyperlink_stack.is_empty()
                        || !field_stack.is_empty()
                    {
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::MceSelectedContent(content),
                        );
                    } else {
                        push_block(
                            SemanticBlock::MceSelectedContent(content),
                            &mut table_stack,
                            &mut blocks,
                        );
                    }
                    path_stack.pop();
                    child_counts.pop();
                    namespace_stack.pop();
                    buffer.clear();
                    continue;
                }

                match name.local_name.as_str() {
                    "ins" | "del" | "moveFrom" | "moveTo" | "pPrChange" | "rPrChange"
                    | "tblPrChange" | "trPrChange" | "tcPrChange" | "sectPrChange" => {
                        active_change = Some(TrackedChangeBuilder::new(
                            source_part_path,
                            &name.local_name,
                            &attrs,
                            anchor.clone(),
                        ));
                    }
                    "hyperlink" if name.is_wordprocessingml() => {
                        let id = semantic_id(
                            document_id,
                            source_part_path,
                            "hyperlink",
                            None,
                            &anchor.xml_path,
                            &document_digest,
                            &mut id_set,
                        )?;
                        let target_kind =
                            if attrs.get("r:id").is_some() || attr_named(&attrs, "id").is_some() {
                                HyperlinkTargetKind::Unresolved
                            } else if attrs.get("w:anchor").is_some()
                                || attr_named(&attrs, "anchor").is_some()
                            {
                                HyperlinkTargetKind::InternalAnchor
                            } else {
                                HyperlinkTargetKind::Unresolved
                            };
                        hyperlink_stack.push(HyperlinkBuilder {
                            id,
                            anchor,
                            relationship_id: attrs
                                .get("r:id")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "id").cloned()),
                            target: HyperlinkTarget {
                                kind: target_kind,
                                raw_target: None,
                                resolved_part_path: None,
                                relationship_type: None,
                                risk_class: None,
                            },
                            anchor_target: attrs
                                .get("w:anchor")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "anchor").cloned()),
                            doc_location: attrs
                                .get("w:docLocation")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "docLocation").cloned()),
                            history: attrs
                                .get("w:history")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "history").cloned()),
                            target_frame: attrs
                                .get("w:tgtFrame")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "tgtFrame").cloned()),
                            tooltip: attrs
                                .get("w:tooltip")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "tooltip").cloned()),
                            children: Vec::new(),
                        });
                    }
                    "drawing" if name.is_wordprocessingml() => {
                        let scope = namespace_context(&namespace_stack);
                        let raw_xml = read_element_xml_with_scope(
                            &event,
                            &scope,
                            &mut reader,
                            source_part_path,
                        )?;
                        append_visual_inline(
                            document_id,
                            source_part_path,
                            &document_digest,
                            VisualInlineContainerKind::Drawing,
                            anchor,
                            &raw_xml,
                            &mut id_set,
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                        )?;
                        path_stack.pop();
                        child_counts.pop();
                        namespace_stack.pop();
                        buffer.clear();
                        continue;
                    }
                    "pict" if name.is_wordprocessingml() => {
                        let scope = namespace_context(&namespace_stack);
                        let raw_xml = read_element_xml_with_scope(
                            &event,
                            &scope,
                            &mut reader,
                            source_part_path,
                        )?;
                        append_visual_inline(
                            document_id,
                            source_part_path,
                            &document_digest,
                            VisualInlineContainerKind::Pict,
                            anchor,
                            &raw_xml,
                            &mut id_set,
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                        )?;
                        path_stack.pop();
                        child_counts.pop();
                        namespace_stack.pop();
                        buffer.clear();
                        continue;
                    }
                    "object" if name.is_wordprocessingml() => {
                        let scope = namespace_context(&namespace_stack);
                        let raw_xml = read_element_xml_with_scope(
                            &event,
                            &scope,
                            &mut reader,
                            source_part_path,
                        )?;
                        if let Some(object) = parse_embedded_visual_object_projection(
                            document_id,
                            source_part_path,
                            &document_digest,
                            anchor,
                            &raw_xml,
                            &mut id_set,
                        )? {
                            append_inline(
                                &mut paragraph_stack,
                                &mut run_stack,
                                &mut active_change,
                                &mut hyperlink_stack,
                                &mut field_stack,
                                SemanticInline::EmbeddedVisualObject(object),
                            );
                        }
                        path_stack.pop();
                        child_counts.pop();
                        namespace_stack.pop();
                        buffer.clear();
                        continue;
                    }
                    "fldSimple" if name.is_wordprocessingml() => {
                        let id = semantic_id(
                            document_id,
                            source_part_path,
                            "field",
                            None,
                            &anchor.xml_path,
                            &document_digest,
                            &mut id_set,
                        )?;
                        field_stack.push(FieldBuilder {
                            id,
                            anchor: anchor.clone(),
                            instruction_raw: attrs
                                .get("w:instr")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "instr").cloned())
                                .unwrap_or_default(),
                            result_children: Vec::new(),
                            markers: vec![FieldCharacterKindProjection {
                                kind: FieldCharacterKind::Simple,
                                source_anchor: anchor,
                            }],
                            field_lock: attrs
                                .get("w:fldLock")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "fldLock").cloned()),
                            dirty: attrs
                                .get("w:dirty")
                                .cloned()
                                .or_else(|| attr_named(&attrs, "dirty").cloned()),
                            mode: FieldCaptureMode::Result,
                        });
                    }
                    "instrText" if name.is_wordprocessingml() => {
                        instr_text_stack.push(());
                    }
                    "p" if name.is_wordprocessingml() => {
                        let source_identifier = attrs.get("w14:paraId").cloned();
                        paragraph_stack.push(ParagraphBuilder {
                            source_identifier,
                            anchor,
                            properties: ParagraphPropertiesProjection::default(),
                            numbering: None,
                            section_story_references: Vec::new(),
                            runs: Vec::new(),
                        });
                    }
                    "pStyle" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            paragraph.properties.style_id = attr_val(&attrs);
                        }
                    }
                    "sectPr" if name.is_wordprocessingml() => {
                        section_index = section_index.saturating_add(1);
                    }
                    "headerReference" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            if let (Some(rel_id), Some(rel_type)) = (
                                attr_named(&attrs, "id")
                                    .cloned()
                                    .or_else(|| attrs.get("r:id").cloned()),
                                attr_named(&attrs, "type")
                                    .cloned()
                                    .or_else(|| attrs.get("w:type").cloned()),
                            ) {
                                let kind = story_part_kind_from_header_footer_type(&rel_type, true);
                                paragraph.section_story_references.push(
                                    HeaderFooterReferenceProjection {
                                        section_index,
                                        kind,
                                        relationship_id: rel_id.clone(),
                                        relationship_type: rel_type,
                                        target: String::new(),
                                        resolved_part_path: None,
                                        source_anchor: anchor.clone(),
                                    },
                                );
                            }
                        }
                    }
                    "footerReference" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            if let (Some(rel_id), Some(rel_type)) = (
                                attr_named(&attrs, "id")
                                    .cloned()
                                    .or_else(|| attrs.get("r:id").cloned()),
                                attr_named(&attrs, "type")
                                    .cloned()
                                    .or_else(|| attrs.get("w:type").cloned()),
                            ) {
                                let kind =
                                    story_part_kind_from_header_footer_type(&rel_type, false);
                                paragraph.section_story_references.push(
                                    HeaderFooterReferenceProjection {
                                        section_index,
                                        kind,
                                        relationship_id: rel_id.clone(),
                                        relationship_type: rel_type,
                                        target: String::new(),
                                        resolved_part_path: None,
                                        source_anchor: anchor.clone(),
                                    },
                                );
                            }
                        }
                    }
                    "numId" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            let num_id = attr_val(&attrs);
                            if let Some(num_id) = num_id {
                                let ilvl = paragraph
                                    .numbering
                                    .as_ref()
                                    .and_then(|numbering| numbering.ilvl.clone());
                                paragraph.numbering = Some(NumberingReference {
                                    num_id,
                                    ilvl,
                                    resolved_level: None,
                                });
                            }
                        }
                    }
                    "ilvl" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            let ilvl = attr_val(&attrs);
                            if let Some(reference) = paragraph.numbering.as_mut() {
                                reference.ilvl = ilvl;
                            } else if let Some(ilvl) = ilvl {
                                paragraph.numbering = Some(NumberingReference {
                                    num_id: String::new(),
                                    ilvl: Some(ilvl),
                                    resolved_level: None,
                                });
                            }
                        }
                    }
                    "r" if name.is_wordprocessingml() => {
                        run_stack.push(RunBuilder {
                            source_identifier: None,
                            anchor,
                            properties: RunPropertiesProjection::default(),
                            inlines: Vec::new(),
                        });
                    }
                    "rStyle" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            run.properties.run_style_id = attr_val(&attrs);
                        }
                    }
                    "b" if name.is_wordprocessingml() => set_run_bool(&mut run_stack, "b", &attrs),
                    "i" if name.is_wordprocessingml() => set_run_bool(&mut run_stack, "i", &attrs),
                    "u" if name.is_wordprocessingml() => set_run_bool(&mut run_stack, "u", &attrs),
                    "strike" if name.is_wordprocessingml() => {
                        set_run_bool(&mut run_stack, "strike", &attrs)
                    }
                    "t" if name.is_wordprocessingml() => {
                        text_preserve_stack.push(
                            attrs
                                .get("xml:space")
                                .map(|value| value == "preserve")
                                .unwrap_or(false),
                        );
                        if let Some(change) = active_change.as_mut() {
                            change.seen_text = true;
                        }
                    }
                    "tab" if name.is_wordprocessingml() => {
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::Tab,
                        );
                    }
                    "footnoteReference" if name.is_wordprocessingml() => {
                        let note_id = attr_named(&attrs, "id")
                            .cloned()
                            .or_else(|| attrs.get("w:id").cloned())
                            .unwrap_or_default();
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::FootnoteReference {
                                note_id,
                                resolved_part_path: None,
                            },
                        );
                    }
                    "endnoteReference" if name.is_wordprocessingml() => {
                        let note_id = attr_named(&attrs, "id")
                            .cloned()
                            .or_else(|| attrs.get("w:id").cloned())
                            .unwrap_or_default();
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::EndnoteReference {
                                note_id,
                                resolved_part_path: None,
                            },
                        );
                    }
                    "commentRangeStart" if name.is_wordprocessingml() => {
                        let comment_id = attr_named(&attrs, "id")
                            .cloned()
                            .or_else(|| attrs.get("w:id").cloned())
                            .unwrap_or_default();
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::CommentRangeStart { comment_id },
                        );
                    }
                    "commentRangeEnd" if name.is_wordprocessingml() => {
                        let comment_id = attr_named(&attrs, "id")
                            .cloned()
                            .or_else(|| attrs.get("w:id").cloned())
                            .unwrap_or_default();
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::CommentRangeEnd { comment_id },
                        );
                    }
                    "commentReference" if name.is_wordprocessingml() => {
                        let comment_id = attr_named(&attrs, "id")
                            .cloned()
                            .or_else(|| attrs.get("w:id").cloned())
                            .unwrap_or_default();
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::CommentReference {
                                comment_id,
                                resolved_part_path: None,
                            },
                        );
                    }
                    "br" | "cr" if name.is_wordprocessingml() => {
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::LineBreak {
                                break_kind: name.local_name.clone(),
                            },
                        );
                    }
                    "tbl" if name.is_wordprocessingml() => {
                        table_stack.push(TableBuilder {
                            anchor,
                            rows: Vec::new(),
                        });
                    }
                    "tr" if name.is_wordprocessingml() => {
                        if let Some(table) = table_stack.last_mut() {
                            table.rows.push(RowBuilder {
                                anchor,
                                cells: Vec::new(),
                            });
                        }
                    }
                    "tc" if name.is_wordprocessingml() => {
                        if let Some(row) = table_stack
                            .last_mut()
                            .and_then(|table| table.rows.last_mut())
                        {
                            row.cells.push(CellBuilder {
                                anchor,
                                grid_span: None,
                                v_merge: None,
                                blocks: Vec::new(),
                            });
                        }
                    }
                    "gridSpan" if name.is_wordprocessingml() => {
                        if let Some(cell) = current_cell_mut(&mut table_stack) {
                            cell.grid_span = attr_val(&attrs);
                        }
                    }
                    "vMerge" if name.is_wordprocessingml() => {
                        if let Some(cell) = current_cell_mut(&mut table_stack) {
                            cell.v_merge = attr_val(&attrs).or_else(|| Some("continue".to_owned()));
                        }
                    }
                    known if is_known_wordprocessingml(known) && name.is_wordprocessingml() => {}
                    _ => unsupported_features.push(UnsupportedSemanticFeature {
                        code: "unsupported_semantic_element".to_owned(),
                        source_anchor: anchor,
                        namespace_uri: name.namespace_uri.clone(),
                        local_name: name.local_name.clone(),
                        handling: UnsupportedFeatureHandling::PreservedRaw,
                    }),
                }
            }
            Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                let anchor = SourceAnchor {
                    source_part_path: source_part_path.to_owned(),
                    xml_path: path.clone(),
                    byte_start: Some(reader.buffer_position()),
                };

                match name.local_name.as_str() {
                    "p" if name.is_wordprocessingml() => {
                        let source_identifier = attrs.get("w14:paraId").cloned();
                        paragraph_stack.push(ParagraphBuilder {
                            source_identifier,
                            anchor,
                            properties: ParagraphPropertiesProjection::default(),
                            numbering: None,
                            section_story_references: Vec::new(),
                            runs: Vec::new(),
                        });
                    }
                    "pStyle" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            paragraph.properties.style_id = attr_val(&attrs);
                        }
                    }
                    "sectPr" if name.is_wordprocessingml() => {
                        section_index = section_index.saturating_add(1);
                    }
                    "numId" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            let num_id = attr_val(&attrs);
                            if let Some(num_id) = num_id {
                                let ilvl = paragraph
                                    .numbering
                                    .as_ref()
                                    .and_then(|numbering| numbering.ilvl.clone());
                                paragraph.numbering = Some(NumberingReference {
                                    num_id,
                                    ilvl,
                                    resolved_level: None,
                                });
                            }
                        }
                    }
                    "ilvl" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            let ilvl = attr_val(&attrs);
                            if let Some(reference) = paragraph.numbering.as_mut() {
                                reference.ilvl = ilvl;
                            } else if let Some(ilvl) = ilvl {
                                paragraph.numbering = Some(NumberingReference {
                                    num_id: String::new(),
                                    ilvl: Some(ilvl),
                                    resolved_level: None,
                                });
                            }
                        }
                    }
                    "fldChar" if name.is_wordprocessingml() => {
                        let fld_type = attrs
                            .get("w:fldCharType")
                            .cloned()
                            .or_else(|| attr_named(&attrs, "fldCharType").cloned())
                            .unwrap_or_default();
                        match fld_type.as_str() {
                            "begin" => {
                                let id = semantic_id(
                                    document_id,
                                    source_part_path,
                                    "field",
                                    None,
                                    &anchor.xml_path,
                                    &document_digest,
                                    &mut id_set,
                                )?;
                                field_stack.push(FieldBuilder {
                                    id,
                                    anchor: anchor.clone(),
                                    instruction_raw: String::new(),
                                    result_children: Vec::new(),
                                    markers: vec![FieldCharacterKindProjection {
                                        kind: FieldCharacterKind::Begin,
                                        source_anchor: anchor,
                                    }],
                                    field_lock: attrs
                                        .get("w:fldLock")
                                        .cloned()
                                        .or_else(|| attr_named(&attrs, "fldLock").cloned()),
                                    dirty: attrs
                                        .get("w:dirty")
                                        .cloned()
                                        .or_else(|| attr_named(&attrs, "dirty").cloned()),
                                    mode: FieldCaptureMode::Instruction,
                                });
                            }
                            "separate" => {
                                if let Some(field) = field_stack.last_mut() {
                                    field.mode = FieldCaptureMode::Result;
                                    field.markers.push(FieldCharacterKindProjection {
                                        kind: FieldCharacterKind::Separate,
                                        source_anchor: anchor,
                                    });
                                }
                            }
                            "end" => {
                                if let Some(mut field) = field_stack.pop() {
                                    field.markers.push(FieldCharacterKindProjection {
                                        kind: FieldCharacterKind::End,
                                        source_anchor: anchor,
                                    });
                                    let instruction = FieldInstructionProjection {
                                        raw: field.instruction_raw,
                                        tokens: Vec::new(),
                                    };
                                    let raw = instruction.raw.clone();
                                    append_inline(
                                        &mut paragraph_stack,
                                        &mut run_stack,
                                        &mut active_change,
                                        &mut hyperlink_stack,
                                        &mut field_stack,
                                        SemanticInline::Field(FieldProjection {
                                            id: field.id.clone(),
                                            source_anchor: field.anchor,
                                            field_kind: classify_field_kind(&raw),
                                            instruction: FieldInstructionProjection {
                                                tokens: instruction_tokens(&raw),
                                                ..instruction
                                            },
                                            result: FieldResultProjection {
                                                children: field.result_children,
                                            },
                                            character_markers: field.markers,
                                            field_lock: field.field_lock,
                                            dirty: field.dirty,
                                            cross_reference: None,
                                        }),
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    "drawing" if name.is_wordprocessingml() => {
                        let scope = namespace_context(&namespace_stack);
                        let raw_xml = empty_event_xml_with_scope(&event, &scope)?;
                        append_visual_inline(
                            document_id,
                            source_part_path,
                            &document_digest,
                            VisualInlineContainerKind::Drawing,
                            anchor,
                            &raw_xml,
                            &mut id_set,
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                        )?;
                    }
                    "pict" if name.is_wordprocessingml() => {
                        let scope = namespace_context(&namespace_stack);
                        let raw_xml = empty_event_xml_with_scope(&event, &scope)?;
                        append_visual_inline(
                            document_id,
                            source_part_path,
                            &document_digest,
                            VisualInlineContainerKind::Pict,
                            anchor,
                            &raw_xml,
                            &mut id_set,
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                        )?;
                    }
                    "object" if name.is_wordprocessingml() => {
                        let scope = namespace_context(&namespace_stack);
                        let raw_xml = empty_event_xml_with_scope(&event, &scope)?;
                        if let Some(object) = parse_embedded_visual_object_projection(
                            document_id,
                            source_part_path,
                            &document_digest,
                            anchor,
                            &raw_xml,
                            &mut id_set,
                        )? {
                            append_inline(
                                &mut paragraph_stack,
                                &mut run_stack,
                                &mut active_change,
                                &mut hyperlink_stack,
                                &mut field_stack,
                                SemanticInline::EmbeddedVisualObject(object),
                            );
                        }
                    }
                    "bookmarkStart" if name.is_wordprocessingml() => {
                        let bookmark_id = attr_named(&attrs, "id")
                            .cloned()
                            .or_else(|| attrs.get("w:id").cloned())
                            .unwrap_or_default();
                        let node_key = format!("bookmark-start:{bookmark_id}");
                        let id = semantic_id(
                            document_id,
                            source_part_path,
                            "bookmark-start",
                            Some(&node_key),
                            &anchor.xml_path,
                            &document_digest,
                            &mut id_set,
                        )?;
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::BookmarkStart(BookmarkProjection {
                                id,
                                source_anchor: anchor,
                                bookmark_id,
                                name: attrs
                                    .get("w:name")
                                    .cloned()
                                    .or_else(|| attr_named(&attrs, "name").cloned()),
                                column_first: attrs
                                    .get("w:colFirst")
                                    .cloned()
                                    .or_else(|| attr_named(&attrs, "colFirst").cloned()),
                                column_last: attrs
                                    .get("w:colLast")
                                    .cloned()
                                    .or_else(|| attr_named(&attrs, "colLast").cloned()),
                                boundary_kind: BookmarkBoundaryKind::Start,
                            }),
                        );
                    }
                    "bookmarkEnd" if name.is_wordprocessingml() => {
                        let bookmark_id = attr_named(&attrs, "id")
                            .cloned()
                            .or_else(|| attrs.get("w:id").cloned())
                            .unwrap_or_default();
                        let node_key = format!("bookmark-end:{bookmark_id}");
                        let id = semantic_id(
                            document_id,
                            source_part_path,
                            "bookmark-end",
                            Some(&node_key),
                            &anchor.xml_path,
                            &document_digest,
                            &mut id_set,
                        )?;
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::BookmarkEnd(BookmarkProjection {
                                id,
                                source_anchor: anchor,
                                bookmark_id,
                                name: None,
                                column_first: None,
                                column_last: None,
                                boundary_kind: BookmarkBoundaryKind::End,
                            }),
                        );
                    }
                    "rStyle" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            run.properties.run_style_id = attr_val(&attrs);
                        }
                    }
                    "b" if name.is_wordprocessingml() => set_run_bool(&mut run_stack, "b", &attrs),
                    "i" if name.is_wordprocessingml() => set_run_bool(&mut run_stack, "i", &attrs),
                    "u" if name.is_wordprocessingml() => set_run_bool(&mut run_stack, "u", &attrs),
                    "strike" if name.is_wordprocessingml() => {
                        set_run_bool(&mut run_stack, "strike", &attrs)
                    }
                    "t" if name.is_wordprocessingml() => append_inline(
                        &mut paragraph_stack,
                        &mut run_stack,
                        &mut active_change,
                        &mut hyperlink_stack,
                        &mut field_stack,
                        SemanticInline::Text(SemanticText {
                            value: String::new(),
                            preserve_space: attrs
                                .get("xml:space")
                                .map(|value| value == "preserve")
                                .unwrap_or(false),
                        }),
                    ),
                    "tab" if name.is_wordprocessingml() => {
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::Tab,
                        );
                    }
                    "br" | "cr" if name.is_wordprocessingml() => {
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::LineBreak {
                                break_kind: name.local_name.clone(),
                            },
                        );
                    }
                    "gridSpan" if name.is_wordprocessingml() => {
                        if let Some(cell) = current_cell_mut(&mut table_stack) {
                            cell.grid_span = attr_val(&attrs);
                        }
                    }
                    "vMerge" if name.is_wordprocessingml() => {
                        if let Some(cell) = current_cell_mut(&mut table_stack) {
                            cell.v_merge = attr_val(&attrs).or_else(|| Some("continue".to_owned()));
                        }
                    }
                    known if is_known_wordprocessingml(known) && name.is_wordprocessingml() => {}
                    _ => unsupported_features.push(UnsupportedSemanticFeature {
                        code: "unsupported_semantic_element".to_owned(),
                        source_anchor: anchor,
                        namespace_uri: name.namespace_uri.clone(),
                        local_name: name.local_name.clone(),
                        handling: UnsupportedFeatureHandling::PreservedRaw,
                    }),
                }
                end_element(
                    document_id,
                    &document_digest,
                    source_part_path,
                    &name.local_name,
                    &mut path_stack,
                    &mut child_counts,
                    &mut paragraph_stack,
                    &mut run_stack,
                    &mut table_stack,
                    &mut blocks,
                    &mut id_set,
                )?;
                namespace_stack.pop();
            }
            Event::Text(text) => {
                let value = String::from_utf8_lossy(text.as_ref()).into_owned();
                if !instr_text_stack.is_empty() {
                    if let Some(field) = field_stack.last_mut() {
                        field.instruction_raw.push_str(&value);
                    }
                    buffer.clear();
                    continue;
                }
                let preserve = text_preserve_stack.last().copied().unwrap_or(false);
                append_inline(
                    &mut paragraph_stack,
                    &mut run_stack,
                    &mut active_change,
                    &mut hyperlink_stack,
                    &mut field_stack,
                    SemanticInline::Text(SemanticText {
                        value,
                        preserve_space: preserve,
                    }),
                );
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: source_part_path.to_owned(),
                });
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if name.local_name == "t" && name.is_wordprocessingml() {
                    text_preserve_stack.pop();
                }
                if name.local_name == "instrText" && name.is_wordprocessingml() {
                    instr_text_stack.pop();
                }
                if name.local_name == "hyperlink" && name.is_wordprocessingml() {
                    if let Some(hyperlink) = hyperlink_stack.pop() {
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::Hyperlink(HyperlinkProjection {
                                id: hyperlink.id,
                                source_anchor: hyperlink.anchor,
                                relationship_id: hyperlink.relationship_id,
                                target: hyperlink.target,
                                anchor: hyperlink.anchor_target,
                                doc_location: hyperlink.doc_location,
                                history: hyperlink.history,
                                target_frame: hyperlink.target_frame,
                                tooltip: hyperlink.tooltip,
                                children: hyperlink.children,
                            }),
                        );
                    }
                }
                if name.local_name == "fldSimple" && name.is_wordprocessingml() {
                    if let Some(field) = field_stack.pop() {
                        let raw = field.instruction_raw.clone();
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::Field(FieldProjection {
                                id: field.id,
                                source_anchor: field.anchor,
                                field_kind: classify_field_kind(&raw),
                                instruction: FieldInstructionProjection {
                                    raw: raw.clone(),
                                    tokens: instruction_tokens(&raw),
                                },
                                result: FieldResultProjection {
                                    children: field.result_children,
                                },
                                character_markers: field.markers,
                                field_lock: field.field_lock,
                                dirty: field.dirty,
                                cross_reference: None,
                            }),
                        );
                    }
                }
                if matches!(
                    name.local_name.as_str(),
                    "ins"
                        | "del"
                        | "moveFrom"
                        | "moveTo"
                        | "pPrChange"
                        | "rPrChange"
                        | "tblPrChange"
                        | "trPrChange"
                        | "tcPrChange"
                        | "sectPrChange"
                ) {
                    if let Some(change) = active_change.take() {
                        let tracked_change = change.finish(
                            document_id,
                            &name.local_name,
                            &source_part_path.to_owned(),
                            &document_digest,
                            &mut id_set,
                        )?;
                        tracked_changes.push(tracked_change.clone());
                        append_inline(
                            &mut paragraph_stack,
                            &mut run_stack,
                            &mut active_change,
                            &mut hyperlink_stack,
                            &mut field_stack,
                            SemanticInline::TrackedChange {
                                change: Box::new(tracked_change),
                            },
                        );
                    }
                }
                end_element(
                    document_id,
                    &document_digest,
                    source_part_path,
                    &name.local_name,
                    &mut path_stack,
                    &mut child_counts,
                    &mut paragraph_stack,
                    &mut run_stack,
                    &mut table_stack,
                    &mut blocks,
                    &mut id_set,
                )?;
                namespace_stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    unsupported_features.sort_by(|left, right| {
        left.source_anchor
            .xml_path
            .cmp(&right.source_anchor.xml_path)
    });
    let track_changes = if tracked_changes.is_empty() {
        None
    } else {
        Some(TrackChangesProjection {
            source_part: source_part_path.to_owned(),
            changes: tracked_changes,
            move_ranges: Vec::new(),
            diagnostics: Vec::new(),
            unsupported_features: Vec::new(),
        })
    };

    Ok((
        SemanticDocument {
            source_part: source_part_path.to_owned(),
            blocks,
            styles: None,
            numbering: None,
            stories: None,
            references: None,
            drawings: None,
            embedded_visual_objects: None,
            unsupported_features,
        },
        track_changes,
    ))
}

#[allow(clippy::too_many_arguments)]
fn end_element(
    document_id: &DocumentId,
    document_digest: &str,
    source_part_path: &str,
    local_name: &str,
    path_stack: &mut Vec<String>,
    child_counts: &mut Vec<BTreeMap<String, usize>>,
    paragraph_stack: &mut Vec<ParagraphBuilder>,
    run_stack: &mut Vec<RunBuilder>,
    table_stack: &mut Vec<TableBuilder>,
    blocks: &mut Vec<SemanticBlock>,
    id_set: &mut BTreeSet<String>,
) -> Result<(), DocxImportError> {
    match local_name {
        "r" => {
            if let Some(run) = run_stack.pop() {
                if !run.inlines.is_empty() {
                    if let Some(paragraph) = paragraph_stack.last_mut() {
                        paragraph.runs.push(run);
                    }
                }
            }
        }
        "p" => {
            if let Some(paragraph) = paragraph_stack.pop() {
                let id = semantic_id(
                    document_id,
                    source_part_path,
                    "paragraph",
                    paragraph.source_identifier.as_deref(),
                    &paragraph.anchor.xml_path,
                    document_digest,
                    id_set,
                )?;
                let block = SemanticBlock::Paragraph(SemanticParagraph {
                    id,
                    source_identifier: paragraph.source_identifier,
                    source_anchor: paragraph.anchor,
                    properties: paragraph.properties,
                    numbering: paragraph.numbering,
                    resolved_style: None,
                    section_story_references: paragraph.section_story_references,
                    runs: paragraph
                        .runs
                        .into_iter()
                        .map(|run| {
                            let id = semantic_id(
                                document_id,
                                source_part_path,
                                "run",
                                run.source_identifier.as_deref(),
                                &run.anchor.xml_path,
                                document_digest,
                                id_set,
                            )?;
                            Ok(SemanticRun {
                                id,
                                source_identifier: run.source_identifier,
                                source_anchor: run.anchor,
                                properties: run.properties,
                                resolved_style: None,
                                inlines: run.inlines,
                            })
                        })
                        .collect::<Result<Vec<_>, DocxImportError>>()?,
                });
                push_block(block, table_stack, blocks);
            }
        }
        "tbl" => {
            if let Some(table) = table_stack.pop() {
                let id = semantic_id(
                    document_id,
                    source_part_path,
                    "table",
                    None,
                    &table.anchor.xml_path,
                    document_digest,
                    id_set,
                )?;
                let block = SemanticBlock::Table(SemanticTable {
                    id,
                    source_anchor: table.anchor,
                    rows: table
                        .rows
                        .into_iter()
                        .map(|row| {
                            let row_id = semantic_id(
                                document_id,
                                source_part_path,
                                "row",
                                None,
                                &row.anchor.xml_path,
                                document_digest,
                                id_set,
                            )?;
                            let cells = row
                                .cells
                                .into_iter()
                                .map(|cell| {
                                    let cell_id = semantic_id(
                                        document_id,
                                        source_part_path,
                                        "cell",
                                        None,
                                        &cell.anchor.xml_path,
                                        document_digest,
                                        id_set,
                                    )?;
                                    Ok(SemanticTableCell {
                                        id: cell_id,
                                        source_anchor: cell.anchor,
                                        grid_span: cell.grid_span,
                                        v_merge: cell.v_merge,
                                        blocks: cell.blocks,
                                    })
                                })
                                .collect::<Result<Vec<_>, DocxImportError>>()?;
                            Ok(SemanticTableRow {
                                id: row_id,
                                source_anchor: row.anchor,
                                cells,
                            })
                        })
                        .collect::<Result<Vec<_>, DocxImportError>>()?,
                });
                push_block(block, table_stack, blocks);
            }
        }
        _ => {}
    }
    path_stack.pop();
    child_counts.pop();
    Ok(())
}

fn push_block(
    block: SemanticBlock,
    table_stack: &mut [TableBuilder],
    blocks: &mut Vec<SemanticBlock>,
) {
    if let Some(cell) = current_cell_mut(table_stack) {
        cell.blocks.push(block);
    } else {
        blocks.push(block);
    }
}

fn current_cell_mut(table_stack: &mut [TableBuilder]) -> Option<&mut CellBuilder> {
    table_stack
        .last_mut()
        .and_then(|table| table.rows.last_mut())
        .and_then(|row| row.cells.last_mut())
}

fn next_path(
    path_stack: &mut Vec<String>,
    child_counts: &mut Vec<BTreeMap<String, usize>>,
    local_name: &str,
) -> String {
    let count = child_counts
        .last_mut()
        .expect("root child counter")
        .entry(local_name.to_owned())
        .and_modify(|count| *count += 1)
        .or_insert(1);
    let segment = format!("{local_name}[{count}]");
    path_stack.push(segment);
    child_counts.push(BTreeMap::new());
    format!("/{}", path_stack.join("/"))
}

fn semantic_id(
    document_id: &DocumentId,
    source_part_path: &str,
    kind: &str,
    source_identifier: Option<&str>,
    xml_path: &str,
    document_digest: &str,
    id_set: &mut BTreeSet<String>,
) -> Result<SemanticNodeId, DocxImportError> {
    let material = match source_identifier {
        Some(source_identifier) => format!(
            "{}|{source_part_path}|{kind}|source:{source_identifier}",
            document_id.as_str()
        ),
        None => format!(
            "{}|{source_part_path}|{kind}|path:{xml_path}|doc-sha256:{document_digest}",
            document_id.as_str()
        ),
    };
    let digest = hex::encode(Sha256::digest(material.as_bytes()));
    let id = format!("sem:{kind}:{}", &digest[..24]);
    if !id_set.insert(id.clone()) {
        return Err(DocxImportError::SemanticIdCollision(id));
    }
    SemanticNodeId::new(id).map_err(|error| DocxImportError::SemanticIdCollision(error.to_string()))
}

fn attr_val(attrs: &BTreeMap<String, String>) -> Option<String> {
    attrs.get("w:val").or_else(|| attrs.get("val")).cloned()
}

fn attr_named<'a>(attrs: &'a BTreeMap<String, String>, name: &str) -> Option<&'a String> {
    attrs.get(name).or_else(|| attrs.get(&format!("w:{name}")))
}

fn current_change_suppresses_semantic(active_change: &Option<TrackedChangeBuilder>) -> bool {
    active_change
        .as_ref()
        .map(|change| {
            change.kind == TrackedChangeKind::Deletion || change.kind == TrackedChangeKind::MoveFrom
        })
        .unwrap_or(false)
}

fn append_inline(
    paragraph_stack: &mut [ParagraphBuilder],
    run_stack: &mut [RunBuilder],
    active_change: &mut Option<TrackedChangeBuilder>,
    hyperlink_stack: &mut [HyperlinkBuilder],
    field_stack: &mut [FieldBuilder],
    inline: SemanticInline,
) {
    if let Some(field) = field_stack.last_mut() {
        if field.mode == FieldCaptureMode::Result {
            field.result_children.push(inline);
        }
        return;
    }
    if let Some(hyperlink) = hyperlink_stack.last_mut() {
        hyperlink.children.push(inline);
        return;
    }

    if let Some(change) = active_change.as_mut() {
        change.inline_items.push(inline.clone());
    }
    if current_change_suppresses_semantic(active_change) {
        return;
    }
    if let Some(run) = run_stack.last_mut() {
        run.inlines.push(inline);
    } else if let Some(paragraph) = paragraph_stack.last_mut() {
        paragraph.runs.push(RunBuilder {
            source_identifier: Some(format!(
                "{}#paragraph-inline-{}",
                paragraph.anchor.xml_path,
                paragraph.runs.len()
            )),
            anchor: paragraph.anchor.clone(),
            properties: RunPropertiesProjection::default(),
            inlines: vec![inline],
        });
    }
}

fn set_run_bool(run_stack: &mut [RunBuilder], property: &str, attrs: &BTreeMap<String, String>) {
    let enabled = attrs
        .get("w:val")
        .or_else(|| attrs.get("val"))
        .map(|value| !matches!(value.as_str(), "false" | "0" | "off"))
        .unwrap_or(true);
    if let Some(run) = run_stack.last_mut() {
        match property {
            "b" => run.properties.bold = enabled,
            "i" => run.properties.italic = enabled,
            "u" => run.properties.underline = enabled,
            "strike" => run.properties.strike = enabled,
            _ => {}
        }
    }
}

fn instruction_tokens(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = raw.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                current.push(ch);
                quoted = !quoted;
            }
            ' ' | '\t' | '\r' | '\n' if !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn classify_field_kind(raw: &str) -> FieldKind {
    let token = instruction_tokens(raw)
        .into_iter()
        .next()
        .unwrap_or_default()
        .trim_matches('"')
        .to_ascii_uppercase();
    match token.as_str() {
        "REF" => FieldKind::Ref,
        "PAGEREF" => FieldKind::Pageref,
        "NOTEREF" => FieldKind::Noteref,
        "HYPERLINK" => FieldKind::Hyperlink,
        "PAGE" => FieldKind::Page,
        "NUMPAGES" => FieldKind::Numpages,
        "DATE" => FieldKind::Date,
        "TIME" => FieldKind::Time,
        "TOC" => FieldKind::Toc,
        "SEQ" => FieldKind::Seq,
        "SYMBOL" => FieldKind::Symbol,
        "INCLUDETEXT" => FieldKind::IncludeText,
        "INCLUDEPICTURE" => FieldKind::IncludePicture,
        "LINK" => FieldKind::Link,
        "DDE" | "DDEAUTO" => FieldKind::Dde,
        _ => FieldKind::Unknown,
    }
}

fn is_known_wordprocessingml(local_name: &str) -> bool {
    matches!(
        local_name,
        "document"
            | "body"
            | "pPr"
            | "rPr"
            | "tblPr"
            | "tblGrid"
            | "gridCol"
            | "tcPr"
            | "sectPr"
            | "styles"
            | "style"
            | "name"
            | "aliases"
            | "basedOn"
            | "next"
            | "link"
            | "qFormat"
            | "semiHidden"
            | "unhideWhenUsed"
            | "uiPriority"
            | "numbering"
            | "abstractNum"
            | "num"
            | "lvl"
            | "lvlOverride"
            | "abstractNumId"
            | "start"
            | "startOverride"
            | "numFmt"
            | "lvlText"
            | "suff"
            | "lvlRestart"
            | "numPr"
            | "numId"
            | "ilvl"
    )
}

#[derive(Debug, Clone)]
struct XmlName {
    local_name: String,
    namespace_uri: Option<String>,
}

impl XmlName {
    fn is_wordprocessingml(&self) -> bool {
        matches!(
            self.namespace_uri.as_deref(),
            Some("http://schemas.openxmlformats.org/wordprocessingml/2006/main")
                | Some("http://purl.oclc.org/ooxml/wordprocessingml/main")
        )
    }
}

fn qname(name: &[u8], namespace_stack: &[BTreeMap<String, String>]) -> XmlName {
    let raw = String::from_utf8_lossy(name);
    let (prefix, local_name) = raw
        .split_once(':')
        .map(|(prefix, local)| (prefix, local))
        .unwrap_or(("", raw.as_ref()));
    let namespace_uri = namespace_stack
        .iter()
        .rev()
        .find_map(|scope| scope.get(prefix))
        .cloned();
    XmlName {
        local_name: local_name.to_owned(),
        namespace_uri,
    }
}

#[derive(Debug)]
struct ParagraphBuilder {
    source_identifier: Option<String>,
    anchor: SourceAnchor,
    properties: ParagraphPropertiesProjection,
    numbering: Option<NumberingReference>,
    section_story_references: Vec<HeaderFooterReferenceProjection>,
    runs: Vec<RunBuilder>,
}

#[derive(Debug)]
struct RunBuilder {
    source_identifier: Option<String>,
    anchor: SourceAnchor,
    properties: RunPropertiesProjection,
    inlines: Vec<SemanticInline>,
}

#[derive(Debug)]
struct TableBuilder {
    anchor: SourceAnchor,
    rows: Vec<RowBuilder>,
}

#[derive(Debug)]
struct RowBuilder {
    anchor: SourceAnchor,
    cells: Vec<CellBuilder>,
}

#[derive(Debug)]
struct CellBuilder {
    anchor: SourceAnchor,
    grid_span: Option<String>,
    v_merge: Option<String>,
    blocks: Vec<SemanticBlock>,
}

#[derive(Debug)]
struct TrackedChangeBuilder {
    kind: TrackedChangeKind,
    change_id: Option<String>,
    author: Option<String>,
    date_raw: Option<String>,
    date_utc_raw: Option<String>,
    rsid_r: Option<String>,
    rsid_del: Option<String>,
    rsid_p: Option<String>,
    rsid_rpr: Option<String>,
    inline_items: Vec<SemanticInline>,
    seen_text: bool,
    anchor: SourceAnchor,
}

#[derive(Debug)]
struct HyperlinkBuilder {
    id: SemanticNodeId,
    anchor: SourceAnchor,
    relationship_id: Option<String>,
    target: HyperlinkTarget,
    anchor_target: Option<String>,
    doc_location: Option<String>,
    history: Option<String>,
    target_frame: Option<String>,
    tooltip: Option<String>,
    children: Vec<SemanticInline>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldCaptureMode {
    Instruction,
    Result,
}

#[derive(Debug)]
struct FieldBuilder {
    id: SemanticNodeId,
    anchor: SourceAnchor,
    instruction_raw: String,
    result_children: Vec<SemanticInline>,
    markers: Vec<FieldCharacterKindProjection>,
    field_lock: Option<String>,
    dirty: Option<String>,
    mode: FieldCaptureMode,
}

impl TrackedChangeBuilder {
    fn new(
        _source_part_path: &str,
        local_name: &str,
        attrs: &BTreeMap<String, String>,
        anchor: SourceAnchor,
    ) -> Self {
        Self {
            kind: tracked_change_kind(local_name),
            change_id: attr_named(attrs, "id")
                .cloned()
                .or_else(|| attrs.get("w:id").cloned()),
            author: attr_named(attrs, "author")
                .cloned()
                .or_else(|| attrs.get("w:author").cloned()),
            date_raw: attr_named(attrs, "date")
                .cloned()
                .or_else(|| attrs.get("w:date").cloned()),
            date_utc_raw: attrs
                .get("w16du:dateUtc")
                .cloned()
                .or_else(|| attrs.get("dateUtc").cloned()),
            rsid_r: attrs.get("w:rsidR").cloned(),
            rsid_del: attrs.get("w:rsidDel").cloned(),
            rsid_p: attrs.get("w:rsidP").cloned(),
            rsid_rpr: attrs.get("w:rsidRPr").cloned(),
            inline_items: Vec::new(),
            seen_text: false,
            anchor,
        }
    }

    fn finish(
        self,
        document_id: &DocumentId,
        local_name: &str,
        source_part_path: &str,
        document_digest: &str,
        id_set: &mut BTreeSet<String>,
    ) -> Result<TrackedChange, DocxImportError> {
        let id = TrackedChangeId(format!(
            "tr:{local_name}:{}",
            &hex::encode(Sha256::digest(
                format!("{source_part_path}|{local_name}|{}", self.anchor.xml_path).as_bytes()
            ))[..24]
        ));
        let anchor_xml_path = self.anchor.xml_path.clone();
        Ok(TrackedChange {
            id,
            kind: self.kind,
            metadata: TrackedChangeMetadata {
                change_id: self.change_id,
                author: self.author,
                date_raw: self.date_raw,
                date_utc_raw: self.date_utc_raw,
                date: None,
                date_utc: None,
                rsid_r: self.rsid_r,
                rsid_del: self.rsid_del,
                rsid_p: self.rsid_p,
                rsid_rpr: self.rsid_rpr,
            },
            content: TrackedContent::Inline {
                items: self.inline_items,
            },
            source_anchor: self.anchor,
            semantic_node_id: semantic_id(
                document_id,
                source_part_path,
                "tracked-change",
                None,
                &anchor_xml_path,
                document_digest,
                id_set,
            )?,
            references: Vec::new(),
        })
    }
}

fn tracked_change_kind(local_name: &str) -> TrackedChangeKind {
    match local_name {
        "ins" => TrackedChangeKind::Insertion,
        "del" => TrackedChangeKind::Deletion,
        "moveFrom" => TrackedChangeKind::MoveFrom,
        "moveTo" => TrackedChangeKind::MoveTo,
        "pPrChange" => TrackedChangeKind::ParagraphProperties,
        "rPrChange" => TrackedChangeKind::RunProperties,
        "tblPrChange" => TrackedChangeKind::TableProperties,
        "trPrChange" => TrackedChangeKind::TableRowProperties,
        "tcPrChange" => TrackedChangeKind::TableCellProperties,
        "sectPrChange" => TrackedChangeKind::SectionProperties,
        _ => TrackedChangeKind::Unknown,
    }
}

fn parse_styles(bytes: &[u8]) -> Result<StyleRegistryProjection, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut path_stack: Vec<String> = Vec::new();
    let mut child_counts: Vec<BTreeMap<String, usize>> = vec![BTreeMap::new()];
    let mut definitions = Vec::new();
    let mut diagnostics = Vec::new();
    let mut unsupported_features = Vec::new();
    let mut current_style: Option<StyleBuilder> = None;
    let mut property_context: Option<PropertyContext> = None;

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                handle_style_element(
                    &name,
                    &attrs,
                    &path,
                    reader.buffer_position(),
                    &mut current_style,
                    &mut property_context,
                    &mut unsupported_features,
                );
            }
            Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                handle_style_element(
                    &name,
                    &attrs,
                    &path,
                    reader.buffer_position(),
                    &mut current_style,
                    &mut property_context,
                    &mut unsupported_features,
                );
                if name.local_name == "style" && name.is_wordprocessingml() {
                    if let Some(style) = current_style.take() {
                        definitions.push(style.finish());
                    }
                }
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if matches!(name.local_name.as_str(), "pPr" | "rPr") && name.is_wordprocessingml() {
                    property_context = None;
                }
                if name.local_name == "style" && name.is_wordprocessingml() {
                    if let Some(style) = current_style.take() {
                        definitions.push(style.finish());
                    }
                }
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: "word/styles.xml".to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    definitions.sort_by(|left, right| {
        left.style_id
            .cmp(&right.style_id)
            .then(left.style_type.cmp(&right.style_type))
    });
    detect_duplicate_styles(&definitions, &mut diagnostics);
    resolve_style_definitions(&mut definitions, &mut diagnostics);
    unsupported_features.sort_by(|left, right| {
        left.source_anchor
            .xml_path
            .cmp(&right.source_anchor.xml_path)
    });
    diagnostics.sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    Ok(StyleRegistryProjection {
        source_part: "word/styles.xml".to_owned(),
        definitions,
        diagnostics,
        unsupported_features,
    })
}

fn handle_style_element(
    name: &XmlName,
    attrs: &BTreeMap<String, String>,
    path: &str,
    byte_start: u64,
    current_style: &mut Option<StyleBuilder>,
    property_context: &mut Option<PropertyContext>,
    unsupported_features: &mut Vec<UnsupportedSemanticFeature>,
) {
    if !name.is_wordprocessingml() {
        unsupported_features.push(unsupported_feature(
            "word/styles.xml",
            path,
            byte_start,
            name,
        ));
        return;
    }

    match name.local_name.as_str() {
        "style" => {
            let style_id = attr_named(attrs, "styleId")
                .cloned()
                .unwrap_or_else(|| "missing-style-id".to_owned());
            *current_style = Some(StyleBuilder {
                style_id,
                style_type: style_type(attrs.get("type").or_else(|| attrs.get("w:type"))),
                name: None,
                aliases: Vec::new(),
                based_on: None,
                next: None,
                link: None,
                is_default: bool_attr(attrs, "default"),
                custom_style: bool_attr(attrs, "customStyle"),
                q_format: false,
                semi_hidden: false,
                unhide_when_used: false,
                ui_priority: None,
                paragraph_properties: ParagraphPropertiesProjection::default(),
                run_properties: RunPropertiesProjection::default(),
            });
        }
        "pPr" => *property_context = Some(PropertyContext::Paragraph),
        "rPr" => *property_context = Some(PropertyContext::Run),
        "name" => {
            if let Some(style) = current_style.as_mut() {
                style.name = attr_val(attrs);
            }
        }
        "aliases" => {
            if let Some(style) = current_style.as_mut() {
                if let Some(value) = attr_val(attrs) {
                    style.aliases = value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                }
            }
        }
        "basedOn" => {
            if let Some(style) = current_style.as_mut() {
                style.based_on = attr_val(attrs).map(|style_id| StyleReference { style_id });
            }
        }
        "next" => {
            if let Some(style) = current_style.as_mut() {
                style.next = attr_val(attrs).map(|style_id| StyleReference { style_id });
            }
        }
        "link" => {
            if let Some(style) = current_style.as_mut() {
                style.link = attr_val(attrs).map(|style_id| StyleReference { style_id });
            }
        }
        "qFormat" => {
            if let Some(style) = current_style.as_mut() {
                style.q_format = true;
            }
        }
        "semiHidden" => {
            if let Some(style) = current_style.as_mut() {
                style.semi_hidden = true;
            }
        }
        "unhideWhenUsed" => {
            if let Some(style) = current_style.as_mut() {
                style.unhide_when_used = true;
            }
        }
        "uiPriority" => {
            if let Some(style) = current_style.as_mut() {
                style.ui_priority = attr_val(attrs);
            }
        }
        "pStyle" => {
            if matches!(property_context, Some(PropertyContext::Paragraph)) {
                if let Some(style) = current_style.as_mut() {
                    style.paragraph_properties.style_id = attr_val(attrs);
                }
            }
        }
        "rStyle" => {
            if matches!(property_context, Some(PropertyContext::Run)) {
                if let Some(style) = current_style.as_mut() {
                    style.run_properties.run_style_id = attr_val(attrs);
                }
            }
        }
        "b" | "i" | "u" | "strike" => {
            if matches!(property_context, Some(PropertyContext::Run)) {
                if let Some(style) = current_style.as_mut() {
                    set_run_property(&mut style.run_properties, name.local_name.as_str(), attrs);
                }
            }
        }
        "styles" => {}
        known if is_known_wordprocessingml(known) => {}
        _ => unsupported_features.push(unsupported_feature(
            "word/styles.xml",
            path,
            byte_start,
            name,
        )),
    }
}

fn parse_numbering(bytes: &[u8]) -> Result<NumberingRegistryProjection, DocxImportError> {
    let mut reader = Reader::from_reader(Cursor::new(bytes));
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut path_stack: Vec<String> = Vec::new();
    let mut child_counts: Vec<BTreeMap<String, usize>> = vec![BTreeMap::new()];
    let mut abstract_numbers = Vec::new();
    let mut instances = Vec::new();
    let mut diagnostics = Vec::new();
    let mut unsupported_features = Vec::new();
    let mut current_abstract: Option<AbstractNumberingBuilder> = None;
    let mut current_instance: Option<NumberingInstanceBuilder> = None;
    let mut current_level: Option<NumberingLevelBuilder> = None;
    let mut property_context: Option<PropertyContext> = None;

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                handle_numbering_element(
                    &name,
                    &attrs,
                    &path,
                    reader.buffer_position(),
                    &mut current_abstract,
                    &mut current_instance,
                    &mut current_level,
                    &mut property_context,
                    &mut unsupported_features,
                );
            }
            Event::Empty(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                handle_numbering_element(
                    &name,
                    &attrs,
                    &path,
                    reader.buffer_position(),
                    &mut current_abstract,
                    &mut current_instance,
                    &mut current_level,
                    &mut property_context,
                    &mut unsupported_features,
                );
                end_numbering_element(
                    &name,
                    &mut current_abstract,
                    &mut current_instance,
                    &mut current_level,
                    &mut property_context,
                    &mut abstract_numbers,
                    &mut instances,
                );
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                end_numbering_element(
                    &name,
                    &mut current_abstract,
                    &mut current_instance,
                    &mut current_level,
                    &mut property_context,
                    &mut abstract_numbers,
                    &mut instances,
                );
                path_stack.pop();
                child_counts.pop();
                namespace_stack.pop();
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: "word/numbering.xml".to_owned(),
                });
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    abstract_numbers.sort_by(|left, right| left.abstract_num_id.cmp(&right.abstract_num_id));
    for abstract_num in &mut abstract_numbers {
        abstract_num
            .levels
            .sort_by(|left, right| left.ilvl.cmp(&right.ilvl));
    }
    instances.sort_by(|left, right| left.num_id.cmp(&right.num_id));
    for instance in &mut instances {
        instance
            .level_overrides
            .sort_by(|left, right| left.ilvl.cmp(&right.ilvl));
    }
    detect_numbering_duplicates(&abstract_numbers, &instances, &mut diagnostics);
    unsupported_features.sort_by(|left, right| {
        left.source_anchor
            .xml_path
            .cmp(&right.source_anchor.xml_path)
    });
    diagnostics.sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    Ok(NumberingRegistryProjection {
        source_part: "word/numbering.xml".to_owned(),
        abstract_numbers,
        instances,
        diagnostics,
        unsupported_features,
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_numbering_element(
    name: &XmlName,
    attrs: &BTreeMap<String, String>,
    path: &str,
    byte_start: u64,
    current_abstract: &mut Option<AbstractNumberingBuilder>,
    current_instance: &mut Option<NumberingInstanceBuilder>,
    current_level: &mut Option<NumberingLevelBuilder>,
    property_context: &mut Option<PropertyContext>,
    unsupported_features: &mut Vec<UnsupportedSemanticFeature>,
) {
    if !name.is_wordprocessingml() {
        unsupported_features.push(unsupported_feature(
            "word/numbering.xml",
            path,
            byte_start,
            name,
        ));
        return;
    }
    match name.local_name.as_str() {
        "abstractNum" => {
            *current_abstract = Some(AbstractNumberingBuilder {
                abstract_num_id: attr_named(attrs, "abstractNumId")
                    .cloned()
                    .unwrap_or_else(|| "missing-abstractNumId".to_owned()),
                levels: Vec::new(),
            });
        }
        "num" => {
            *current_instance = Some(NumberingInstanceBuilder {
                num_id: attr_named(attrs, "numId")
                    .cloned()
                    .unwrap_or_else(|| "missing-numId".to_owned()),
                abstract_num_id: None,
                level_overrides: Vec::new(),
            });
        }
        "lvl" => {
            *current_level = Some(NumberingLevelBuilder::new(
                attr_named(attrs, "ilvl")
                    .cloned()
                    .unwrap_or_else(|| "0".to_owned()),
            ));
        }
        "lvlOverride" => {
            *current_level = Some(NumberingLevelBuilder::new_override(
                attr_named(attrs, "ilvl")
                    .cloned()
                    .unwrap_or_else(|| "0".to_owned()),
            ));
        }
        "abstractNumId" => {
            if let Some(instance) = current_instance.as_mut() {
                instance.abstract_num_id = attr_val(attrs);
            }
        }
        "start" => {
            if let Some(level) = current_level.as_mut() {
                level.level.start = attr_val(attrs);
            }
        }
        "startOverride" => {
            if let Some(level) = current_level.as_mut() {
                level.level.start_override = attr_val(attrs);
            }
        }
        "numFmt" => {
            if let Some(level) = current_level.as_mut() {
                level.level.num_fmt = attr_val(attrs).map(|value| NumberFormatProjection { value });
            }
        }
        "lvlText" => {
            if let Some(level) = current_level.as_mut() {
                level.level.lvl_text = attr_val(attrs);
            }
        }
        "suff" => {
            if let Some(level) = current_level.as_mut() {
                level.level.suff = attr_val(attrs);
            }
        }
        "pStyle" => {
            if let Some(level) = current_level.as_mut() {
                level.level.paragraph_style = attr_val(attrs);
            }
        }
        "lvlRestart" => {
            if let Some(level) = current_level.as_mut() {
                level.level.lvl_restart = attr_val(attrs);
            }
        }
        "pPr" => *property_context = Some(PropertyContext::Paragraph),
        "rPr" => *property_context = Some(PropertyContext::Run),
        "rStyle" => {
            if matches!(property_context, Some(PropertyContext::Run)) {
                if let Some(level) = current_level.as_mut() {
                    level.level.run_properties.run_style_id = attr_val(attrs);
                }
            }
        }
        "b" | "i" | "u" | "strike" => {
            if matches!(property_context, Some(PropertyContext::Run)) {
                if let Some(level) = current_level.as_mut() {
                    set_run_property(
                        &mut level.level.run_properties,
                        name.local_name.as_str(),
                        attrs,
                    );
                }
            }
        }
        "numbering" => {}
        known if is_known_wordprocessingml(known) => {}
        _ => unsupported_features.push(unsupported_feature(
            "word/numbering.xml",
            path,
            byte_start,
            name,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn end_numbering_element(
    name: &XmlName,
    current_abstract: &mut Option<AbstractNumberingBuilder>,
    current_instance: &mut Option<NumberingInstanceBuilder>,
    current_level: &mut Option<NumberingLevelBuilder>,
    property_context: &mut Option<PropertyContext>,
    abstract_numbers: &mut Vec<AbstractNumberingProjection>,
    instances: &mut Vec<NumberingInstanceProjection>,
) {
    if !name.is_wordprocessingml() {
        return;
    }
    match name.local_name.as_str() {
        "pPr" | "rPr" => *property_context = None,
        "lvl" => {
            if let (Some(abstract_num), Some(level)) =
                (current_abstract.as_mut(), current_level.take())
            {
                abstract_num.levels.push(level.level);
            }
        }
        "lvlOverride" => {
            if let (Some(instance), Some(level)) = (current_instance.as_mut(), current_level.take())
            {
                instance.level_overrides.push(level.level);
            }
        }
        "abstractNum" => {
            if let Some(abstract_num) = current_abstract.take() {
                abstract_numbers.push(AbstractNumberingProjection {
                    abstract_num_id: abstract_num.abstract_num_id,
                    levels: abstract_num.levels,
                });
            }
        }
        "num" => {
            if let Some(instance) = current_instance.take() {
                instances.push(NumberingInstanceProjection {
                    num_id: instance.num_id,
                    abstract_num_id: instance.abstract_num_id,
                    level_overrides: instance.level_overrides,
                });
            }
        }
        _ => {}
    }
}

fn resolve_semantic_references(
    semantic: &mut SemanticDocument,
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    objects: &BTreeMap<String, Vec<u8>>,
) {
    let styles_snapshot = semantic.styles.clone();
    let numbering_snapshot = semantic.numbering.clone();
    for block in &mut semantic.blocks {
        resolve_block_references(
            block,
            styles_snapshot.as_ref(),
            numbering_snapshot.as_ref(),
            relationships,
        );
    }
    if let Some(numbering) = semantic.numbering.as_mut() {
        detect_numbering_reference_diagnostics(&semantic.blocks, numbering);
    }
    if let Some(stories) = semantic.stories.as_mut() {
        resolve_story_registry(stories, &semantic.blocks, relationships);
    }
    resolve_document_references(semantic, relationships);
    resolve_embedded_visual_objects(semantic, relationships, content_types, parts, objects);
    resolve_document_drawings(semantic, relationships, content_types, parts);
}

fn resolve_block_references(
    block: &mut SemanticBlock,
    styles: Option<&StyleRegistryProjection>,
    numbering: Option<&NumberingRegistryProjection>,
    relationships: &[OpcRelationship],
) {
    match block {
        SemanticBlock::Paragraph(paragraph) => {
            paragraph.resolved_style = resolve_paragraph_style(paragraph, styles);
            if let Some(reference) = paragraph.numbering.as_mut() {
                reference.resolved_level = resolve_numbering_reference(reference, numbering);
            }
            resolve_section_story_references(paragraph, relationships);
            for run in &mut paragraph.runs {
                run.resolved_style = resolve_run_style(run, styles);
                resolve_run_story_references(run, relationships);
            }
        }
        SemanticBlock::Table(table) => {
            for row in &mut table.rows {
                for cell in &mut row.cells {
                    for child in &mut cell.blocks {
                        resolve_block_references(child, styles, numbering, relationships);
                    }
                }
            }
        }
        SemanticBlock::TrackedChange(change) => {
            resolve_tracked_change_references(change, styles, numbering, relationships);
        }
        SemanticBlock::MceSelectedContent(content) => {
            for child in &mut content.blocks {
                resolve_block_references(child, styles, numbering, relationships);
            }
            resolve_mce_inline_references(&mut content.inlines, relationships);
        }
    }
}

fn resolve_tracked_change_references(
    change: &mut TrackedChange,
    styles: Option<&StyleRegistryProjection>,
    numbering: Option<&NumberingRegistryProjection>,
    relationships: &[OpcRelationship],
) {
    match &mut change.content {
        TrackedContent::Inline { items } => {
            for inline in items {
                if let SemanticInline::TrackedChange { change: inner } = inline {
                    resolve_tracked_change_references(inner, styles, numbering, relationships);
                }
            }
        }
        TrackedContent::Block { blocks } => {
            for block in blocks {
                resolve_block_references(block, styles, numbering, relationships);
            }
        }
        TrackedContent::PropertyChange { .. } => {}
    }
}

fn resolve_paragraph_style(
    paragraph: &SemanticParagraph,
    styles: Option<&StyleRegistryProjection>,
) -> Option<ResolvedStyleProjection> {
    let styles = styles?;
    if let Some(style_id) = paragraph.properties.style_id.as_ref() {
        return styles
            .definitions
            .iter()
            .find(|style| style.style_id == *style_id)
            .and_then(|style| style.resolved_style.clone());
    }
    styles
        .definitions
        .iter()
        .find(|style| style.style_type == StyleType::Paragraph && style.is_default)
        .and_then(|style| style.resolved_style.clone())
}

fn resolve_run_style(
    run: &SemanticRun,
    styles: Option<&StyleRegistryProjection>,
) -> Option<ResolvedStyleProjection> {
    let styles = styles?;
    run.properties.run_style_id.as_ref().and_then(|style_id| {
        styles
            .definitions
            .iter()
            .find(|style| style.style_id == *style_id)
            .and_then(|style| style.resolved_style.clone())
    })
}

fn resolve_section_story_references(
    paragraph: &mut SemanticParagraph,
    relationships: &[OpcRelationship],
) {
    let mut seen = BTreeSet::new();
    for reference in &mut paragraph.section_story_references {
        let key = (
            reference.section_index,
            reference.kind,
            reference.relationship_id.clone(),
        );
        if !seen.insert(key) {
            continue;
        }
        if let Some(relationship) = relationships.iter().find(|relationship| {
            relationship.source_part.as_deref() == Some("word/document.xml")
                && relationship.relationship_id == reference.relationship_id
        }) {
            reference.target = relationship.target.clone();
            if relationship.target_mode == TargetMode::Internal {
                reference.resolved_part_path =
                    resolve_internal_target_path("word/document.xml", &relationship.target);
            }
        }
    }
}

fn resolve_run_story_references(run: &mut SemanticRun, relationships: &[OpcRelationship]) {
    for inline in &mut run.inlines {
        match inline {
            SemanticInline::FootnoteReference {
                note_id,
                resolved_part_path,
            } => {
                if resolved_part_path.is_none() {
                    *resolved_part_path =
                        resolve_story_part_for_note(relationships, "word/footnotes.xml", note_id);
                }
            }
            SemanticInline::EndnoteReference {
                note_id,
                resolved_part_path,
            } => {
                if resolved_part_path.is_none() {
                    *resolved_part_path =
                        resolve_story_part_for_note(relationships, "word/endnotes.xml", note_id);
                }
            }
            SemanticInline::CommentReference {
                comment_id,
                resolved_part_path,
            } => {
                if resolved_part_path.is_none() {
                    *resolved_part_path = resolve_story_part_for_comment(
                        relationships,
                        "word/comments.xml",
                        comment_id,
                    );
                }
            }
            SemanticInline::MceSelectedContent(content) => {
                resolve_mce_inline_references(&mut content.inlines, relationships);
                for child in &mut content.blocks {
                    resolve_block_references(child, None, None, relationships);
                }
            }
            SemanticInline::Hyperlink(hyperlink) => {
                resolve_mce_inline_references(&mut hyperlink.children, relationships);
            }
            SemanticInline::Field(field) => {
                resolve_mce_inline_references(&mut field.result.children, relationships);
            }
            SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. }
            | SemanticInline::Text(_)
            | SemanticInline::BookmarkStart(_)
            | SemanticInline::BookmarkEnd(_)
            | SemanticInline::Drawing(_)
            | SemanticInline::EmbeddedVisualObject(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::TrackedChange { .. } => {}
        }
    }
}

fn resolve_mce_inline_references(
    inlines: &mut [SemanticInline],
    relationships: &[OpcRelationship],
) {
    for inline in inlines {
        match inline {
            SemanticInline::TrackedChange { change } => {
                resolve_tracked_change_references(change, None, None, relationships);
            }
            SemanticInline::MceSelectedContent(content) => {
                resolve_mce_inline_references(&mut content.inlines, relationships);
                for child in &mut content.blocks {
                    resolve_block_references(child, None, None, relationships);
                }
            }
            SemanticInline::Hyperlink(hyperlink) => {
                resolve_mce_inline_references(&mut hyperlink.children, relationships);
            }
            SemanticInline::Field(field) => {
                resolve_mce_inline_references(&mut field.result.children, relationships);
            }
            SemanticInline::Text(_)
            | SemanticInline::BookmarkStart(_)
            | SemanticInline::BookmarkEnd(_)
            | SemanticInline::Drawing(_)
            | SemanticInline::EmbeddedVisualObject(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::FootnoteReference { .. }
            | SemanticInline::EndnoteReference { .. }
            | SemanticInline::CommentReference { .. }
            | SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. } => {}
        }
    }
}

fn resolve_story_part_for_note(
    _relationships: &[OpcRelationship],
    default_part: &str,
    _note_id: &str,
) -> Option<String> {
    Some(default_part.to_owned())
}

fn resolve_story_part_for_comment(
    _relationships: &[OpcRelationship],
    default_part: &str,
    _comment_id: &str,
) -> Option<String> {
    Some(default_part.to_owned())
}

fn resolve_document_references(semantic: &mut SemanticDocument, relationships: &[OpcRelationship]) {
    let mut projection = DocumentReferencesProjection {
        source_part: semantic.source_part.clone(),
        hyperlinks: Vec::new(),
        bookmarks: Vec::new(),
        bookmark_ranges: Vec::new(),
        fields: Vec::new(),
        cross_references: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut bookmark_starts = BTreeMap::<(String, String), BookmarkProjection>::new();
    let mut bookmark_ends = BTreeMap::<(String, String), BookmarkProjection>::new();
    let mut bookmark_names = BTreeMap::<(String, String), Vec<String>>::new();

    collect_reference_phase_one(
        &mut semantic.blocks,
        relationships,
        &mut projection,
        &mut bookmark_starts,
        &mut bookmark_ends,
        &mut bookmark_names,
    );
    if let Some(stories) = semantic.stories.as_mut() {
        for part in &mut stories.parts {
            collect_reference_phase_one(
                &mut part.blocks,
                relationships,
                &mut projection,
                &mut bookmark_starts,
                &mut bookmark_ends,
                &mut bookmark_names,
            );
            for note in &mut part.notes {
                collect_reference_phase_one(
                    &mut note.blocks,
                    relationships,
                    &mut projection,
                    &mut bookmark_starts,
                    &mut bookmark_ends,
                    &mut bookmark_names,
                );
            }
            for comment in &mut part.comments {
                collect_reference_phase_one(
                    &mut comment.blocks,
                    relationships,
                    &mut projection,
                    &mut bookmark_starts,
                    &mut bookmark_ends,
                    &mut bookmark_names,
                );
            }
        }
    }

    build_bookmark_ranges(
        &bookmark_starts,
        &bookmark_ends,
        &bookmark_names,
        &mut projection,
    );

    collect_reference_phase_two(&mut semantic.blocks, &bookmark_names, &mut projection);
    if let Some(stories) = semantic.stories.as_mut() {
        for part in &mut stories.parts {
            collect_reference_phase_two(&mut part.blocks, &bookmark_names, &mut projection);
            for note in &mut part.notes {
                collect_reference_phase_two(&mut note.blocks, &bookmark_names, &mut projection);
            }
            for comment in &mut part.comments {
                collect_reference_phase_two(&mut comment.blocks, &bookmark_names, &mut projection);
            }
        }
    }

    projection.hyperlinks.sort_by(|left, right| {
        left.source_anchor
            .source_part_path
            .cmp(&right.source_anchor.source_part_path)
            .then(
                left.source_anchor
                    .xml_path
                    .cmp(&right.source_anchor.xml_path),
            )
    });
    projection.bookmarks.sort_by(|left, right| {
        left.source_anchor
            .source_part_path
            .cmp(&right.source_anchor.source_part_path)
            .then(
                left.source_anchor
                    .xml_path
                    .cmp(&right.source_anchor.xml_path),
            )
    });
    projection.bookmark_ranges.sort_by(|left, right| {
        left.source_part
            .cmp(&right.source_part)
            .then(left.bookmark_id.cmp(&right.bookmark_id))
    });
    projection.fields.sort_by(|left, right| {
        left.source_anchor
            .source_part_path
            .cmp(&right.source_anchor.source_part_path)
            .then(
                left.source_anchor
                    .xml_path
                    .cmp(&right.source_anchor.xml_path),
            )
    });
    projection.cross_references.sort_by(|left, right| {
        left.source_anchor
            .source_part_path
            .cmp(&right.source_anchor.source_part_path)
            .then(
                left.source_anchor
                    .xml_path
                    .cmp(&right.source_anchor.xml_path),
            )
    });
    projection
        .diagnostics
        .sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    semantic.references = Some(projection);
}

fn resolve_document_drawings(
    semantic: &mut SemanticDocument,
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
) {
    let mut projection = DrawingRegistryProjection {
        source_part: semantic.source_part.clone(),
        drawings: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut doc_pr_ids = BTreeMap::<String, SourceAnchor>::new();
    collect_drawings_from_blocks(
        &mut semantic.blocks,
        relationships,
        content_types,
        parts,
        &mut projection,
        &mut doc_pr_ids,
    );
    if let Some(stories) = semantic.stories.as_mut() {
        for part in &mut stories.parts {
            collect_drawings_from_blocks(
                &mut part.blocks,
                relationships,
                content_types,
                parts,
                &mut projection,
                &mut doc_pr_ids,
            );
            for note in &mut part.notes {
                collect_drawings_from_blocks(
                    &mut note.blocks,
                    relationships,
                    content_types,
                    parts,
                    &mut projection,
                    &mut doc_pr_ids,
                );
            }
            for comment in &mut part.comments {
                collect_drawings_from_blocks(
                    &mut comment.blocks,
                    relationships,
                    content_types,
                    parts,
                    &mut projection,
                    &mut doc_pr_ids,
                );
            }
        }
    }
    projection.drawings.sort_by(|left, right| {
        left.source_anchor
            .source_part_path
            .cmp(&right.source_anchor.source_part_path)
            .then(
                left.source_anchor
                    .xml_path
                    .cmp(&right.source_anchor.xml_path),
            )
    });
    projection
        .diagnostics
        .sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    semantic.drawings = Some(projection);
}

fn resolve_embedded_visual_objects(
    semantic: &mut SemanticDocument,
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    objects: &BTreeMap<String, Vec<u8>>,
) {
    let mut projection = EmbeddedVisualObjectsProjection {
        source_part: semantic.source_part.clone(),
        objects: Vec::new(),
        diagnostics: Vec::new(),
    };
    collect_embedded_visual_objects_from_blocks(
        &mut semantic.blocks,
        relationships,
        content_types,
        parts,
        objects,
        &mut projection,
    );
    if let Some(stories) = semantic.stories.as_mut() {
        for part in &mut stories.parts {
            collect_embedded_visual_objects_from_blocks(
                &mut part.blocks,
                relationships,
                content_types,
                parts,
                objects,
                &mut projection,
            );
            for note in &mut part.notes {
                collect_embedded_visual_objects_from_blocks(
                    &mut note.blocks,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    &mut projection,
                );
            }
            for comment in &mut part.comments {
                collect_embedded_visual_objects_from_blocks(
                    &mut comment.blocks,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    &mut projection,
                );
            }
        }
    }
    projection.objects.sort_by(|left, right| {
        left.source_anchor
            .source_part_path
            .cmp(&right.source_anchor.source_part_path)
            .then(
                left.source_anchor
                    .xml_path
                    .cmp(&right.source_anchor.xml_path),
            )
    });
    projection
        .diagnostics
        .sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
    semantic.embedded_visual_objects = Some(projection);
}

fn collect_embedded_visual_objects_from_blocks(
    blocks: &mut [SemanticBlock],
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    objects: &BTreeMap<String, Vec<u8>>,
    projection: &mut EmbeddedVisualObjectsProjection,
) {
    for block in blocks {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                for run in &mut paragraph.runs {
                    collect_embedded_visual_objects_from_inlines(
                        &mut run.inlines,
                        relationships,
                        content_types,
                        parts,
                        objects,
                        projection,
                    );
                }
            }
            SemanticBlock::Table(table) => {
                for row in &mut table.rows {
                    for cell in &mut row.cells {
                        collect_embedded_visual_objects_from_blocks(
                            &mut cell.blocks,
                            relationships,
                            content_types,
                            parts,
                            objects,
                            projection,
                        );
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => match &mut change.content {
                TrackedContent::Inline { items } => collect_embedded_visual_objects_from_inlines(
                    items,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    projection,
                ),
                TrackedContent::Block { blocks } => collect_embedded_visual_objects_from_blocks(
                    blocks,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    projection,
                ),
                TrackedContent::PropertyChange { .. } => {}
            },
            SemanticBlock::MceSelectedContent(content) => {
                collect_embedded_visual_objects_from_blocks(
                    &mut content.blocks,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    projection,
                );
                collect_embedded_visual_objects_from_inlines(
                    &mut content.inlines,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    projection,
                );
            }
        }
    }
}

fn collect_embedded_visual_objects_from_inlines(
    inlines: &mut [SemanticInline],
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    objects: &BTreeMap<String, Vec<u8>>,
    projection: &mut EmbeddedVisualObjectsProjection,
) {
    for inline in inlines {
        match inline {
            SemanticInline::Drawing(drawing) => {
                for object in &mut drawing.embedded_visual_objects {
                    resolve_embedded_visual_object_targets(
                        object,
                        relationships,
                        content_types,
                        parts,
                        objects,
                    );
                    projection.diagnostics.extend(object.diagnostics.clone());
                    projection.objects.push(object.clone());
                }
            }
            SemanticInline::EmbeddedVisualObject(object) => {
                resolve_embedded_visual_object_targets(
                    object,
                    relationships,
                    content_types,
                    parts,
                    objects,
                );
                projection.diagnostics.extend(object.diagnostics.clone());
                projection.objects.push(object.clone());
            }
            SemanticInline::Hyperlink(hyperlink) => collect_embedded_visual_objects_from_inlines(
                &mut hyperlink.children,
                relationships,
                content_types,
                parts,
                objects,
                projection,
            ),
            SemanticInline::Field(field) => collect_embedded_visual_objects_from_inlines(
                &mut field.result.children,
                relationships,
                content_types,
                parts,
                objects,
                projection,
            ),
            SemanticInline::TrackedChange { change } => match &mut change.content {
                TrackedContent::Inline { items } => collect_embedded_visual_objects_from_inlines(
                    items,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    projection,
                ),
                TrackedContent::Block { blocks } => collect_embedded_visual_objects_from_blocks(
                    blocks,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    projection,
                ),
                TrackedContent::PropertyChange { .. } => {}
            },
            SemanticInline::MceSelectedContent(content) => {
                collect_embedded_visual_objects_from_blocks(
                    &mut content.blocks,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    projection,
                );
                collect_embedded_visual_objects_from_inlines(
                    &mut content.inlines,
                    relationships,
                    content_types,
                    parts,
                    objects,
                    projection,
                );
            }
            SemanticInline::Text(_)
            | SemanticInline::BookmarkStart(_)
            | SemanticInline::BookmarkEnd(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::FootnoteReference { .. }
            | SemanticInline::EndnoteReference { .. }
            | SemanticInline::CommentReference { .. }
            | SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. } => {}
        }
    }
}

fn resolve_embedded_visual_object_targets(
    object: &mut EmbeddedVisualObjectProjection,
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    blobs: &BTreeMap<String, Vec<u8>>,
) {
    for target in &mut object.targets {
        resolve_embedded_object_target(
            &object.source_anchor,
            object.kind,
            target,
            relationships,
            content_types,
            parts,
            &mut object.diagnostics,
        );
    }
    if let Some(relationship_id) = object.preview_image_relationship_id.as_deref() {
        if let Some(relationship) = resolve_relationship(
            relationships,
            &object.source_anchor.source_part_path,
            relationship_id,
        ) {
            if relationship.relationship_type == IMAGE_RELATIONSHIP_TYPE
                && relationship.target_mode == TargetMode::Internal
            {
                if let Some(part_path) = resolve_internal_target_path(
                    &object.source_anchor.source_part_path,
                    &relationship.target,
                ) {
                    object.preview_image =
                        build_embedded_resource(content_types, parts, &part_path);
                }
            }
        } else {
            object.diagnostics.push(embedded_object_diag(
                "CVN_EMBEDDED_OBJECT_RELATIONSHIP_MISSING",
                &object.source_anchor.xml_path,
                format!("preview image relationship `{relationship_id}` is not defined"),
            ));
        }
    }

    match object.kind {
        EmbeddedVisualObjectKind::Chart => {
            if let Some(target) = object
                .targets
                .iter()
                .find(|target| target.role.as_deref() == Some("chart_part"))
            {
                if let Some(resource) = target.resource.as_ref() {
                    object.chart = Some(parse_chart_projection(
                        resource,
                        &object.source_anchor,
                        relationships,
                        content_types,
                        parts,
                        blobs,
                        &mut object.diagnostics,
                    ));
                }
            }
            object
                .risk_class
                .get_or_insert_with(|| "passive_chart".to_owned());
        }
        EmbeddedVisualObjectKind::SmartartDiagram => {
            object.diagram = Some(parse_diagram_projection(
                object,
                relationships,
                content_types,
                parts,
                blobs,
            ));
            object
                .risk_class
                .get_or_insert_with(|| "passive_diagram".to_owned());
            object.diagnostics.push(embedded_object_diag(
                "CVN_DIAGRAM_LAYOUT_NOT_EVALUATED",
                &object.source_anchor.xml_path,
                "diagram layout is preserved but not evaluated",
            ));
        }
        EmbeddedVisualObjectKind::EmbeddedPackage => {
            if let Some(target) = object
                .targets
                .iter()
                .find(|target| target.role.as_deref() == Some("object"))
            {
                object.package_resource = target.resource.clone();
            }
        }
        EmbeddedVisualObjectKind::OleLinkedObject
        | EmbeddedVisualObjectKind::OleEmbeddedObject
        | EmbeddedVisualObjectKind::ActivexBlocked
        | EmbeddedVisualObjectKind::UnsupportedVisualObject
        | EmbeddedVisualObjectKind::Unresolved => {}
    }
}

fn collect_part_bytes<'a>(
    resource: &EmbeddedResourceProjection,
    blobs: &'a BTreeMap<String, Vec<u8>>,
) -> Option<&'a [u8]> {
    blobs
        .get(resource.object_digest.as_deref()?)
        .map(Vec::as_slice)
}

fn resolve_embedded_object_target(
    anchor: &SourceAnchor,
    object_kind: EmbeddedVisualObjectKind,
    target: &mut EmbeddedObjectTarget,
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    diagnostics: &mut Vec<EmbeddedVisualObjectDiagnostic>,
) {
    let Some(relationship_id) = target.relationship_id.as_deref() else {
        return;
    };
    let Some(relationship) =
        resolve_relationship(relationships, &anchor.source_part_path, relationship_id)
    else {
        diagnostics.push(embedded_object_diag(
            "CVN_EMBEDDED_OBJECT_RELATIONSHIP_MISSING",
            &anchor.xml_path,
            format!("relationship `{relationship_id}` is not defined"),
        ));
        target.kind = EmbeddedObjectTargetKind::Unresolved;
        return;
    };

    target.relationship_type = Some(relationship.relationship_type.clone());
    target.target_mode = Some(relationship.target_mode);
    target.raw_target = Some(relationship.target.clone());
    if let Some(expected) =
        expected_relationship_type_for_target(object_kind, target.role.as_deref())
    {
        if relationship.relationship_type != expected {
            diagnostics.push(embedded_object_diag(
                "CVN_EMBEDDED_OBJECT_RELATIONSHIP_TYPE_MISMATCH",
                &anchor.xml_path,
                format!(
                    "relationship `{relationship_id}` has unexpected type `{}`",
                    relationship.relationship_type
                ),
            ));
        }
    }

    match relationship.target_mode {
        TargetMode::External => {
            target.kind = EmbeddedObjectTargetKind::ExternalRelationship;
            target.risk_class = Some(classify_embedded_visual_object_risk(
                object_kind,
                &relationship.target,
            ));
            diagnostics.push(embedded_object_diag(
                "CVN_EMBEDDED_OBJECT_EXTERNAL_TARGET_INERT",
                &anchor.xml_path,
                "external embedded-object target is preserved inertly",
            ));
            if matches!(
                object_kind,
                EmbeddedVisualObjectKind::OleLinkedObject
                    | EmbeddedVisualObjectKind::ActivexBlocked
            ) {
                diagnostics.push(embedded_object_diag(
                    "CVN_EMBEDDED_OBJECT_ACTIVE_CONTENT_BLOCKED",
                    &anchor.xml_path,
                    "active embedded content is preserved but blocked",
                ));
            }
        }
        TargetMode::Internal => {
            let Some(part_path) =
                resolve_internal_target_path(&anchor.source_part_path, &relationship.target)
            else {
                diagnostics.push(embedded_object_diag(
                    "CVN_EMBEDDED_OBJECT_PART_MISSING",
                    &anchor.xml_path,
                    format!(
                        "target `{}` does not resolve to a valid OPC part",
                        relationship.target
                    ),
                ));
                target.kind = EmbeddedObjectTargetKind::Unresolved;
                return;
            };
            target.resolved_part_path = Some(part_path.clone());
            target.kind = match object_kind {
                EmbeddedVisualObjectKind::OleEmbeddedObject
                | EmbeddedVisualObjectKind::EmbeddedPackage => {
                    EmbeddedObjectTargetKind::EmbeddedPart
                }
                _ => EmbeddedObjectTargetKind::InternalPart,
            };
            target.resource = build_embedded_resource(content_types, parts, &part_path);
            if target.resource.is_none() {
                diagnostics.push(embedded_object_diag(
                    if target
                        .role
                        .as_deref()
                        .unwrap_or_default()
                        .starts_with("diagram_")
                    {
                        "CVN_DIAGRAM_PART_MISSING"
                    } else {
                        "CVN_EMBEDDED_OBJECT_PART_MISSING"
                    },
                    &anchor.xml_path,
                    format!("target part `{part_path}` is not present"),
                ));
                target.kind = EmbeddedObjectTargetKind::Unresolved;
            }
        }
    }
}

fn resolve_relationship<'a>(
    relationships: &'a [OpcRelationship],
    source_part: &str,
    relationship_id: &str,
) -> Option<&'a OpcRelationship> {
    relationships.iter().find(|relationship| {
        relationship.source_part.as_deref() == Some(source_part)
            && relationship.relationship_id == relationship_id
    })
}

fn build_embedded_resource(
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    part_path: &str,
) -> Option<EmbeddedResourceProjection> {
    let part = parts.iter().find(|part| part.original_path == part_path)?;
    let content_type = part
        .content_type
        .clone()
        .or_else(|| resolve_content_type(content_types, part_path));
    Some(EmbeddedResourceProjection {
        part_path: Some(part.original_path.clone()),
        content_type: content_type.clone(),
        object_digest: Some(part.content_digest.clone()),
        length: Some(part.original_size),
        format_hint: content_type.as_deref().map(format_hint_for_content_type),
    })
}

fn format_hint_for_content_type(content_type: &str) -> String {
    if let Some((_, subtype)) = content_type.split_once('/') {
        subtype
            .trim()
            .trim_start_matches("vnd.")
            .trim_start_matches("ms-")
            .to_ascii_lowercase()
    } else {
        content_type.to_ascii_lowercase()
    }
}

fn classify_embedded_visual_object_risk(
    kind: EmbeddedVisualObjectKind,
    raw_target: &str,
) -> String {
    match kind {
        EmbeddedVisualObjectKind::Chart => "linked_external_object".to_owned(),
        EmbeddedVisualObjectKind::SmartartDiagram => "passive_diagram".to_owned(),
        EmbeddedVisualObjectKind::EmbeddedPackage => "embedded_office_package".to_owned(),
        EmbeddedVisualObjectKind::ActivexBlocked => "activex".to_owned(),
        EmbeddedVisualObjectKind::OleLinkedObject => {
            let base =
                classify_hyperlink_risk(raw_target).unwrap_or_else(|| "unknown_scheme".to_owned());
            if base == "ordinary_web" || base == "unknown_scheme" {
                "linked_external_object".to_owned()
            } else {
                base
            }
        }
        EmbeddedVisualObjectKind::OleEmbeddedObject => "embedded_binary_object".to_owned(),
        EmbeddedVisualObjectKind::UnsupportedVisualObject
        | EmbeddedVisualObjectKind::Unresolved => "unknown_embedded_object".to_owned(),
    }
}

fn expected_relationship_type_for_target(
    object_kind: EmbeddedVisualObjectKind,
    role: Option<&str>,
) -> Option<&'static str> {
    match (object_kind, role) {
        (EmbeddedVisualObjectKind::Chart, Some("chart_part")) => Some(CHART_RELATIONSHIP_TYPE),
        (EmbeddedVisualObjectKind::SmartartDiagram, Some("diagram_data")) => {
            Some(DIAGRAM_DATA_RELATIONSHIP_TYPE)
        }
        (EmbeddedVisualObjectKind::SmartartDiagram, Some("diagram_layout")) => {
            Some(DIAGRAM_LAYOUT_RELATIONSHIP_TYPE)
        }
        (EmbeddedVisualObjectKind::SmartartDiagram, Some("diagram_style")) => {
            Some(DIAGRAM_STYLE_RELATIONSHIP_TYPE)
        }
        (EmbeddedVisualObjectKind::SmartartDiagram, Some("diagram_colors")) => {
            Some(DIAGRAM_COLORS_RELATIONSHIP_TYPE)
        }
        (EmbeddedVisualObjectKind::EmbeddedPackage, Some("object")) => {
            Some(PACKAGE_RELATIONSHIP_TYPE)
        }
        (EmbeddedVisualObjectKind::ActivexBlocked, Some("object")) => {
            Some(CONTROL_RELATIONSHIP_TYPE)
        }
        (
            EmbeddedVisualObjectKind::OleEmbeddedObject | EmbeddedVisualObjectKind::OleLinkedObject,
            Some("object"),
        ) => Some(OLE_OBJECT_RELATIONSHIP_TYPE),
        _ => None,
    }
}

fn parse_chart_projection(
    resource: &EmbeddedResourceProjection,
    source_anchor: &SourceAnchor,
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    blobs: &BTreeMap<String, Vec<u8>>,
    diagnostics: &mut Vec<EmbeddedVisualObjectDiagnostic>,
) -> ChartProjection {
    let mut projection = ChartProjection {
        part_path: resource.part_path.clone(),
        content_type: resource.content_type.clone(),
        object_digest: resource.object_digest.clone(),
        length: resource.length,
        chart_type: "unknown".to_owned(),
        title: None,
        series: Vec::new(),
        embedded_workbook: None,
        external_data: None,
        external_data_auto_update: None,
    };
    let Some(bytes) = collect_part_bytes(resource, blobs) else {
        return projection;
    };
    let Some(part_path) = resource.part_path.as_deref() else {
        return projection;
    };

    let mut reader = Reader::from_reader(Cursor::new(bytes));
    let mut buffer = Vec::new();
    let mut namespace_stack = Vec::<BTreeMap<String, String>>::new();
    let mut tag_stack = Vec::<String>::new();
    let mut current_series: Option<ChartSeriesProjection> = None;
    let mut series_role: Option<&str> = None;
    let mut series_formula: Option<String> = None;
    let mut series_strings = Vec::<String>::new();
    let mut series_numbers = Vec::<String>::new();
    let mut title_text = String::new();
    let mut series_title = String::new();
    let mut external_data_id: Option<String> = None;
    let mut external_data_auto_update: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) => {
                namespace_stack.push(namespace_declarations(&event).unwrap_or_default());
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event).unwrap_or_default();
                tag_stack.push(name.local_name.clone());
                match name.local_name.as_str() {
                    "barChart" => projection.chart_type = "bar".to_owned(),
                    "lineChart" => projection.chart_type = "line".to_owned(),
                    "pieChart" => projection.chart_type = "pie".to_owned(),
                    "areaChart" => projection.chart_type = "area".to_owned(),
                    "scatterChart" => projection.chart_type = "scatter".to_owned(),
                    "doughnutChart" => projection.chart_type = "doughnut".to_owned(),
                    "radarChart" => projection.chart_type = "radar".to_owned(),
                    "surfaceChart" => projection.chart_type = "surface".to_owned(),
                    "stockChart" => projection.chart_type = "stock".to_owned(),
                    "bubbleChart" => projection.chart_type = "bubble".to_owned(),
                    "ser" => {
                        current_series = Some(ChartSeriesProjection {
                            title: None,
                            category_reference: None,
                            value_reference: None,
                        });
                        series_title.clear();
                    }
                    "cat" | "xVal" => {
                        series_role = Some("category");
                        series_formula = None;
                        series_strings.clear();
                        series_numbers.clear();
                    }
                    "val" | "yVal" => {
                        series_role = Some("value");
                        series_formula = None;
                        series_strings.clear();
                        series_numbers.clear();
                    }
                    "externalData" => {
                        external_data_id = attrs
                            .get("r:id")
                            .cloned()
                            .or_else(|| attrs.get("id").cloned());
                    }
                    "autoUpdate" => {
                        external_data_auto_update = attrs.get("val").cloned();
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(event)) => {
                namespace_stack.push(namespace_declarations(&event).unwrap_or_default());
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event).unwrap_or_default();
                match name.local_name.as_str() {
                    "externalData" => {
                        external_data_id = attrs
                            .get("r:id")
                            .cloned()
                            .or_else(|| attrs.get("id").cloned());
                    }
                    "autoUpdate" => {
                        external_data_auto_update = attrs.get("val").cloned();
                    }
                    _ => {}
                }
                namespace_stack.pop();
            }
            Ok(Event::Text(text)) => {
                let value = text
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                match tag_stack.last().map(String::as_str) {
                    Some("t") => {
                        if tag_stack.iter().any(|tag| tag == "title") {
                            title_text.push_str(&value);
                        } else if current_series.is_some()
                            && tag_stack.iter().any(|tag| tag == "tx")
                        {
                            series_title.push_str(&value);
                        } else if current_series.is_none()
                            && tag_stack.iter().any(|tag| tag == "pt")
                        {
                        }
                    }
                    Some("v")
                        if current_series.is_some()
                            && tag_stack.iter().any(|tag| tag == "tx")
                            && !tag_stack.iter().any(|tag| {
                                tag == "cat" || tag == "val" || tag == "xVal" || tag == "yVal"
                            }) =>
                    {
                        series_title.push_str(&value);
                    }
                    Some("f") if current_series.is_some() => {
                        series_formula = Some(value);
                    }
                    Some("v") if current_series.is_some() => match series_role {
                        Some("category") => series_strings.push(value),
                        Some("value") => series_numbers.push(value),
                        _ => {}
                    },
                    _ => {}
                }
            }
            Ok(Event::End(event)) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                match name.local_name.as_str() {
                    "title" => {
                        if !title_text.is_empty() {
                            projection.title = Some(ChartTitleProjection {
                                text: title_text.clone(),
                            });
                            title_text.clear();
                        }
                    }
                    "tx" => {
                        if let Some(series) = current_series.as_mut() {
                            if !series_title.is_empty() {
                                series.title = Some(series_title.clone());
                                series_title.clear();
                            }
                        }
                    }
                    "cat" | "xVal" => {
                        if let Some(series) = current_series.as_mut() {
                            series.category_reference = Some(ChartDataReferenceProjection {
                                formula: series_formula.take(),
                                cached_string_values: std::mem::take(&mut series_strings),
                                cached_numeric_values: std::mem::take(&mut series_numbers),
                            });
                        }
                        series_role = None;
                    }
                    "val" | "yVal" => {
                        if let Some(series) = current_series.as_mut() {
                            series.value_reference = Some(ChartDataReferenceProjection {
                                formula: series_formula.take(),
                                cached_string_values: std::mem::take(&mut series_strings),
                                cached_numeric_values: std::mem::take(&mut series_numbers),
                            });
                        }
                        series_role = None;
                    }
                    "ser" => {
                        if let Some(series) = current_series.take() {
                            if series
                                .category_reference
                                .as_ref()
                                .and_then(|value| value.formula.as_ref())
                                .is_some()
                                || series
                                    .value_reference
                                    .as_ref()
                                    .and_then(|value| value.formula.as_ref())
                                    .is_some()
                            {
                                diagnostics.push(embedded_object_diag(
                                    "CVN_CHART_FORMULA_NOT_EVALUATED",
                                    &source_anchor.xml_path,
                                    "chart formulas are preserved but not evaluated",
                                ));
                            }
                            projection.series.push(series);
                        }
                    }
                    _ => {}
                }
                tag_stack.pop();
                namespace_stack.pop();
            }
            Ok(Event::DocType(_)) => {
                diagnostics.push(embedded_object_diag(
                    "CVN_CHART_PART_MALFORMED",
                    &source_anchor.xml_path,
                    format!("chart part `{part_path}` contains a disallowed DOCTYPE"),
                ));
                break;
            }
            Ok(Event::Eof) => break,
            Err(_) => {
                diagnostics.push(embedded_object_diag(
                    "CVN_CHART_PART_MALFORMED",
                    &source_anchor.xml_path,
                    format!("chart part `{part_path}` could not be parsed"),
                ));
                break;
            }
            _ => {}
        }
        buffer.clear();
    }

    if let Some(workbook_rel) = relationships.iter().find(|relationship| {
        relationship.source_part.as_deref() == Some(part_path)
            && relationship.target_mode == TargetMode::Internal
            && relationship.relationship_type.contains("package")
    }) {
        if let Some(workbook_path) = resolve_internal_target_path(part_path, &workbook_rel.target) {
            projection.embedded_workbook =
                build_embedded_resource(content_types, parts, &workbook_path);
        }
    }
    if let Some(relationship_id) = external_data_id {
        let mut target = EmbeddedObjectTarget {
            kind: EmbeddedObjectTargetKind::Unresolved,
            role: Some("chart_external_data".to_owned()),
            relationship_id: Some(relationship_id.clone()),
            relationship_type: None,
            target_mode: None,
            raw_target: None,
            resolved_part_path: None,
            resource: None,
            risk_class: None,
        };
        if let Some(relationship) = resolve_relationship(relationships, part_path, &relationship_id)
        {
            target.relationship_type = Some(relationship.relationship_type.clone());
            target.target_mode = Some(relationship.target_mode);
            target.raw_target = Some(relationship.target.clone());
            match relationship.target_mode {
                TargetMode::External => {
                    target.kind = EmbeddedObjectTargetKind::ExternalRelationship;
                    target.risk_class = Some("linked_external_object".to_owned());
                }
                TargetMode::Internal => {
                    if let Some(target_path) =
                        resolve_internal_target_path(part_path, &relationship.target)
                    {
                        target.kind = EmbeddedObjectTargetKind::InternalPart;
                        target.resolved_part_path = Some(target_path.clone());
                        target.resource =
                            build_embedded_resource(content_types, parts, &target_path);
                    }
                }
            }
            diagnostics.push(embedded_object_diag(
                "CVN_CHART_EXTERNAL_DATA_INERT",
                &source_anchor.xml_path,
                "chart externalData is preserved but not updated",
            ));
        }
        projection.external_data = Some(target);
        projection.external_data_auto_update = external_data_auto_update;
    }
    projection
}

fn parse_diagram_projection(
    object: &EmbeddedVisualObjectProjection,
    _relationships: &[OpcRelationship],
    _content_types: &ContentTypesProjection,
    _parts: &[OpcPart],
    blobs: &BTreeMap<String, Vec<u8>>,
) -> DiagramProjection {
    let mut projection = DiagramProjection {
        data_part: None,
        layout_part: None,
        style_part: None,
        colors_part: None,
        points: Vec::new(),
        connections: Vec::new(),
        texts: Vec::new(),
    };
    for target in &object.targets {
        let reference = DiagramPartReferenceProjection {
            role: target.role.clone().unwrap_or_default(),
            relationship_id: target.relationship_id.clone(),
            part_path: target
                .resource
                .as_ref()
                .and_then(|resource| resource.part_path.clone()),
            content_type: target
                .resource
                .as_ref()
                .and_then(|resource| resource.content_type.clone()),
            object_digest: target
                .resource
                .as_ref()
                .and_then(|resource| resource.object_digest.clone()),
            length: target
                .resource
                .as_ref()
                .and_then(|resource| resource.length),
        };
        match target.role.as_deref() {
            Some("diagram_data") => projection.data_part = Some(reference),
            Some("diagram_layout") => projection.layout_part = Some(reference),
            Some("diagram_style") => projection.style_part = Some(reference),
            Some("diagram_colors") => projection.colors_part = Some(reference),
            _ => {}
        }
    }
    if let Some(data_part) = projection.data_part.as_ref() {
        if let Some(bytes) = collect_part_bytes(
            &EmbeddedResourceProjection {
                part_path: data_part.part_path.clone(),
                content_type: data_part.content_type.clone(),
                object_digest: data_part.object_digest.clone(),
                length: data_part.length,
                format_hint: None,
            },
            blobs,
        ) {
            let mut reader = Reader::from_reader(Cursor::new(bytes));
            let mut buffer = Vec::new();
            let mut namespace_stack = Vec::<BTreeMap<String, String>>::new();
            let mut tag_stack = Vec::<String>::new();
            loop {
                match reader.read_event_into(&mut buffer) {
                    Ok(Event::Start(event)) => {
                        namespace_stack.push(namespace_declarations(&event).unwrap_or_default());
                        let name = qname(event.name().as_ref(), &namespace_stack);
                        let attrs = attributes(&reader, &event).unwrap_or_default();
                        tag_stack.push(name.local_name.clone());
                        match name.local_name.as_str() {
                            "pt" => {
                                if let Some(id) = attrs
                                    .get("modelId")
                                    .cloned()
                                    .or_else(|| attrs.get("id").cloned())
                                {
                                    projection.points.push(id);
                                }
                            }
                            "cxn" => {
                                let id = attrs
                                    .get("modelId")
                                    .cloned()
                                    .or_else(|| attrs.get("id").cloned())
                                    .unwrap_or_default();
                                let src = attrs.get("srcId").cloned().unwrap_or_default();
                                let dst = attrs.get("destId").cloned().unwrap_or_default();
                                projection.connections.push(format!("{id}:{src}:{dst}"));
                            }
                            _ => {}
                        }
                    }
                    Ok(Event::Text(text)) => {
                        if tag_stack.last().map(String::as_str) == Some("t") {
                            let value = text
                                .decode()
                                .map(|value| value.into_owned())
                                .unwrap_or_default();
                            if !value.is_empty() {
                                projection.texts.push(value);
                            }
                        }
                    }
                    Ok(Event::End(_)) => {
                        tag_stack.pop();
                        namespace_stack.pop();
                    }
                    Ok(Event::Empty(event)) => {
                        namespace_stack.push(namespace_declarations(&event).unwrap_or_default());
                        let name = qname(event.name().as_ref(), &namespace_stack);
                        let attrs = attributes(&reader, &event).unwrap_or_default();
                        match name.local_name.as_str() {
                            "pt" => {
                                if let Some(id) = attrs
                                    .get("modelId")
                                    .cloned()
                                    .or_else(|| attrs.get("id").cloned())
                                {
                                    projection.points.push(id);
                                }
                            }
                            "cxn" => {
                                let id = attrs
                                    .get("modelId")
                                    .cloned()
                                    .or_else(|| attrs.get("id").cloned())
                                    .unwrap_or_default();
                                let src = attrs.get("srcId").cloned().unwrap_or_default();
                                let dst = attrs.get("destId").cloned().unwrap_or_default();
                                projection.connections.push(format!("{id}:{src}:{dst}"));
                            }
                            _ => {}
                        }
                        namespace_stack.pop();
                    }
                    Ok(Event::Eof) => break,
                    _ => {}
                }
                buffer.clear();
            }
        }
    }
    projection
}

fn collect_drawings_from_blocks(
    blocks: &mut [SemanticBlock],
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    projection: &mut DrawingRegistryProjection,
    doc_pr_ids: &mut BTreeMap<String, SourceAnchor>,
) {
    for block in blocks {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                for run in &mut paragraph.runs {
                    collect_drawings_from_inlines(
                        &mut run.inlines,
                        relationships,
                        content_types,
                        parts,
                        projection,
                        doc_pr_ids,
                    );
                }
            }
            SemanticBlock::Table(table) => {
                for row in &mut table.rows {
                    for cell in &mut row.cells {
                        collect_drawings_from_blocks(
                            &mut cell.blocks,
                            relationships,
                            content_types,
                            parts,
                            projection,
                            doc_pr_ids,
                        );
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => match &mut change.content {
                TrackedContent::Inline { items } => collect_drawings_from_inlines(
                    items,
                    relationships,
                    content_types,
                    parts,
                    projection,
                    doc_pr_ids,
                ),
                TrackedContent::Block { blocks } => collect_drawings_from_blocks(
                    blocks,
                    relationships,
                    content_types,
                    parts,
                    projection,
                    doc_pr_ids,
                ),
                TrackedContent::PropertyChange { .. } => {}
            },
            SemanticBlock::MceSelectedContent(content) => {
                collect_drawings_from_blocks(
                    &mut content.blocks,
                    relationships,
                    content_types,
                    parts,
                    projection,
                    doc_pr_ids,
                );
                collect_drawings_from_inlines(
                    &mut content.inlines,
                    relationships,
                    content_types,
                    parts,
                    projection,
                    doc_pr_ids,
                );
            }
        }
    }
}

fn collect_drawings_from_inlines(
    inlines: &mut [SemanticInline],
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
    projection: &mut DrawingRegistryProjection,
    doc_pr_ids: &mut BTreeMap<String, SourceAnchor>,
) {
    for inline in inlines {
        match inline {
            SemanticInline::Drawing(drawing) => {
                resolve_drawing_targets(drawing, relationships, content_types, parts);
                if let Some(metadata) = drawing
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.doc_pr_id.as_ref())
                {
                    if let Some(previous) =
                        doc_pr_ids.insert(metadata.clone(), drawing.source_anchor.clone())
                    {
                        let message =
                            format!("docPr id `{metadata}` is duplicated across drawings");
                        projection.diagnostics.push(drawing_diag(
                            "CVN_DRAWING_DOC_PR_DUPLICATE_ID",
                            &drawing.source_anchor.xml_path,
                            message.clone(),
                        ));
                        projection.diagnostics.push(drawing_diag(
                            "CVN_DRAWING_DOC_PR_DUPLICATE_ID",
                            &previous.xml_path,
                            message,
                        ));
                    }
                }
                projection.diagnostics.extend(drawing.diagnostics.clone());
                projection.drawings.push(drawing.clone());
            }
            SemanticInline::Hyperlink(hyperlink) => collect_drawings_from_inlines(
                &mut hyperlink.children,
                relationships,
                content_types,
                parts,
                projection,
                doc_pr_ids,
            ),
            SemanticInline::Field(field) => collect_drawings_from_inlines(
                &mut field.result.children,
                relationships,
                content_types,
                parts,
                projection,
                doc_pr_ids,
            ),
            SemanticInline::TrackedChange { change } => match &mut change.content {
                TrackedContent::Inline { items } => collect_drawings_from_inlines(
                    items,
                    relationships,
                    content_types,
                    parts,
                    projection,
                    doc_pr_ids,
                ),
                TrackedContent::Block { blocks } => collect_drawings_from_blocks(
                    blocks,
                    relationships,
                    content_types,
                    parts,
                    projection,
                    doc_pr_ids,
                ),
                TrackedContent::PropertyChange { .. } => {}
            },
            SemanticInline::MceSelectedContent(content) => {
                collect_drawings_from_blocks(
                    &mut content.blocks,
                    relationships,
                    content_types,
                    parts,
                    projection,
                    doc_pr_ids,
                );
                collect_drawings_from_inlines(
                    &mut content.inlines,
                    relationships,
                    content_types,
                    parts,
                    projection,
                    doc_pr_ids,
                );
            }
            SemanticInline::Text(_)
            | SemanticInline::BookmarkStart(_)
            | SemanticInline::BookmarkEnd(_)
            | SemanticInline::EmbeddedVisualObject(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::FootnoteReference { .. }
            | SemanticInline::EndnoteReference { .. }
            | SemanticInline::CommentReference { .. }
            | SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. } => {}
        }
    }
}

fn resolve_drawing_targets(
    drawing: &mut DrawingProjection,
    relationships: &[OpcRelationship],
    content_types: &ContentTypesProjection,
    parts: &[OpcPart],
) {
    for target in &mut drawing.targets {
        let Some(relationship_id) = target.relationship_id.as_ref() else {
            continue;
        };
        let Some(relationship) = relationships.iter().find(|relationship| {
            relationship.source_part.as_deref()
                == Some(drawing.source_anchor.source_part_path.as_str())
                && relationship.relationship_id == *relationship_id
        }) else {
            drawing.diagnostics.push(drawing_diag(
                "CVN_DRAWING_RELATIONSHIP_MISSING",
                &drawing.source_anchor.xml_path,
                format!("relationship `{relationship_id}` is not defined"),
            ));
            target.kind = DrawingTargetKind::Unresolved;
            continue;
        };

        target.relationship_type = Some(relationship.relationship_type.clone());
        target.target_mode = Some(relationship.target_mode);
        target.raw_target = Some(relationship.target.clone());

        if relationship.relationship_type != IMAGE_RELATIONSHIP_TYPE {
            drawing.diagnostics.push(drawing_diag(
                "CVN_DRAWING_RELATIONSHIP_TYPE_MISMATCH",
                &drawing.source_anchor.xml_path,
                format!(
                    "relationship `{relationship_id}` has unexpected type `{}`",
                    relationship.relationship_type
                ),
            ));
        }

        match relationship.target_mode {
            TargetMode::External => {
                target.kind = DrawingTargetKind::ExternalRelationship;
                target.risk_class = classify_hyperlink_risk(&relationship.target);
                drawing.diagnostics.push(drawing_diag(
                    "CVN_DRAWING_EXTERNAL_TARGET_INERT",
                    &drawing.source_anchor.xml_path,
                    "external image target is preserved inertly",
                ));
            }
            TargetMode::Internal => {
                target.kind = DrawingTargetKind::EmbeddedPart;
                target.resolved_part_path = resolve_internal_target_path(
                    &drawing.source_anchor.source_part_path,
                    &relationship.target,
                );
                let Some(part_path) = target.resolved_part_path.as_ref() else {
                    drawing.diagnostics.push(drawing_diag(
                        "CVN_DRAWING_MEDIA_PART_MISSING",
                        &drawing.source_anchor.xml_path,
                        format!(
                            "target `{}` does not resolve to a valid OPC part",
                            relationship.target
                        ),
                    ));
                    target.kind = DrawingTargetKind::Unresolved;
                    continue;
                };
                let Some(part) = parts.iter().find(|part| part.original_path == *part_path) else {
                    drawing.diagnostics.push(drawing_diag(
                        "CVN_DRAWING_MEDIA_PART_MISSING",
                        &drawing.source_anchor.xml_path,
                        format!("media part `{part_path}` is not present"),
                    ));
                    target.kind = DrawingTargetKind::Unresolved;
                    continue;
                };
                let content_type = part
                    .content_type
                    .clone()
                    .or_else(|| resolve_content_type(content_types, part_path));
                if content_type.is_none() {
                    drawing.diagnostics.push(drawing_diag(
                        "CVN_DRAWING_CONTENT_TYPE_MISSING",
                        &drawing.source_anchor.xml_path,
                        format!("content type for `{part_path}` is not defined"),
                    ));
                }
                target.resource = Some(ImageResourceProjection {
                    part_path: Some(part.original_path.clone()),
                    content_type,
                    object_digest: Some(part.content_digest.clone()),
                    length: Some(part.original_size),
                });
            }
        }
    }
}

fn collect_reference_phase_one(
    blocks: &mut [SemanticBlock],
    relationships: &[OpcRelationship],
    projection: &mut DocumentReferencesProjection,
    bookmark_starts: &mut BTreeMap<(String, String), BookmarkProjection>,
    bookmark_ends: &mut BTreeMap<(String, String), BookmarkProjection>,
    bookmark_names: &mut BTreeMap<(String, String), Vec<String>>,
) {
    for block in blocks {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                for run in &mut paragraph.runs {
                    collect_reference_inlines_phase_one(
                        &mut run.inlines,
                        relationships,
                        projection,
                        bookmark_starts,
                        bookmark_ends,
                        bookmark_names,
                    );
                }
            }
            SemanticBlock::Table(table) => {
                for row in &mut table.rows {
                    for cell in &mut row.cells {
                        collect_reference_phase_one(
                            &mut cell.blocks,
                            relationships,
                            projection,
                            bookmark_starts,
                            bookmark_ends,
                            bookmark_names,
                        );
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => collect_reference_change_phase_one(
                change,
                relationships,
                projection,
                bookmark_starts,
                bookmark_ends,
                bookmark_names,
            ),
            SemanticBlock::MceSelectedContent(content) => {
                collect_reference_phase_one(
                    &mut content.blocks,
                    relationships,
                    projection,
                    bookmark_starts,
                    bookmark_ends,
                    bookmark_names,
                );
                collect_reference_inlines_phase_one(
                    &mut content.inlines,
                    relationships,
                    projection,
                    bookmark_starts,
                    bookmark_ends,
                    bookmark_names,
                );
            }
        }
    }
}

fn collect_reference_change_phase_one(
    change: &mut TrackedChange,
    relationships: &[OpcRelationship],
    projection: &mut DocumentReferencesProjection,
    bookmark_starts: &mut BTreeMap<(String, String), BookmarkProjection>,
    bookmark_ends: &mut BTreeMap<(String, String), BookmarkProjection>,
    bookmark_names: &mut BTreeMap<(String, String), Vec<String>>,
) {
    match &mut change.content {
        TrackedContent::Inline { items } => collect_reference_inlines_phase_one(
            items,
            relationships,
            projection,
            bookmark_starts,
            bookmark_ends,
            bookmark_names,
        ),
        TrackedContent::Block { blocks } => collect_reference_phase_one(
            blocks,
            relationships,
            projection,
            bookmark_starts,
            bookmark_ends,
            bookmark_names,
        ),
        TrackedContent::PropertyChange { .. } => {}
    }
}

fn collect_reference_inlines_phase_one(
    inlines: &mut [SemanticInline],
    relationships: &[OpcRelationship],
    projection: &mut DocumentReferencesProjection,
    bookmark_starts: &mut BTreeMap<(String, String), BookmarkProjection>,
    bookmark_ends: &mut BTreeMap<(String, String), BookmarkProjection>,
    bookmark_names: &mut BTreeMap<(String, String), Vec<String>>,
) {
    for inline in inlines {
        match inline {
            SemanticInline::Hyperlink(hyperlink) => {
                resolve_hyperlink(hyperlink, relationships, &mut projection.diagnostics);
                collect_reference_inlines_phase_one(
                    &mut hyperlink.children,
                    relationships,
                    projection,
                    bookmark_starts,
                    bookmark_ends,
                    bookmark_names,
                );
                projection.hyperlinks.push(hyperlink.clone());
            }
            SemanticInline::BookmarkStart(bookmark) => {
                let key = (
                    bookmark.source_anchor.source_part_path.clone(),
                    bookmark.bookmark_id.clone(),
                );
                if bookmark_starts
                    .insert(key.clone(), bookmark.clone())
                    .is_some()
                {
                    projection.diagnostics.push(reference_diag(
                        "CVN_BOOKMARK_DUPLICATE_START",
                        &bookmark.source_anchor.xml_path,
                        format!("bookmark start `{}` is duplicated", bookmark.bookmark_id),
                    ));
                }
                if let Some(name) = bookmark.name.as_ref() {
                    bookmark_names
                        .entry((
                            bookmark.source_anchor.source_part_path.clone(),
                            name.clone(),
                        ))
                        .or_default()
                        .push(bookmark.bookmark_id.clone());
                }
                projection.bookmarks.push(bookmark.clone());
            }
            SemanticInline::BookmarkEnd(bookmark) => {
                let key = (
                    bookmark.source_anchor.source_part_path.clone(),
                    bookmark.bookmark_id.clone(),
                );
                if bookmark_ends.insert(key, bookmark.clone()).is_some() {
                    projection.diagnostics.push(reference_diag(
                        "CVN_BOOKMARK_DUPLICATE_END",
                        &bookmark.source_anchor.xml_path,
                        format!("bookmark end `{}` is duplicated", bookmark.bookmark_id),
                    ));
                }
                projection.bookmarks.push(bookmark.clone());
            }
            SemanticInline::Field(field) => {
                collect_reference_inlines_phase_one(
                    &mut field.result.children,
                    relationships,
                    projection,
                    bookmark_starts,
                    bookmark_ends,
                    bookmark_names,
                );
            }
            SemanticInline::TrackedChange { change } => collect_reference_change_phase_one(
                change,
                relationships,
                projection,
                bookmark_starts,
                bookmark_ends,
                bookmark_names,
            ),
            SemanticInline::MceSelectedContent(content) => {
                collect_reference_phase_one(
                    &mut content.blocks,
                    relationships,
                    projection,
                    bookmark_starts,
                    bookmark_ends,
                    bookmark_names,
                );
                collect_reference_inlines_phase_one(
                    &mut content.inlines,
                    relationships,
                    projection,
                    bookmark_starts,
                    bookmark_ends,
                    bookmark_names,
                );
            }
            SemanticInline::Text(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::FootnoteReference { .. }
            | SemanticInline::EndnoteReference { .. }
            | SemanticInline::CommentReference { .. }
            | SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. }
            | SemanticInline::Drawing(_)
            | SemanticInline::EmbeddedVisualObject(_) => {}
        }
    }
}

fn build_bookmark_ranges(
    bookmark_starts: &BTreeMap<(String, String), BookmarkProjection>,
    bookmark_ends: &BTreeMap<(String, String), BookmarkProjection>,
    bookmark_names: &BTreeMap<(String, String), Vec<String>>,
    projection: &mut DocumentReferencesProjection,
) {
    for ((part, bookmark_id), start) in bookmark_starts {
        let end = bookmark_ends.get(&(part.clone(), bookmark_id.clone()));
        if end.is_none() {
            projection.diagnostics.push(reference_diag(
                "CVN_BOOKMARK_END_MISSING",
                &start.source_anchor.xml_path,
                format!("bookmark `{bookmark_id}` has no matching end"),
            ));
        }
        projection.bookmark_ranges.push(BookmarkRangeProjection {
            source_part: part.clone(),
            bookmark_id: bookmark_id.clone(),
            name: start.name.clone(),
            start: Some(start.source_anchor.clone()),
            end: end.map(|value| value.source_anchor.clone()),
            markers: end
                .map(|value| vec![start.id.clone(), value.id.clone()])
                .unwrap_or_else(|| vec![start.id.clone()]),
        });
    }
    for ((_, bookmark_id), end) in bookmark_ends {
        if !bookmark_starts.contains_key(&(
            end.source_anchor.source_part_path.clone(),
            bookmark_id.clone(),
        )) {
            projection.diagnostics.push(reference_diag(
                "CVN_BOOKMARK_START_MISSING",
                &end.source_anchor.xml_path,
                format!("bookmark `{bookmark_id}` has no matching start"),
            ));
        }
    }
    for ((part, name), ids) in bookmark_names {
        if ids.len() > 1 {
            projection.diagnostics.push(reference_diag(
                "CVN_BOOKMARK_NAME_AMBIGUOUS",
                part,
                format!("bookmark name `{name}` is defined {} times", ids.len()),
            ));
        }
    }
}

fn collect_reference_phase_two(
    blocks: &mut [SemanticBlock],
    bookmark_names: &BTreeMap<(String, String), Vec<String>>,
    projection: &mut DocumentReferencesProjection,
) {
    for block in blocks {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                for run in &mut paragraph.runs {
                    collect_reference_inlines_phase_two(
                        &mut run.inlines,
                        bookmark_names,
                        projection,
                    );
                }
            }
            SemanticBlock::Table(table) => {
                for row in &mut table.rows {
                    for cell in &mut row.cells {
                        collect_reference_phase_two(&mut cell.blocks, bookmark_names, projection);
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => match &mut change.content {
                TrackedContent::Inline { items } => {
                    collect_reference_inlines_phase_two(items, bookmark_names, projection)
                }
                TrackedContent::Block { blocks } => {
                    collect_reference_phase_two(blocks, bookmark_names, projection)
                }
                TrackedContent::PropertyChange { .. } => {}
            },
            SemanticBlock::MceSelectedContent(content) => {
                collect_reference_phase_two(&mut content.blocks, bookmark_names, projection);
                collect_reference_inlines_phase_two(
                    &mut content.inlines,
                    bookmark_names,
                    projection,
                );
            }
        }
    }
}

fn collect_reference_inlines_phase_two(
    inlines: &mut [SemanticInline],
    bookmark_names: &BTreeMap<(String, String), Vec<String>>,
    projection: &mut DocumentReferencesProjection,
) {
    for inline in inlines {
        match inline {
            SemanticInline::Hyperlink(hyperlink) => {
                collect_reference_inlines_phase_two(
                    &mut hyperlink.children,
                    bookmark_names,
                    projection,
                );
            }
            SemanticInline::Field(field) => {
                collect_reference_inlines_phase_two(
                    &mut field.result.children,
                    bookmark_names,
                    projection,
                );
                if field.instruction.raw.trim().is_empty() {
                    projection.diagnostics.push(reference_diag(
                        "CVN_FIELD_INSTRUCTION_MISSING",
                        &field.source_anchor.xml_path,
                        "field instruction is empty",
                    ));
                }
                if matches!(
                    field.field_kind,
                    FieldKind::Dde
                        | FieldKind::IncludeText
                        | FieldKind::IncludePicture
                        | FieldKind::Link
                ) {
                    projection.diagnostics.push(reference_diag(
                        "CVN_FIELD_EXECUTION_BLOCKED",
                        &field.source_anchor.xml_path,
                        "field execution is blocked and not evaluated",
                    ));
                }
                field.cross_reference = resolve_field_cross_reference(
                    field,
                    bookmark_names,
                    &mut projection.diagnostics,
                );
                projection.fields.push(field.clone());
                if let Some(cross_reference) = field.cross_reference.clone() {
                    projection.cross_references.push(cross_reference);
                }
            }
            SemanticInline::TrackedChange { change } => match &mut change.content {
                TrackedContent::Inline { items } => {
                    collect_reference_inlines_phase_two(items, bookmark_names, projection)
                }
                TrackedContent::Block { blocks } => {
                    collect_reference_phase_two(blocks, bookmark_names, projection)
                }
                TrackedContent::PropertyChange { .. } => {}
            },
            SemanticInline::MceSelectedContent(content) => {
                collect_reference_phase_two(&mut content.blocks, bookmark_names, projection);
                collect_reference_inlines_phase_two(
                    &mut content.inlines,
                    bookmark_names,
                    projection,
                );
            }
            SemanticInline::BookmarkStart(_)
            | SemanticInline::BookmarkEnd(_)
            | SemanticInline::Drawing(_)
            | SemanticInline::EmbeddedVisualObject(_)
            | SemanticInline::Text(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::FootnoteReference { .. }
            | SemanticInline::EndnoteReference { .. }
            | SemanticInline::CommentReference { .. }
            | SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. } => {}
        }
    }
}

fn resolve_hyperlink(
    hyperlink: &mut HyperlinkProjection,
    relationships: &[OpcRelationship],
    diagnostics: &mut Vec<DocumentReferenceDiagnostic>,
) {
    if let Some(relationship_id) = hyperlink.relationship_id.as_ref() {
        if let Some(relationship) = relationships.iter().find(|relationship| {
            relationship.source_part.as_deref()
                == Some(hyperlink.source_anchor.source_part_path.as_str())
                && relationship.relationship_id == *relationship_id
        }) {
            hyperlink.target.relationship_type = Some(relationship.relationship_type.clone());
            hyperlink.target.raw_target = Some(relationship.target.clone());
            match relationship.target_mode {
                TargetMode::External => {
                    hyperlink.target.kind = HyperlinkTargetKind::ExternalRelationship;
                    hyperlink.target.risk_class =
                        classify_hyperlink_risk(relationship.target.as_str());
                    diagnostics.push(reference_diag(
                        "CVN_HYPERLINK_EXTERNAL_TARGET_INERT",
                        &hyperlink.source_anchor.xml_path,
                        "external hyperlink target is preserved inertly",
                    ));
                    if matches!(
                        hyperlink.target.risk_class.as_deref(),
                        Some("active_or_script_scheme" | "office_protocol" | "data_uri")
                    ) {
                        diagnostics.push(reference_diag(
                            "CVN_HYPERLINK_ACTIVE_SCHEME_INERT",
                            &hyperlink.source_anchor.xml_path,
                            "active hyperlink scheme is preserved inertly",
                        ));
                    }
                }
                TargetMode::Internal => {
                    hyperlink.target.kind = HyperlinkTargetKind::InternalPart;
                    hyperlink.target.resolved_part_path = resolve_internal_target_path(
                        &hyperlink.source_anchor.source_part_path,
                        &relationship.target,
                    );
                }
            }
        } else {
            diagnostics.push(reference_diag(
                "CVN_HYPERLINK_RELATIONSHIP_MISSING",
                &hyperlink.source_anchor.xml_path,
                format!("relationship `{relationship_id}` is not defined"),
            ));
            hyperlink.target.kind = HyperlinkTargetKind::Unresolved;
        }
    } else if hyperlink.anchor.is_some() {
        hyperlink.target.kind = HyperlinkTargetKind::InternalAnchor;
    }
}

fn classify_hyperlink_risk(value: &str) -> Option<String> {
    let scheme = value
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let risk = match scheme.as_str() {
        "http" | "https" | "mailto" => "ordinary_web",
        "file" => "file_or_local_resource",
        "javascript" | "vbscript" | "shell" => "active_or_script_scheme",
        "ms-word" | "ms-excel" | "ms-powerpoint" => "office_protocol",
        "data" => "data_uri",
        "" => return None,
        _ => "unknown_scheme",
    };
    Some(risk.to_owned())
}

fn resolve_field_cross_reference(
    field: &mut FieldProjection,
    bookmark_names: &BTreeMap<(String, String), Vec<String>>,
    diagnostics: &mut Vec<DocumentReferenceDiagnostic>,
) -> Option<CrossReferenceProjection> {
    let tokens = if field.instruction.tokens.is_empty() {
        instruction_tokens(&field.instruction.raw)
    } else {
        field.instruction.tokens.clone()
    };
    let mut projection = CrossReferenceProjection {
        field_id: field.id.clone(),
        field_kind: field.field_kind,
        target_bookmark_name: None,
        resolved_bookmark_id: None,
        hyperlink_target: None,
        source_anchor: field.source_anchor.clone(),
    };
    match field.field_kind {
        FieldKind::Ref | FieldKind::Pageref | FieldKind::Noteref => {
            let target = tokens
                .get(1)
                .map(|value| value.trim_matches('"').to_owned());
            projection.target_bookmark_name = target.clone();
            if let Some(target) = target {
                match bookmark_names
                    .get(&(field.source_anchor.source_part_path.clone(), target.clone()))
                {
                    Some(ids) if ids.len() == 1 => {
                        projection.resolved_bookmark_id = ids.first().cloned();
                    }
                    Some(ids) if ids.len() > 1 => diagnostics.push(reference_diag(
                        "CVN_REFERENCE_BOOKMARK_AMBIGUOUS",
                        &field.source_anchor.xml_path,
                        format!("bookmark `{target}` resolves to {} candidates", ids.len()),
                    )),
                    _ => diagnostics.push(reference_diag(
                        "CVN_REFERENCE_BOOKMARK_MISSING",
                        &field.source_anchor.xml_path,
                        format!("bookmark `{target}` is not defined"),
                    )),
                }
            }
            Some(projection)
        }
        FieldKind::Hyperlink => {
            let mut target = None;
            let mut local_anchor = None;
            let mut index = 1;
            while index < tokens.len() {
                if tokens[index].eq_ignore_ascii_case("\\l") {
                    local_anchor = tokens
                        .get(index + 1)
                        .map(|value| value.trim_matches('"').to_owned());
                    index += 2;
                    continue;
                }
                if !tokens[index].starts_with('\\') && target.is_none() {
                    target = Some(tokens[index].trim_matches('"').to_owned());
                }
                index += 1;
            }
            projection.target_bookmark_name = local_anchor.clone();
            projection.hyperlink_target = Some(if let Some(anchor) = local_anchor {
                HyperlinkTarget {
                    kind: HyperlinkTargetKind::InternalAnchor,
                    raw_target: Some(anchor),
                    resolved_part_path: None,
                    relationship_type: None,
                    risk_class: None,
                }
            } else {
                let raw = target.clone();
                HyperlinkTarget {
                    kind: raw
                        .as_ref()
                        .map(|_| HyperlinkTargetKind::ExternalRelationship)
                        .unwrap_or(HyperlinkTargetKind::Unresolved),
                    raw_target: raw.clone(),
                    resolved_part_path: None,
                    relationship_type: None,
                    risk_class: raw.as_deref().and_then(classify_hyperlink_risk),
                }
            });
            Some(projection)
        }
        _ => None,
    }
}

fn reference_diag(
    code: &str,
    path: &str,
    message: impl Into<String>,
) -> DocumentReferenceDiagnostic {
    DocumentReferenceDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.into(),
    }
}

fn resolve_story_references(
    references: &mut [StoryReference],
    relationships: &[OpcRelationship],
    diagnostics: &mut Vec<StoryResolutionDiagnostic>,
) {
    for reference in references {
        match reference.kind {
            StoryReferenceKind::HeaderReference | StoryReferenceKind::FooterReference => {
                if let Some(relationship_id) = reference.relationship_id.clone() {
                    if let Some(relationship) = relationships.iter().find(|relationship| {
                        relationship.source_part.as_deref() == Some("word/document.xml")
                            && relationship.relationship_id == relationship_id
                    }) {
                        reference.target = Some(relationship.target.clone());
                        reference.target_mode = Some(relationship.target_mode);
                        if relationship.target_mode == TargetMode::Internal {
                            reference.resolved_part_path = resolve_internal_target_path(
                                "word/document.xml",
                                &relationship.target,
                            );
                        } else {
                            diagnostics.push(story_diag(
                                "CVN_STORY_EXTERNAL_TARGET_UNSUPPORTED",
                                &reference.source_anchor.xml_path,
                                "external story relationship targets are not resolved",
                            ));
                        }
                    } else {
                        diagnostics.push(story_diag(
                            "CVN_STORY_RELATIONSHIP_MISSING",
                            &reference.source_anchor.xml_path,
                            format!("relationship `{relationship_id}` is not defined"),
                        ));
                    }
                }
            }
            StoryReferenceKind::FootnoteReference => {
                if reference.resolved_part_path.is_none() {
                    reference.resolved_part_path = Some("word/footnotes.xml".to_owned());
                }
            }
            StoryReferenceKind::EndnoteReference => {
                if reference.resolved_part_path.is_none() {
                    reference.resolved_part_path = Some("word/endnotes.xml".to_owned());
                }
            }
            StoryReferenceKind::CommentReference => {
                if reference.resolved_part_path.is_none() {
                    reference.resolved_part_path = Some("word/comments.xml".to_owned());
                }
            }
            StoryReferenceKind::CommentRangeStart | StoryReferenceKind::CommentRangeEnd => {}
        }
    }
}

fn resolve_story_registry(
    stories: &mut StoryRegistryProjection,
    blocks: &[SemanticBlock],
    relationships: &[OpcRelationship],
) {
    let mut references = Vec::new();
    collect_story_references(blocks, &mut references);
    resolve_story_references(&mut references, relationships, &mut stories.diagnostics);
    let mut ranges_by_comment = BTreeMap::<String, Vec<CommentRangeProjection>>::new();
    collect_comment_ranges(blocks, &mut ranges_by_comment);
    let note_targets = story_note_targets(&stories.parts);
    let comment_targets = story_comment_targets(&stories.parts);
    for reference in &references {
        match reference.kind {
            StoryReferenceKind::FootnoteReference => {
                if let Some(note_id) = reference.source_identifier.as_ref() {
                    if !note_targets.contains_key(note_id) {
                        stories.diagnostics.push(story_diag(
                            "CVN_FOOTNOTE_TARGET_MISSING",
                            &reference.source_anchor.xml_path,
                            format!("footnote `{note_id}` is not defined"),
                        ));
                    }
                }
            }
            StoryReferenceKind::EndnoteReference => {
                if let Some(note_id) = reference.source_identifier.as_ref() {
                    if !note_targets.contains_key(note_id) {
                        stories.diagnostics.push(story_diag(
                            "CVN_ENDNOTE_TARGET_MISSING",
                            &reference.source_anchor.xml_path,
                            format!("endnote `{note_id}` is not defined"),
                        ));
                    }
                }
            }
            StoryReferenceKind::CommentReference => {
                if let Some(comment_id) = reference.source_identifier.as_ref() {
                    if !comment_targets.contains_key(comment_id) {
                        stories.diagnostics.push(story_diag(
                            "CVN_COMMENT_TARGET_MISSING",
                            &reference.source_anchor.xml_path,
                            format!("comment `{comment_id}` is not defined"),
                        ));
                    }
                }
            }
            StoryReferenceKind::HeaderReference
            | StoryReferenceKind::FooterReference
            | StoryReferenceKind::CommentRangeStart
            | StoryReferenceKind::CommentRangeEnd => {}
        }
    }
    resolve_story_parts(
        &mut stories.parts,
        &note_targets,
        &comment_targets,
        &ranges_by_comment,
        &mut stories.diagnostics,
        relationships,
    );
    stories.references = references;
    stories
        .diagnostics
        .sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
}

fn resolve_story_parts(
    parts: &mut [StoryPartProjection],
    note_targets: &BTreeMap<String, String>,
    comment_targets: &BTreeMap<String, String>,
    ranges_by_comment: &BTreeMap<String, Vec<CommentRangeProjection>>,
    diagnostics: &mut Vec<StoryResolutionDiagnostic>,
    relationships: &[OpcRelationship],
) {
    let mut seen_section_refs = BTreeSet::new();
    for part in parts {
        for reference in &mut part.section_story_references {
            let key = (
                reference.section_index,
                reference.kind,
                reference.relationship_id.clone(),
            );
            if !seen_section_refs.insert(key) {
                diagnostics.push(story_diag(
                    "CVN_STORY_DUPLICATE_REFERENCE",
                    &reference.source_anchor.xml_path,
                    "duplicate section story reference in the same section",
                ));
                continue;
            }
            if let Some(relationship) = relationships.iter().find(|relationship| {
                relationship.source_part.as_deref() == Some("word/document.xml")
                    && relationship.relationship_id == reference.relationship_id
            }) {
                reference.target = relationship.target.clone();
                if relationship.target_mode == TargetMode::Internal {
                    reference.resolved_part_path =
                        resolve_internal_target_path("word/document.xml", &relationship.target);
                } else {
                    diagnostics.push(story_diag(
                        "CVN_STORY_EXTERNAL_TARGET_UNSUPPORTED",
                        &reference.source_anchor.xml_path,
                        "external story relationship targets are not resolved",
                    ));
                }
            } else {
                diagnostics.push(story_diag(
                    "CVN_STORY_RELATIONSHIP_MISSING",
                    &reference.source_anchor.xml_path,
                    format!(
                        "relationship `{}` is not defined for section reference",
                        reference.relationship_id
                    ),
                ));
            }
        }

        for note in &mut part.notes {
            if !note_targets.contains_key(&note.note_id) {
                diagnostics.push(story_diag(
                    if part.kind == StoryPartKind::Footnotes {
                        "CVN_FOOTNOTE_TARGET_MISSING"
                    } else {
                        "CVN_ENDNOTE_TARGET_MISSING"
                    },
                    &note.source_anchor.xml_path,
                    format!("story note `{}` is not defined", note.note_id),
                ));
            }
        }

        for comment in &mut part.comments {
            match comment_targets.get(&comment.comment_id) {
                Some(_) => {
                    if let Some(ranges) = ranges_by_comment.get(&comment.comment_id) {
                        comment.ranges = ranges.clone();
                    } else {
                        diagnostics.push(story_diag(
                            "CVN_COMMENT_RANGE_START_MISSING",
                            &comment.source_anchor.xml_path,
                            format!("comment `{}` has no range markers", comment.comment_id),
                        ));
                    }
                }
                None => diagnostics.push(story_diag(
                    "CVN_COMMENT_TARGET_MISSING",
                    &comment.source_anchor.xml_path,
                    format!("comment `{}` is not defined", comment.comment_id),
                )),
            }
        }
    }
}

fn collect_story_references(blocks: &[SemanticBlock], references: &mut Vec<StoryReference>) {
    for block in blocks {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                for reference in &paragraph.section_story_references {
                    references.push(StoryReference {
                        kind: match reference.kind {
                            StoryPartKind::HeaderDefault
                            | StoryPartKind::HeaderFirst
                            | StoryPartKind::HeaderEven => StoryReferenceKind::HeaderReference,
                            StoryPartKind::FooterDefault
                            | StoryPartKind::FooterFirst
                            | StoryPartKind::FooterEven => StoryReferenceKind::FooterReference,
                            _ => StoryReferenceKind::HeaderReference,
                        },
                        source_anchor: reference.source_anchor.clone(),
                        source_identifier: None,
                        relationship_id: Some(reference.relationship_id.clone()),
                        relationship_type: Some(reference.relationship_type.clone()),
                        target: Some(reference.target.clone()),
                        target_mode: None,
                        resolved_part_path: reference.resolved_part_path.clone(),
                    });
                }
                for run in &paragraph.runs {
                    collect_run_story_references(run, references);
                }
            }
            SemanticBlock::Table(table) => {
                for row in &table.rows {
                    for cell in &row.cells {
                        collect_story_references(&cell.blocks, references);
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => {
                collect_track_change_story_references(change, references)
            }
            SemanticBlock::MceSelectedContent(content) => {
                collect_story_references(&content.blocks, references);
                collect_mce_inline_story_references(&content.inlines, references);
            }
        }
    }
}

fn collect_track_change_story_references(
    change: &TrackedChange,
    references: &mut Vec<StoryReference>,
) {
    match &change.content {
        TrackedContent::Inline { items } => {
            for inline in items {
                match inline {
                    SemanticInline::FootnoteReference {
                        note_id,
                        resolved_part_path,
                    } => references.push(StoryReference {
                        kind: StoryReferenceKind::FootnoteReference,
                        source_anchor: change.source_anchor.clone(),
                        source_identifier: Some(note_id.clone()),
                        relationship_id: None,
                        relationship_type: None,
                        target: None,
                        target_mode: None,
                        resolved_part_path: resolved_part_path.clone(),
                    }),
                    SemanticInline::EndnoteReference {
                        note_id,
                        resolved_part_path,
                    } => references.push(StoryReference {
                        kind: StoryReferenceKind::EndnoteReference,
                        source_anchor: change.source_anchor.clone(),
                        source_identifier: Some(note_id.clone()),
                        relationship_id: None,
                        relationship_type: None,
                        target: None,
                        target_mode: None,
                        resolved_part_path: resolved_part_path.clone(),
                    }),
                    SemanticInline::CommentReference {
                        comment_id,
                        resolved_part_path,
                    } => references.push(StoryReference {
                        kind: StoryReferenceKind::CommentReference,
                        source_anchor: change.source_anchor.clone(),
                        source_identifier: Some(comment_id.clone()),
                        relationship_id: None,
                        relationship_type: None,
                        target: None,
                        target_mode: None,
                        resolved_part_path: resolved_part_path.clone(),
                    }),
                    SemanticInline::CommentRangeStart { comment_id } => {
                        references.push(StoryReference {
                            kind: StoryReferenceKind::CommentRangeStart,
                            source_anchor: change.source_anchor.clone(),
                            source_identifier: Some(comment_id.clone()),
                            relationship_id: None,
                            relationship_type: None,
                            target: None,
                            target_mode: None,
                            resolved_part_path: None,
                        })
                    }
                    SemanticInline::CommentRangeEnd { comment_id } => {
                        references.push(StoryReference {
                            kind: StoryReferenceKind::CommentRangeEnd,
                            source_anchor: change.source_anchor.clone(),
                            source_identifier: Some(comment_id.clone()),
                            relationship_id: None,
                            relationship_type: None,
                            target: None,
                            target_mode: None,
                            resolved_part_path: None,
                        })
                    }
                    SemanticInline::MceSelectedContent(content) => {
                        collect_story_references(&content.blocks, references);
                        collect_mce_inline_story_references(&content.inlines, references);
                    }
                    SemanticInline::Hyperlink(hyperlink) => {
                        collect_mce_inline_story_references(&hyperlink.children, references);
                    }
                    SemanticInline::Field(field) => {
                        collect_mce_inline_story_references(&field.result.children, references);
                    }
                    SemanticInline::Text(_)
                    | SemanticInline::BookmarkStart(_)
                    | SemanticInline::BookmarkEnd(_)
                    | SemanticInline::Drawing(_)
                    | SemanticInline::EmbeddedVisualObject(_)
                    | SemanticInline::Tab
                    | SemanticInline::LineBreak { .. }
                    | SemanticInline::TrackedChange { .. } => {}
                }
            }
        }
        TrackedContent::Block { blocks } => collect_story_references(blocks, references),
        TrackedContent::PropertyChange { .. } => {}
    }
}

fn collect_run_story_references(run: &SemanticRun, references: &mut Vec<StoryReference>) {
    for inline in &run.inlines {
        match inline {
            SemanticInline::FootnoteReference {
                note_id,
                resolved_part_path,
            } => references.push(StoryReference {
                kind: StoryReferenceKind::FootnoteReference,
                source_anchor: run.source_anchor.clone(),
                source_identifier: Some(note_id.clone()),
                relationship_id: None,
                relationship_type: None,
                target: None,
                target_mode: None,
                resolved_part_path: resolved_part_path.clone(),
            }),
            SemanticInline::EndnoteReference {
                note_id,
                resolved_part_path,
            } => references.push(StoryReference {
                kind: StoryReferenceKind::EndnoteReference,
                source_anchor: run.source_anchor.clone(),
                source_identifier: Some(note_id.clone()),
                relationship_id: None,
                relationship_type: None,
                target: None,
                target_mode: None,
                resolved_part_path: resolved_part_path.clone(),
            }),
            SemanticInline::CommentReference {
                comment_id,
                resolved_part_path,
            } => references.push(StoryReference {
                kind: StoryReferenceKind::CommentReference,
                source_anchor: run.source_anchor.clone(),
                source_identifier: Some(comment_id.clone()),
                relationship_id: None,
                relationship_type: None,
                target: None,
                target_mode: None,
                resolved_part_path: resolved_part_path.clone(),
            }),
            SemanticInline::CommentRangeStart { comment_id } => references.push(StoryReference {
                kind: StoryReferenceKind::CommentRangeStart,
                source_anchor: run.source_anchor.clone(),
                source_identifier: Some(comment_id.clone()),
                relationship_id: None,
                relationship_type: None,
                target: None,
                target_mode: None,
                resolved_part_path: None,
            }),
            SemanticInline::CommentRangeEnd { comment_id } => references.push(StoryReference {
                kind: StoryReferenceKind::CommentRangeEnd,
                source_anchor: run.source_anchor.clone(),
                source_identifier: Some(comment_id.clone()),
                relationship_id: None,
                relationship_type: None,
                target: None,
                target_mode: None,
                resolved_part_path: None,
            }),
            SemanticInline::Hyperlink(hyperlink) => {
                collect_mce_inline_story_references(&hyperlink.children, references);
            }
            SemanticInline::Field(field) => {
                collect_mce_inline_story_references(&field.result.children, references);
            }
            SemanticInline::Text(_)
            | SemanticInline::BookmarkStart(_)
            | SemanticInline::BookmarkEnd(_)
            | SemanticInline::Drawing(_)
            | SemanticInline::EmbeddedVisualObject(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. } => {}
            SemanticInline::TrackedChange { change } => {
                collect_track_change_story_references(change, references)
            }
            SemanticInline::MceSelectedContent(content) => {
                collect_story_references(&content.blocks, references);
                collect_mce_inline_story_references(&content.inlines, references);
            }
        }
    }
}

fn collect_mce_inline_story_references(
    inlines: &[SemanticInline],
    references: &mut Vec<StoryReference>,
) {
    let synthetic_run = SemanticRun {
        id: SemanticNodeId::new("sem:run:mce-inline-story").expect("valid id"),
        source_identifier: None,
        source_anchor: SourceAnchor {
            source_part_path: "mce-inline".to_owned(),
            xml_path: "/mce-inline".to_owned(),
            byte_start: None,
        },
        properties: RunPropertiesProjection::default(),
        resolved_style: None,
        inlines: inlines.to_vec(),
    };
    collect_run_story_references(&synthetic_run, references);
}

fn collect_comment_ranges(
    blocks: &[SemanticBlock],
    ranges_by_comment: &mut BTreeMap<String, Vec<CommentRangeProjection>>,
) {
    for block in blocks {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                for run in &paragraph.runs {
                    for inline in &run.inlines {
                        match inline {
                            SemanticInline::CommentRangeStart { comment_id } => {
                                ranges_by_comment
                                    .entry(comment_id.clone())
                                    .or_default()
                                    .push(CommentRangeProjection {
                                        comment_id: comment_id.clone(),
                                        kind: StoryReferenceKind::CommentRangeStart,
                                        source_anchor: run.source_anchor.clone(),
                                    });
                            }
                            SemanticInline::CommentRangeEnd { comment_id } => {
                                ranges_by_comment
                                    .entry(comment_id.clone())
                                    .or_default()
                                    .push(CommentRangeProjection {
                                        comment_id: comment_id.clone(),
                                        kind: StoryReferenceKind::CommentRangeEnd,
                                        source_anchor: run.source_anchor.clone(),
                                    });
                            }
                            SemanticInline::MceSelectedContent(content) => {
                                collect_comment_ranges(&content.blocks, ranges_by_comment);
                                collect_mce_inline_comment_ranges(
                                    &content.inlines,
                                    ranges_by_comment,
                                );
                            }
                            SemanticInline::Hyperlink(hyperlink) => {
                                collect_mce_inline_comment_ranges(
                                    &hyperlink.children,
                                    ranges_by_comment,
                                );
                            }
                            SemanticInline::Field(field) => {
                                collect_mce_inline_comment_ranges(
                                    &field.result.children,
                                    ranges_by_comment,
                                );
                            }
                            SemanticInline::Text(_)
                            | SemanticInline::BookmarkStart(_)
                            | SemanticInline::BookmarkEnd(_)
                            | SemanticInline::Drawing(_)
                            | SemanticInline::EmbeddedVisualObject(_)
                            | SemanticInline::Tab
                            | SemanticInline::LineBreak { .. }
                            | SemanticInline::FootnoteReference { .. }
                            | SemanticInline::EndnoteReference { .. }
                            | SemanticInline::CommentReference { .. }
                            | SemanticInline::TrackedChange { .. } => {}
                        }
                    }
                }
            }
            SemanticBlock::Table(table) => {
                for row in &table.rows {
                    for cell in &row.cells {
                        collect_comment_ranges(&cell.blocks, ranges_by_comment);
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => {
                collect_track_change_comment_ranges(change, ranges_by_comment)
            }
            SemanticBlock::MceSelectedContent(content) => {
                collect_comment_ranges(&content.blocks, ranges_by_comment);
                collect_mce_inline_comment_ranges(&content.inlines, ranges_by_comment);
            }
        }
    }
}

fn collect_track_change_comment_ranges(
    change: &TrackedChange,
    ranges_by_comment: &mut BTreeMap<String, Vec<CommentRangeProjection>>,
) {
    match &change.content {
        TrackedContent::Inline { items } => {
            for inline in items {
                match inline {
                    SemanticInline::CommentRangeStart { comment_id } => {
                        ranges_by_comment
                            .entry(comment_id.clone())
                            .or_default()
                            .push(CommentRangeProjection {
                                comment_id: comment_id.clone(),
                                kind: StoryReferenceKind::CommentRangeStart,
                                source_anchor: change.source_anchor.clone(),
                            });
                    }
                    SemanticInline::CommentRangeEnd { comment_id } => {
                        ranges_by_comment
                            .entry(comment_id.clone())
                            .or_default()
                            .push(CommentRangeProjection {
                                comment_id: comment_id.clone(),
                                kind: StoryReferenceKind::CommentRangeEnd,
                                source_anchor: change.source_anchor.clone(),
                            });
                    }
                    SemanticInline::MceSelectedContent(content) => {
                        collect_comment_ranges(&content.blocks, ranges_by_comment);
                        collect_mce_inline_comment_ranges(&content.inlines, ranges_by_comment);
                    }
                    SemanticInline::Hyperlink(hyperlink) => {
                        collect_mce_inline_comment_ranges(&hyperlink.children, ranges_by_comment);
                    }
                    SemanticInline::Field(field) => {
                        collect_mce_inline_comment_ranges(
                            &field.result.children,
                            ranges_by_comment,
                        );
                    }
                    SemanticInline::Text(_)
                    | SemanticInline::BookmarkStart(_)
                    | SemanticInline::BookmarkEnd(_)
                    | SemanticInline::Drawing(_)
                    | SemanticInline::EmbeddedVisualObject(_)
                    | SemanticInline::Tab
                    | SemanticInline::LineBreak { .. }
                    | SemanticInline::FootnoteReference { .. }
                    | SemanticInline::EndnoteReference { .. }
                    | SemanticInline::CommentReference { .. }
                    | SemanticInline::TrackedChange { .. } => {}
                }
            }
        }
        TrackedContent::Block { blocks } => collect_comment_ranges(blocks, ranges_by_comment),
        TrackedContent::PropertyChange { .. } => {}
    }
}

fn collect_mce_inline_comment_ranges(
    inlines: &[SemanticInline],
    ranges_by_comment: &mut BTreeMap<String, Vec<CommentRangeProjection>>,
) {
    for inline in inlines {
        match inline {
            SemanticInline::CommentRangeStart { comment_id } => {
                ranges_by_comment
                    .entry(comment_id.clone())
                    .or_default()
                    .push(CommentRangeProjection {
                        comment_id: comment_id.clone(),
                        kind: StoryReferenceKind::CommentRangeStart,
                        source_anchor: SourceAnchor {
                            source_part_path: "mce-inline".to_owned(),
                            xml_path: "/mce-inline".to_owned(),
                            byte_start: None,
                        },
                    });
            }
            SemanticInline::CommentRangeEnd { comment_id } => {
                ranges_by_comment
                    .entry(comment_id.clone())
                    .or_default()
                    .push(CommentRangeProjection {
                        comment_id: comment_id.clone(),
                        kind: StoryReferenceKind::CommentRangeEnd,
                        source_anchor: SourceAnchor {
                            source_part_path: "mce-inline".to_owned(),
                            xml_path: "/mce-inline".to_owned(),
                            byte_start: None,
                        },
                    });
            }
            SemanticInline::TrackedChange { change } => {
                collect_track_change_comment_ranges(change, ranges_by_comment)
            }
            SemanticInline::MceSelectedContent(content) => {
                collect_comment_ranges(&content.blocks, ranges_by_comment);
                collect_mce_inline_comment_ranges(&content.inlines, ranges_by_comment);
            }
            SemanticInline::Hyperlink(hyperlink) => {
                collect_mce_inline_comment_ranges(&hyperlink.children, ranges_by_comment);
            }
            SemanticInline::Field(field) => {
                collect_mce_inline_comment_ranges(&field.result.children, ranges_by_comment);
            }
            SemanticInline::Text(_)
            | SemanticInline::BookmarkStart(_)
            | SemanticInline::BookmarkEnd(_)
            | SemanticInline::Drawing(_)
            | SemanticInline::EmbeddedVisualObject(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::FootnoteReference { .. }
            | SemanticInline::EndnoteReference { .. }
            | SemanticInline::CommentReference { .. } => {}
        }
    }
}

fn story_note_targets(parts: &[StoryPartProjection]) -> BTreeMap<String, String> {
    let mut targets = BTreeMap::new();
    for part in parts {
        for note in &part.notes {
            targets
                .entry(note.note_id.clone())
                .or_insert_with(|| part.source_part.clone());
        }
    }
    targets
}

fn story_comment_targets(parts: &[StoryPartProjection]) -> BTreeMap<String, String> {
    let mut targets = BTreeMap::new();
    for part in parts {
        for comment in &part.comments {
            targets
                .entry(comment.comment_id.clone())
                .or_insert_with(|| part.source_part.clone());
        }
    }
    targets
}

fn story_diag(code: &str, path: &str, message: impl Into<String>) -> StoryResolutionDiagnostic {
    StoryResolutionDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.into(),
    }
}

fn resolve_numbering_reference(
    reference: &NumberingReference,
    numbering: Option<&NumberingRegistryProjection>,
) -> Option<NumberingLevelProjection> {
    let numbering = numbering?;
    let instance = numbering
        .instances
        .iter()
        .find(|instance| instance.num_id == reference.num_id)?;
    let ilvl = reference.ilvl.as_deref().unwrap_or("0");
    if let Some(override_level) = instance
        .level_overrides
        .iter()
        .find(|level| level.ilvl == ilvl)
    {
        return Some(override_level.clone());
    }
    let abstract_id = instance.abstract_num_id.as_ref()?;
    numbering
        .abstract_numbers
        .iter()
        .find(|abstract_num| abstract_num.abstract_num_id == *abstract_id)?
        .levels
        .iter()
        .find(|level| level.ilvl == ilvl)
        .cloned()
}

fn detect_numbering_reference_diagnostics(
    blocks: &[SemanticBlock],
    numbering: &mut NumberingRegistryProjection,
) {
    let mut diagnostics = Vec::new();
    collect_numbering_reference_diagnostics(blocks, numbering, &mut diagnostics);
    numbering.diagnostics.extend(diagnostics);
    numbering
        .diagnostics
        .sort_by(|left, right| left.path.cmp(&right.path).then(left.code.cmp(&right.code)));
}

fn collect_numbering_reference_diagnostics(
    blocks: &[SemanticBlock],
    numbering: &NumberingRegistryProjection,
    diagnostics: &mut Vec<NumberingResolutionDiagnostic>,
) {
    for block in blocks {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                if let Some(reference) = paragraph.numbering.as_ref() {
                    let path = paragraph.source_anchor.xml_path.clone();
                    let Some(instance) = numbering
                        .instances
                        .iter()
                        .find(|instance| instance.num_id == reference.num_id)
                    else {
                        diagnostics.push(numbering_diag(
                            "CVN_NUMBERING_INSTANCE_MISSING",
                            &path,
                            format!("numbering instance `{}` is not defined", reference.num_id),
                        ));
                        continue;
                    };
                    let Some(abstract_id) = instance.abstract_num_id.as_ref() else {
                        diagnostics.push(numbering_diag(
                            "CVN_ABSTRACT_NUMBERING_MISSING",
                            &path,
                            format!(
                                "numbering instance `{}` has no abstractNumId",
                                instance.num_id
                            ),
                        ));
                        continue;
                    };
                    let Some(abstract_num) = numbering
                        .abstract_numbers
                        .iter()
                        .find(|abstract_num| abstract_num.abstract_num_id == *abstract_id)
                    else {
                        diagnostics.push(numbering_diag(
                            "CVN_ABSTRACT_NUMBERING_MISSING",
                            &path,
                            format!("abstract numbering `{abstract_id}` is not defined"),
                        ));
                        continue;
                    };
                    let ilvl = reference.ilvl.as_deref().unwrap_or("0");
                    let has_override = instance
                        .level_overrides
                        .iter()
                        .any(|level| level.ilvl == ilvl);
                    let has_base = abstract_num.levels.iter().any(|level| level.ilvl == ilvl);
                    if !has_override && !has_base {
                        diagnostics.push(numbering_diag(
                            "CVN_NUMBERING_LEVEL_MISSING",
                            &path,
                            format!(
                                "level `{ilvl}` is not defined for numId `{}`",
                                reference.num_id
                            ),
                        ));
                    }
                }
            }
            SemanticBlock::Table(table) => {
                for row in &table.rows {
                    for cell in &row.cells {
                        collect_numbering_reference_diagnostics(
                            &cell.blocks,
                            numbering,
                            diagnostics,
                        );
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => {
                if let TrackedContent::Block { blocks } = &change.content {
                    collect_numbering_reference_diagnostics(blocks, numbering, diagnostics);
                }
            }
            SemanticBlock::MceSelectedContent(content) => {
                collect_numbering_reference_diagnostics(&content.blocks, numbering, diagnostics);
            }
        }
    }
}

fn resolve_style_definitions(
    definitions: &mut [StyleDefinitionProjection],
    diagnostics: &mut Vec<StyleResolutionDiagnostic>,
) {
    let duplicate_ids = duplicate_style_ids(definitions);
    let snapshot = definitions.to_vec();
    for definition in definitions.iter_mut() {
        if duplicate_ids.contains(&definition.style_id) {
            continue;
        }
        let mut visiting = Vec::new();
        definition.resolved_style = resolve_style_chain(
            &definition.style_id,
            &snapshot,
            &duplicate_ids,
            &mut visiting,
            diagnostics,
        );
    }
}

fn resolve_style_chain(
    style_id: &str,
    definitions: &[StyleDefinitionProjection],
    duplicate_ids: &BTreeSet<String>,
    visiting: &mut Vec<String>,
    diagnostics: &mut Vec<StyleResolutionDiagnostic>,
) -> Option<ResolvedStyleProjection> {
    if visiting.iter().any(|id| id == style_id) {
        diagnostics.push(style_diag(
            "CVN_STYLE_INHERITANCE_CYCLE",
            style_id,
            format!("style inheritance cycle includes `{style_id}`"),
        ));
        return None;
    }
    if duplicate_ids.contains(style_id) {
        return None;
    }
    let definition = definitions
        .iter()
        .find(|style| style.style_id == style_id)?;
    visiting.push(style_id.to_owned());
    let parent = match definition.based_on.as_ref() {
        Some(reference) => {
            if definitions
                .iter()
                .all(|style| style.style_id != reference.style_id)
            {
                diagnostics.push(style_diag(
                    "CVN_STYLE_BASE_MISSING",
                    style_id,
                    format!("base style `{}` is not defined", reference.style_id),
                ));
                None
            } else {
                resolve_style_chain(
                    &reference.style_id,
                    definitions,
                    duplicate_ids,
                    visiting,
                    diagnostics,
                )
            }
        }
        None => None,
    };
    visiting.pop();

    let mut paragraph_properties = parent
        .as_ref()
        .map(|resolved| resolved.paragraph_properties.clone())
        .unwrap_or_default();
    if definition.paragraph_properties.style_id.is_some() {
        paragraph_properties.style_id = definition.paragraph_properties.style_id.clone();
    }
    let mut run_properties = parent
        .as_ref()
        .map(|resolved| resolved.run_properties.clone())
        .unwrap_or_default();
    merge_run_properties(&mut run_properties, &definition.run_properties);
    let mut chain = parent.map(|resolved| resolved.chain).unwrap_or_default();
    chain.push(definition.style_id.clone());
    Some(ResolvedStyleProjection {
        style_id: definition.style_id.clone(),
        style_type: definition.style_type,
        chain,
        paragraph_properties,
        run_properties,
    })
}

fn detect_duplicate_styles(
    definitions: &[StyleDefinitionProjection],
    diagnostics: &mut Vec<StyleResolutionDiagnostic>,
) {
    for style_id in duplicate_style_ids(definitions) {
        diagnostics.push(style_diag(
            "CVN_STYLE_DUPLICATE_ID",
            &style_id,
            format!("style id `{style_id}` is defined more than once"),
        ));
    }
    for definition in definitions {
        if let Some(link) = definition.link.as_ref() {
            if definitions
                .iter()
                .all(|style| style.style_id != link.style_id)
            {
                diagnostics.push(style_diag(
                    "CVN_STYLE_LINK_MISSING",
                    &definition.style_id,
                    format!("linked style `{}` is not defined", link.style_id),
                ));
            }
        }
    }
}

fn duplicate_style_ids(definitions: &[StyleDefinitionProjection]) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for definition in definitions {
        if !seen.insert(definition.style_id.clone()) {
            duplicates.insert(definition.style_id.clone());
        }
    }
    duplicates
}

fn detect_numbering_duplicates(
    abstract_numbers: &[AbstractNumberingProjection],
    instances: &[NumberingInstanceProjection],
    diagnostics: &mut Vec<NumberingResolutionDiagnostic>,
) {
    let mut seen_abstracts = BTreeSet::new();
    for abstract_num in abstract_numbers {
        if !seen_abstracts.insert(abstract_num.abstract_num_id.clone()) {
            diagnostics.push(numbering_diag(
                "CVN_NUMBERING_DUPLICATE_ABSTRACT_ID",
                &abstract_num.abstract_num_id,
                format!(
                    "abstract numbering `{}` is defined more than once",
                    abstract_num.abstract_num_id
                ),
            ));
        }
        let mut seen_levels = BTreeSet::new();
        for level in &abstract_num.levels {
            if !seen_levels.insert(level.ilvl.clone()) {
                diagnostics.push(numbering_diag(
                    "CVN_NUMBERING_DUPLICATE_LEVEL",
                    &format!("{}/{}", abstract_num.abstract_num_id, level.ilvl),
                    format!(
                        "level `{}` is defined more than once in abstract numbering `{}`",
                        level.ilvl, abstract_num.abstract_num_id
                    ),
                ));
            }
        }
    }
    let mut seen_instances = BTreeSet::new();
    for instance in instances {
        if !seen_instances.insert(instance.num_id.clone()) {
            diagnostics.push(numbering_diag(
                "CVN_NUMBERING_DUPLICATE_INSTANCE_ID",
                &instance.num_id,
                format!(
                    "numbering instance `{}` is defined more than once",
                    instance.num_id
                ),
            ));
        }
    }
}

fn unsupported_feature(
    source_part_path: &str,
    xml_path: &str,
    byte_start: u64,
    name: &XmlName,
) -> UnsupportedSemanticFeature {
    UnsupportedSemanticFeature {
        code: "unsupported_semantic_element".to_owned(),
        source_anchor: SourceAnchor {
            source_part_path: source_part_path.to_owned(),
            xml_path: xml_path.to_owned(),
            byte_start: Some(byte_start),
        },
        namespace_uri: name.namespace_uri.clone(),
        local_name: name.local_name.clone(),
        handling: UnsupportedFeatureHandling::PreservedRaw,
    }
}

fn style_diag(code: &str, path: &str, message: impl Into<String>) -> StyleResolutionDiagnostic {
    StyleResolutionDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.into(),
    }
}

fn numbering_diag(
    code: &str,
    path: &str,
    message: impl Into<String>,
) -> NumberingResolutionDiagnostic {
    NumberingResolutionDiagnostic {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.into(),
    }
}

fn style_type(value: Option<&String>) -> StyleType {
    match value.map(String::as_str) {
        Some("paragraph") => StyleType::Paragraph,
        Some("character") => StyleType::Character,
        Some("table") => StyleType::Table,
        Some("numbering") => StyleType::Numbering,
        _ => StyleType::Unknown,
    }
}

fn bool_attr(attrs: &BTreeMap<String, String>, name: &str) -> bool {
    attrs
        .get(name)
        .or_else(|| attrs.get(&format!("w:{name}")))
        .map(|value| matches!(value.as_str(), "1" | "true" | "on"))
        .unwrap_or(false)
}

fn set_run_property(
    properties: &mut RunPropertiesProjection,
    property: &str,
    attrs: &BTreeMap<String, String>,
) {
    let enabled = attrs
        .get("w:val")
        .or_else(|| attrs.get("val"))
        .map(|value| !matches!(value.as_str(), "false" | "0" | "off"))
        .unwrap_or(true);
    match property {
        "b" => properties.bold = enabled,
        "i" => properties.italic = enabled,
        "u" => properties.underline = enabled,
        "strike" => properties.strike = enabled,
        _ => {}
    }
}

fn merge_run_properties(target: &mut RunPropertiesProjection, overlay: &RunPropertiesProjection) {
    if overlay.run_style_id.is_some() {
        target.run_style_id = overlay.run_style_id.clone();
    }
    target.bold |= overlay.bold;
    target.italic |= overlay.italic;
    target.underline |= overlay.underline;
    target.strike |= overlay.strike;
}

#[derive(Debug, Clone, Copy)]
enum PropertyContext {
    Paragraph,
    Run,
}

#[derive(Debug)]
struct StyleBuilder {
    style_id: String,
    style_type: StyleType,
    name: Option<String>,
    aliases: Vec<String>,
    based_on: Option<StyleReference>,
    next: Option<StyleReference>,
    link: Option<StyleReference>,
    is_default: bool,
    custom_style: bool,
    q_format: bool,
    semi_hidden: bool,
    unhide_when_used: bool,
    ui_priority: Option<String>,
    paragraph_properties: ParagraphPropertiesProjection,
    run_properties: RunPropertiesProjection,
}

impl StyleBuilder {
    fn finish(self) -> StyleDefinitionProjection {
        StyleDefinitionProjection {
            style_id: self.style_id,
            style_type: self.style_type,
            name: self.name,
            aliases: self.aliases,
            based_on: self.based_on,
            next: self.next,
            link: self.link,
            is_default: self.is_default,
            custom_style: self.custom_style,
            q_format: self.q_format,
            semi_hidden: self.semi_hidden,
            unhide_when_used: self.unhide_when_used,
            ui_priority: self.ui_priority,
            paragraph_properties: self.paragraph_properties,
            run_properties: self.run_properties,
            resolved_style: None,
        }
    }
}

#[derive(Debug)]
struct AbstractNumberingBuilder {
    abstract_num_id: String,
    levels: Vec<NumberingLevelProjection>,
}

#[derive(Debug)]
struct NumberingInstanceBuilder {
    num_id: String,
    abstract_num_id: Option<String>,
    level_overrides: Vec<NumberingLevelProjection>,
}

#[derive(Debug)]
struct NumberingLevelBuilder {
    level: NumberingLevelProjection,
}

impl NumberingLevelBuilder {
    fn new(ilvl: String) -> Self {
        Self {
            level: NumberingLevelProjection {
                ilvl,
                start: None,
                start_override: None,
                num_fmt: None,
                lvl_text: None,
                suff: None,
                paragraph_style: None,
                lvl_restart: None,
                paragraph_properties: ParagraphPropertiesProjection::default(),
                run_properties: RunPropertiesProjection::default(),
            },
        }
    }

    fn new_override(ilvl: String) -> Self {
        Self::new(ilvl)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    use base64::Engine;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use sha2::Sha256;
    use zip::write::FileOptions;
    use zip::ZipWriter;

    use super::*;

    #[test]
    fn docx_import_is_implemented() {
        assert!(is_implemented());
    }

    #[test]
    fn imports_minimal_docx_and_deduplicates_identical_blobs() {
        let docx = write_test_docx("import-dedup", false, None);
        let package = import_docx(&docx).unwrap();

        assert_eq!(package.document.opc.parts.len(), 6);
        assert_eq!(package.objects.len(), 5);
        assert!(package
            .document
            .opc
            .relationships
            .iter()
            .any(|rel| rel.target_mode == TargetMode::External
                && rel.target == "https://example.invalid/image?a=1&b=2"));

        let document_part = package
            .document
            .opc
            .parts
            .iter()
            .find(|part| part.original_path == "word/document.xml")
            .unwrap();
        let copy_part = package
            .document
            .opc
            .parts
            .iter()
            .find(|part| part.original_path == "word/copy.xml")
            .unwrap();
        assert_eq!(document_part.content_digest, copy_part.content_digest);

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn discovers_and_verifies_opc_xml_signature_from_relationship_graph() {
        let docx = write_signed_docx("signature-valid", false, false);
        let package = import_docx(&docx).unwrap();
        let signatures = package.document.signatures.as_ref().unwrap();

        assert_eq!(signatures.origins.len(), 1);
        assert_eq!(signatures.signatures.len(), 1);
        let signature = &signatures.signatures[0];
        assert_eq!(signature.origin_part_path, "_xmlsignatures/origin.sigs");
        assert_eq!(signature.signature_part_path, "_xmlsignatures/sig1.xml");
        assert_eq!(
            signature.verification.status,
            SignatureVerificationStatus::Valid
        );
        assert_eq!(
            signature.verification.certificate_trust,
            SignatureVerificationStatus::UnassessedTrust
        );
        assert!(signature
            .verification
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_SIGNATURE_TRUST_UNASSESSED"));
        assert_eq!(signature.verification.references.len(), 1);
        assert_eq!(
            signature.verification.references[0].status,
            SignatureVerificationStatus::Valid
        );

        std::fs::remove_file(docx).unwrap();
    }

    fn write_signed_docx(
        name: &str,
        tamper_reference_target: bool,
        tamper_signature_value: bool,
    ) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        let document_bytes = b"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>signed</w:t></w:r></w:p></w:body></w:document>".to_vec();
        let digest =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&document_bytes));
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let signed_info = format!(
            "<ds:SignedInfo xmlns:ds=\"{DSIG_NAMESPACE}\"><ds:CanonicalizationMethod Algorithm=\"{C14N_10}\"/><ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/><ds:Reference URI=\"/word/document.xml\"><ds:DigestMethod Algorithm=\"{SHA256_DIGEST}\"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        );
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let mut signature_value = base64::engine::general_purpose::STANDARD
            .encode(signing_key.sign(signed_info.as_bytes()).to_vec());
        if tamper_signature_value {
            signature_value.replace_range(0..1, "A");
        }
        let modulus =
            base64::engine::general_purpose::STANDARD.encode(public_key.n().to_bytes_be());
        let exponent =
            base64::engine::general_purpose::STANDARD.encode(public_key.e().to_bytes_be());
        let signature_xml = format!(
            "<ds:Signature xmlns:ds=\"{DSIG_NAMESPACE}\">{signed_info}<ds:SignatureValue>{signature_value}</ds:SignatureValue><ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{modulus}</ds:Modulus><ds:Exponent>{exponent}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue><ds:X509Data><ds:X509Certificate>not-a-certificate</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object Id=\"idOfficeObject\"><SignatureInfoV1><SetupID>setup</SetupID><SignatureComments>fixture</SignatureComments><SignatureType>1</SignatureType></SignatureInfoV1></ds:Object></ds:Signature>"
        );
        let final_document_bytes = if tamper_reference_target {
            b"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>tampered</w:t></w:r></w:p></w:body></w:document>".to_vec()
        } else {
            document_bytes
        };
        let file = fs::File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        add(&mut zip, options, "[Content_Types].xml", br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/_xmlsignatures/origin.sigs" ContentType="application/vnd.openxmlformats-package.digital-signature-origin"/><Override PartName="/_xmlsignatures/sig1.xml" ContentType="application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rDoc" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rSigOrigin" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin" Target="_xmlsignatures/origin.sigs"/></Relationships>"#);
        add(
            &mut zip,
            options,
            "word/document.xml",
            &final_document_bytes,
        );
        add(&mut zip, options, "_xmlsignatures/origin.sigs", b"");
        add(&mut zip, options, "_xmlsignatures/_rels/origin.sigs.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rSig1" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature" Target="sig1.xml"/></Relationships>"#);
        add(
            &mut zip,
            options,
            "_xmlsignatures/sig1.xml",
            signature_xml.as_bytes(),
        );
        zip.finish().unwrap();
        path
    }

    enum X509FixtureKeyInfo<'a> {
        X509Only {
            certificates: Vec<&'a str>,
        },
        RsaKeyValueAndX509 {
            certificates: Vec<&'a str>,
            bad_rsa_key_value: bool,
        },
    }

    fn write_x509_signed_docx(
        name: &str,
        key_info: X509FixtureKeyInfo<'_>,
        tamper_signature_value: bool,
    ) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        let document_bytes = b"<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>x509 signed</w:t></w:r></w:p></w:body></w:document>".to_vec();
        let digest =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&document_bytes));
        let private_der = base64::engine::general_purpose::STANDARD
            .decode(RSA1_PKCS8_B64)
            .unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_der(&private_der).unwrap();
        let public_key = private_key.to_public_key();
        let signed_info = format!(
            "<ds:SignedInfo xmlns:ds=\"{DSIG_NAMESPACE}\"><ds:CanonicalizationMethod Algorithm=\"{C14N_10}\"/><ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/><ds:Reference URI=\"/word/document.xml\"><ds:DigestMethod Algorithm=\"{SHA256_DIGEST}\"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        );
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let mut signature_value = base64::engine::general_purpose::STANDARD
            .encode(signing_key.sign(signed_info.as_bytes()).to_vec());
        if tamper_signature_value {
            signature_value.replace_range(
                0..1,
                if signature_value.starts_with('A') {
                    "B"
                } else {
                    "A"
                },
            );
        }
        let key_info_xml = x509_fixture_key_info_xml(key_info, &public_key);
        let signature_xml = format!(
            "<ds:Signature xmlns:ds=\"{DSIG_NAMESPACE}\">{signed_info}<ds:SignatureValue>{signature_value}</ds:SignatureValue>{key_info_xml}<ds:Object Id=\"idOfficeObject\"><SignatureInfoV1><SetupID>setup</SetupID><SignatureComments>x509 fixture</SignatureComments><SignatureType>1</SignatureType></SignatureInfoV1></ds:Object></ds:Signature>"
        );
        let file = fs::File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        add(&mut zip, options, "[Content_Types].xml", br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/_xmlsignatures/origin.sigs" ContentType="application/vnd.openxmlformats-package.digital-signature-origin"/><Override PartName="/_xmlsignatures/sig1.xml" ContentType="application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rDoc" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rSigOrigin" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin" Target="_xmlsignatures/origin.sigs"/></Relationships>"#);
        add(&mut zip, options, "word/document.xml", &document_bytes);
        add(&mut zip, options, "_xmlsignatures/origin.sigs", b"");
        add(&mut zip, options, "_xmlsignatures/_rels/origin.sigs.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rSig1" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature" Target="sig1.xml"/></Relationships>"#);
        add(
            &mut zip,
            options,
            "_xmlsignatures/sig1.xml",
            signature_xml.as_bytes(),
        );
        zip.finish().unwrap();
        path
    }

    fn x509_fixture_key_info_xml(
        key_info: X509FixtureKeyInfo<'_>,
        valid_public_key: &rsa::RsaPublicKey,
    ) -> String {
        let mut xml = String::from("<ds:KeyInfo>");
        match key_info {
            X509FixtureKeyInfo::X509Only { certificates } => {
                push_x509_data(&mut xml, certificates);
            }
            X509FixtureKeyInfo::RsaKeyValueAndX509 {
                certificates,
                bad_rsa_key_value,
            } => {
                let (modulus, exponent) = if bad_rsa_key_value {
                    let mut rng = rsa::rand_core::OsRng;
                    let bad_key = RsaPrivateKey::new(&mut rng, 2048).unwrap().to_public_key();
                    (bad_key.n().to_bytes_be(), bad_key.e().to_bytes_be())
                } else {
                    (
                        valid_public_key.n().to_bytes_be(),
                        valid_public_key.e().to_bytes_be(),
                    )
                };
                xml.push_str("<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>");
                xml.push_str(&base64::engine::general_purpose::STANDARD.encode(modulus));
                xml.push_str("</ds:Modulus><ds:Exponent>");
                xml.push_str(&base64::engine::general_purpose::STANDARD.encode(exponent));
                xml.push_str("</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>");
                push_x509_data(&mut xml, certificates);
            }
        }
        xml.push_str("</ds:KeyInfo>");
        xml
    }

    fn push_x509_data(xml: &mut String, certificates: Vec<&str>) {
        xml.push_str("<ds:X509Data>");
        for certificate in certificates {
            xml.push_str("<ds:X509Certificate>");
            xml.push_str(certificate);
            xml.push_str("</ds:X509Certificate>");
        }
        xml.push_str("</ds:X509Data>");
    }

    const RSA1_PKCS8_B64: &str = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMf7EATZAVhQv7/88hdEpP0hD4LZKEyv+8fismtMkqaAfqRLserz6ljCf9kgeCQTgti53peBtH/yckPdcV3dbDRwTY+sINEzn1C7pA7j2RPd+oCMr6S19xngMofDZeiJ8WjWni3zdf5UZG/9jOPlYE7UFijfucbpfRccsAf5TEJu8lWgU/Vm5VUqmLJm/ViGynfAs6VIbvXY01ctQp+DtkKzZ3hN0/QWSHrr0LvMUZ58I3keirrky1TOFzDZctwcqJWb0xrByVBvDzISWL/E6J+mV0/WGuWI/vXGWokFduk8TVLhw9HxRgmwe/WdmYMj5oKVCtvXLpYu9Rw50QCRFhAgMBAAECggEAATElWPkaw+VYoollLa692CVDUA8D8Z41S2X43mrjWUnt8eGgrZcb6F8exI2bWZkDuNA9hWTb09ma4s0xecEnRVAeqR0dEHJyPglpdoNs/HG94f7bIAZccg8XuZ6vunFVbA469cWTTw3JERTgsKMQYUr4vJhTRSAn5mKhaklUFqiYxK2VX8KFmwZU4gHpV8c4bcZtQn1ZvrMPXo2yYJXQc1oS1oM1zC6z76uUTeOcDUZYCN8+5gKxjwP5HT8NjH+wv5cNiZsWodXD+uq4Q9vsVCA6glOjsWWVuLS0CzP+DxUNba94PI0eIGDshK+WgU7AeA1NMtlDuHGcFIKnwqqOAQKBgQDvrY/mlOB9SRyGnw+ET8l7A5DWqSUGvdmWQtOeYutEcI09WYgBKzlj/g5B5eRaoPCA5G0NDIc3WroxpOf/iO0XwjDpHNALGkP9olEuGSZQ6Z9N8uLD/uaP2XSpYxluJ1PGLusdNlY1oF1Bwig4lCSp/1e80SrItbudTo4Vz56ZcQKBgQDabNTOr+RFypQFNUZEMO23VvKNwQciVoE85y9XGK5y0cIIzuCBWA1Iqh582Co28qtR7xpKBqFXOWECFmlqX6TzmGG00BWK1EvJTwDEIPNaEz/cKYswbOnhEEJf2jcSG515dr+ynVUmIAo9idsM+ys3Y5x3nUSLkeyqZI8l3QV+8QKBgDxxCXv9iUsu98mfLRuRv16NPKZVi2fS0p9JBPLJQUlGFOgmvtyEmPl1ZQULQ3XzZhMrB7Eluqej8pZ4XqUbU6cNKqZuxKw4GHNKzqwQXZBECg9vM+53Ro96KChbPFuCAWdWB6abQExPv5TIsLnr6f8QzIBqQx7QbZqy57PqYrWRAoGBAKzlIL5KdILaC7jjpq8rm79YT77tYFxJ5Rr0VIC4xL2WU+Ts/MDllf5Cysc/xIqiJAJDJaga/3MvtB4W53KQKt23bP/XBnZR/Xtn0c9t1bMjMZVwPQEj9S111VRSQu1OdqRC3xLffxsimXiEuqPX3SmG67+y+SMRayilWLo77bHBAoGBAMIbMu7LAymVwuMUwCyWBhZv09XacDdnZ59hb7kAlQtyqmqnrXyOAd8ESz1r2xONA5AkAXpkZFdxFyvQ4TeIDG4b1WeVeC2YtV9cqjNI/oIB/XTuTEEttpn3UjFPTK/5zS93B9mPXsxzzVNI83CcEAL1p2miOIdXsdMCBzsE9gM3";
    const RSA1_CERT_B64: &str = "MIICyjCCAbKgAwIBAgIUEY9fqe5jyxGm1tqMPwNuhuPePXAwDQYJKoZIhvcNAQELBQAwHzEdMBsGA1UEAwwUVFVGRi1DVk4gUlNBIGZpeHR1cmUwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjAfMR0wGwYDVQQDDBRUVUZGLUNWTiBSU0EgZml4dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMx/sQBNkBWFC/v/zyF0Sk/SEPgtkoTK/7x+Kya0ySpoB+pEux6vPqWMJ/2SB4JBOC2Lnel4G0f/JyQ91xXd1sNHBNj6wg0TOfULukDuPZE936gIyvpLX3GeAyh8Nl6InxaNaeLfN1/lRkb/2M4+VgTtQWKN+5xul9FxywB/lMQm7yVaBT9WblVSqYsmb9WIbKd8CzpUhu9djTVy1Cn4O2QrNneE3T9BZIeuvQu8xRnnwjeR6KuuTLVM4XMNly3ByolZvTGsHJUG8PMhJYv8Ton6ZXT9Ya5Yj+9cZaiQV26TxNUuHD0fFGCbB79Z2ZgyPmgpUK29culi71HDnRAJEWECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAn/s463UQRE2dFK8XCPGC/kn5Xc3bLho7UsphclGgpjTUJA1Ysv0yHwNxavWECaKFORMP7ZSOVFojIKlbF/jdglJuySvZ0yd35qvdnaIL/Jm+niWfmARUMzMeRI0NSes9vyGDbWoouxcCea9d6h/Ncxy4/xQzyfr4VEm6IbRiKA7fvLE3dte98zAsSidcZ8CivBakApJ6bxyevUd+eOWKhD/0+gOWrEdrZVA1Blvna+2BBp5ZKAg2WnQ9ZlS5a5xfbvitjL6lIG2WkvlQG3smJ5y/o3/6UtE+c5bxf1Ba/t6/X3nqWTeePgEhwjy0uXMhrVYL7fbHk1Y0pryZaVQNZw==";
    const RSA2_CERT_B64: &str = "MIIC1jCCAb6gAwIBAgIULc1xT5RKtySzZNEt8SQdWxAjUKowDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwaVFVGRi1DVk4gb3RoZXIgUlNBIGZpeHR1cmUwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjAlMSMwIQYDVQQDDBpUVUZGLUNWTiBvdGhlciBSU0EgZml4dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANK8UBCGj5m2VEe06bdG7AfsJD+51qznbQLF8MZl4csNayWu30M4X5hRRLop3O9kT1hno2sjLISISGvJEwOEXzxJ6JLF/hS9WEQX8Uo5E1K4a2OJCDAicyK8KB9waRm2oHha3GERORnPr3Oob78vr3IentcRzeFfpnfzSLlZ4T+vhA3eiU6G8/HDyotumPqpYkgrhC8b/7LRmF+JkTPc0Ytfe2Mj4MgpUhtaok6yknrJ+atISz0EL/d4AthkJVjQnGrJXfpVIhVI5dwmNN0b+DideIDGNvXzW03yjipC+E+GmNy36rH6keqcpa7Uj/cazUOOS2w2+mTOfoIezTSP/Y8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAHRpXGS/SgBlBFhCQoG8CUCGpvQED3aF8gd7kie76IHyaf1UEvzw1d2X7+uOfidjQ/YldhqGrPrBv6gE2VshQX+SJFLKk07rOzx7e5ELGx2bbedyW4UOTC/5zUqrK5z7KvYiLJ7IrP4P4n11UHnT1kK3KP0qDMYkGKVbv8mVoW1AFVDk5sY56pUO1Qet3OTaEmc3oBwLZyfQIbp2IZtL4qIxwzZQfzDcAyjZkRag/0+q2agKg2TBjb+zVquzAdkv25psKExmuvWA1yzQe3gKsQCcUElxcC0xR2cEM+iSgbzClDRjKjdFM3hWQL4epj9mShuZ7/LM1s5ppP5sF3IhOtA==";
    const EC_CERT_B64: &str = "MIIBPDCB4qADAgECAhRQY9nW63QiYQ+KTw+hRRka/wOk/zAKBggqhkjOPQQDAjAeMRwwGgYDVQQDDBNUVUZGLUNWTiBFQyBmaXh0dXJlMB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowHjEcMBoGA1UEAwwTVFVGRi1DVk4gRUMgZml4dHVyZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOydcTcN3lLwlHKuzRe6vI/SE26bWc0YrTTTsO1lJOOnCaD9vX955H7WnwMsIvtwUaR9+fa0b3jL1vfi0tv0WycwCgYIKoZIzj0EAwIDSQAwRgIhAMTTpVulPEPL+PScdgY6nclr05C6TGtC+0ZmEs/S4kvAAiEAqfSnUrSczbsP7uxJGVmGIfOgjUvkQMFwCgU7IPXHC08=";

    #[test]
    fn signature_reference_digest_mismatch_is_reported() {
        let docx = write_signed_docx("signature-reference-tamper", true, false);
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.references[0].status,
            SignatureVerificationStatus::Invalid
        );
        assert!(signature
            .verification
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_SIGNATURE_REFERENCE_DIGEST_MISMATCH"));

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn signature_value_mismatch_is_reported() {
        let docx = write_signed_docx("signature-value-tamper", false, true);
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.signature_value_status,
            SignatureVerificationStatus::Invalid
        );
        assert!(signature
            .verification
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_SIGNATURE_VALUE_MISMATCH"));

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn x509_only_signature_verifies_with_certificate_public_key() {
        let docx = write_x509_signed_docx(
            "x509-only-valid",
            X509FixtureKeyInfo::X509Only {
                certificates: vec![RSA1_CERT_B64],
            },
            false,
        );
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.cryptographic_validity,
            SignatureVerificationStatus::Valid
        );
        assert_eq!(
            signature.verification.key_source,
            Some(SignatureKeySource::X509Certificate)
        );
        assert_eq!(signature.verification.certificate_index, Some(0));
        assert!(signature.verification.public_key_fingerprint.is_some());
        assert_eq!(
            signature.verification.certificate_trust,
            SignatureVerificationStatus::UnassessedTrust
        );

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn rsa_key_value_is_preferred_when_it_matches_x509_key() {
        let docx = write_x509_signed_docx(
            "rsa-key-value-and-x509",
            X509FixtureKeyInfo::RsaKeyValueAndX509 {
                certificates: vec![RSA1_CERT_B64],
                bad_rsa_key_value: false,
            },
            false,
        );
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.status,
            SignatureVerificationStatus::Valid
        );
        assert_eq!(
            signature.verification.key_source,
            Some(SignatureKeySource::RsaKeyValue)
        );
        assert_eq!(signature.verification.certificate_index, None);

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn bad_rsa_key_value_falls_back_to_valid_x509_key() {
        let docx = write_x509_signed_docx(
            "bad-rsa-key-value-valid-x509",
            X509FixtureKeyInfo::RsaKeyValueAndX509 {
                certificates: vec![RSA1_CERT_B64],
                bad_rsa_key_value: true,
            },
            false,
        );
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.status,
            SignatureVerificationStatus::Valid
        );
        assert_eq!(
            signature.verification.key_source,
            Some(SignatureKeySource::X509Certificate)
        );
        assert_eq!(signature.verification.certificate_index, Some(0));

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn multiple_x509_certificates_select_matching_certificate_index() {
        let docx = write_x509_signed_docx(
            "multiple-x509",
            X509FixtureKeyInfo::X509Only {
                certificates: vec![RSA2_CERT_B64, RSA1_CERT_B64],
            },
            false,
        );
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.status,
            SignatureVerificationStatus::Valid
        );
        assert_eq!(
            signature.verification.key_source,
            Some(SignatureKeySource::X509Certificate)
        );
        assert_eq!(signature.verification.certificate_index, Some(1));

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn x509_non_rsa_certificate_is_unsupported_algorithm() {
        let docx = write_x509_signed_docx(
            "x509-non-rsa",
            X509FixtureKeyInfo::X509Only {
                certificates: vec![EC_CERT_B64],
            },
            false,
        );
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.status,
            SignatureVerificationStatus::UnsupportedAlgorithm
        );
        assert!(signature.verification.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "CVN_SIGNATURE_CERTIFICATE_KEY_ALGORITHM_UNSUPPORTED"
        }));

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn x509_public_key_tamper_causes_signature_value_mismatch() {
        let docx = write_x509_signed_docx(
            "x509-public-key-tamper",
            X509FixtureKeyInfo::X509Only {
                certificates: vec![RSA2_CERT_B64],
            },
            false,
        );
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.signature_value_status,
            SignatureVerificationStatus::Invalid
        );
        assert!(signature
            .verification
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_SIGNATURE_VALUE_MISMATCH"));

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn x509_only_signature_value_tamper_is_detected() {
        let docx = write_x509_signed_docx(
            "x509-signature-value-tamper",
            X509FixtureKeyInfo::X509Only {
                certificates: vec![RSA1_CERT_B64],
            },
            true,
        );
        let package = import_docx(&docx).unwrap();
        let signature = &package.document.signatures.as_ref().unwrap().signatures[0];

        assert_eq!(
            signature.verification.signature_value_status,
            SignatureVerificationStatus::Invalid
        );
        assert!(signature
            .verification
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_SIGNATURE_VALUE_MISMATCH"));

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn x509_only_signature_import_is_deterministic() {
        let docx = write_x509_signed_docx(
            "x509-deterministic",
            X509FixtureKeyInfo::X509Only {
                certificates: vec![RSA1_CERT_B64],
            },
            false,
        );
        let package_a = import_docx(&docx).unwrap();
        let package_b = import_docx(&docx).unwrap();
        assert_eq!(package_a.document.signatures, package_b.document.signatures);

        let out_a = std::env::temp_dir().join(format!(
            "tuff-cvn-x509-deterministic-a-{}",
            std::process::id()
        ));
        let out_b = std::env::temp_dir().join(format!(
            "tuff-cvn-x509-deterministic-b-{}",
            std::process::id()
        ));
        cleanup_dir(&out_a);
        cleanup_dir(&out_b);
        write_package(&out_a, &package_a).unwrap();
        write_package(&out_b, &package_b).unwrap();
        let cvn_a = fs::read(out_a.join(cvn_package::MANIFEST_FILE)).unwrap();
        let cvn_b = fs::read(out_b.join(cvn_package::MANIFEST_FILE)).unwrap();
        assert_eq!(cvn_a, cvn_b);
        cleanup_dir(&out_a);
        cleanup_dir(&out_b);
        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn duplicate_zip_entry_is_rejected() {
        let docx = write_test_docx("duplicate-entry", true, None);
        let error = import_docx(&docx).unwrap_err();
        assert!(matches!(error, DocxImportError::DuplicateEntry(_)));
        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn path_traversal_entry_is_rejected() {
        let docx = write_test_docx("path-traversal", false, Some("../evil.xml"));
        let error = import_docx(&docx).unwrap_err();
        assert!(matches!(error, DocxImportError::InvalidPath(_)));
        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn oversized_expansion_limit_is_rejected() {
        let docx = write_test_docx("oversized", false, None);
        let error = import_docx_with_limits(
            &docx,
            ImportLimits {
                max_single_entry_uncompressed_size: 10,
                ..ImportLimits::default()
            },
        )
        .unwrap_err();
        assert!(matches!(error, DocxImportError::EntrySizeLimit { .. }));
        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn semantic_projection_is_deterministic_and_preserves_supported_shapes() {
        let docx = write_semantic_docx("semantic");
        let first = import_docx(&docx).unwrap();
        let second = import_docx(&docx).unwrap();

        assert_eq!(first.document.semantic, second.document.semantic);
        assert_eq!(first.document.semantic.blocks.len(), 4);
        assert!(!first.document.semantic.unsupported_features.is_empty());

        let ids = collect_semantic_ids(&first.document.semantic);
        assert_eq!(ids, collect_semantic_ids(&second.document.semantic));

        let first_paragraph = match &first.document.semantic.blocks[0] {
            SemanticBlock::Paragraph(paragraph) => paragraph,
            _ => panic!("expected paragraph"),
        };
        assert_eq!(
            first_paragraph.source_identifier.as_deref(),
            Some("00ABCDEF")
        );
        assert_eq!(
            first_paragraph.properties.style_id.as_deref(),
            Some("Heading1")
        );
        assert_eq!(first_paragraph.runs.len(), 2);
        assert!(first_paragraph.runs[0].properties.bold);
        assert!(first_paragraph.runs[0].properties.italic);
        assert!(first_paragraph.runs[0].properties.underline);
        assert_eq!(
            first_paragraph.runs[0].properties.run_style_id.as_deref(),
            Some("Strong")
        );
        assert!(matches!(
            first_paragraph.runs[0].inlines[0],
            SemanticInline::Text(SemanticText {
                preserve_space: true,
                ..
            })
        ));
        assert!(first_paragraph
            .runs
            .iter()
            .flat_map(|run| run.inlines.iter())
            .any(|inline| matches!(inline, SemanticInline::Tab)));
        assert!(first_paragraph
            .runs
            .iter()
            .flat_map(|run| run.inlines.iter())
            .any(|inline| matches!(inline, SemanticInline::LineBreak { break_kind } if break_kind == "br")));

        let empty_paragraph = match &first.document.semantic.blocks[1] {
            SemanticBlock::Paragraph(paragraph) => paragraph,
            _ => panic!("expected empty paragraph"),
        };
        assert!(empty_paragraph.source_identifier.is_none());
        assert!(empty_paragraph.runs.is_empty());

        let table = match &first.document.semantic.blocks[2] {
            SemanticBlock::Table(table) => table,
            _ => panic!("expected table"),
        };
        assert_eq!(table.rows.len(), 1);
        assert_eq!(table.rows[0].cells.len(), 2);
        assert_eq!(table.rows[0].cells[0].grid_span.as_deref(), Some("2"));
        assert!(table.rows[0].cells[1]
            .blocks
            .iter()
            .any(|block| matches!(block, SemanticBlock::Table(_))));

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn style_and_numbering_projection_is_deterministic_and_resolved() {
        let docx = write_style_numbering_docx("style-numbering");
        let first = import_docx(&docx).unwrap();
        let second = import_docx(&docx).unwrap();

        assert_eq!(
            first.document.semantic.styles,
            second.document.semantic.styles
        );
        assert_eq!(
            first.document.semantic.numbering,
            second.document.semantic.numbering
        );

        let styles = first.document.semantic.styles.as_ref().unwrap();
        assert!(styles
            .definitions
            .iter()
            .any(|style| style.style_id == "BodyText"
                && style
                    .resolved_style
                    .as_ref()
                    .is_some_and(|resolved| resolved.chain == ["Normal", "BodyText"]
                        && resolved.run_properties.bold)));
        assert!(styles
            .definitions
            .iter()
            .any(|style| style.style_id == "Strong"
                && style.style_type == StyleType::Character
                && style.run_properties.italic));
        assert!(styles
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_STYLE_INHERITANCE_CYCLE"));
        assert!(styles
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_STYLE_BASE_MISSING"));
        assert!(!styles.unsupported_features.is_empty());

        let numbering = first.document.semantic.numbering.as_ref().unwrap();
        assert!(numbering
            .abstract_numbers
            .iter()
            .any(|abstract_num| abstract_num.abstract_num_id == "10"
                && abstract_num.levels.iter().any(|level| level.ilvl == "1")));
        assert!(numbering
            .instances
            .iter()
            .any(|instance| instance.num_id == "20"
                && instance.abstract_num_id.as_deref() == Some("10")
                && instance.level_overrides.iter().any(
                    |level| level.ilvl == "1" && level.start_override.as_deref() == Some("5")
                )));
        assert!(numbering
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_NUMBERING_INSTANCE_MISSING"));
        assert!(numbering
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_ABSTRACT_NUMBERING_MISSING"));
        assert!(numbering
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_NUMBERING_LEVEL_MISSING"));
        assert!(!numbering.unsupported_features.is_empty());

        let first_paragraph = match &first.document.semantic.blocks[0] {
            SemanticBlock::Paragraph(paragraph) => paragraph,
            _ => panic!("expected paragraph"),
        };
        assert_eq!(
            first_paragraph.properties.style_id.as_deref(),
            Some("BodyText")
        );
        assert_eq!(
            first_paragraph
                .resolved_style
                .as_ref()
                .unwrap()
                .style_id
                .as_str(),
            "BodyText"
        );
        assert!(
            first_paragraph
                .resolved_style
                .as_ref()
                .unwrap()
                .run_properties
                .bold
        );
        assert_eq!(
            first_paragraph.numbering.as_ref().unwrap().num_id.as_str(),
            "20"
        );
        assert_eq!(
            first_paragraph.numbering.as_ref().unwrap().ilvl.as_deref(),
            Some("1")
        );
        assert_eq!(
            first_paragraph
                .numbering
                .as_ref()
                .unwrap()
                .resolved_level
                .as_ref()
                .unwrap()
                .start_override
                .as_deref(),
            Some("5")
        );
        assert!(
            first_paragraph.runs[0]
                .resolved_style
                .as_ref()
                .unwrap()
                .run_properties
                .italic
        );
        assert!(first_paragraph.runs[0].properties.bold);

        std::fs::remove_file(docx).unwrap();
    }

    #[test]
    fn missing_optional_style_and_numbering_parts_are_allowed() {
        let docx = write_semantic_docx("missing-style-numbering");
        let package = import_docx(&docx).unwrap();

        assert!(package.document.semantic.styles.is_none());
        assert!(package.document.semantic.numbering.is_none());

        std::fs::remove_file(docx).unwrap();
    }

    fn write_test_docx(
        name: &str,
        duplicate: bool,
        extra_path: Option<&str>,
    ) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());

        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#);
        let document = br#"<w:document b="2" a="1">  <w:body>Hello</w:body></w:document>"#;
        add(&mut zip, options, "word/document.xml", document);
        add(&mut zip, options, "word/copy.xml", document);
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdImg" Type="image" Target="media/image1.bin"/><Relationship Id="rIdExt" Type="hyperlink" Target="https://example.invalid/image?a=1&amp;b=2" TargetMode="External"/></Relationships>"#);
        add(&mut zip, options, "word/media/image1.bin", b"image-bytes");
        if duplicate {
            add(&mut zip, options, "word/document.xml", b"duplicate");
        }
        if let Some(path) = extra_path {
            add(&mut zip, options, path, b"evil");
        }
        zip.finish().unwrap();
        path
    }

    fn write_semantic_docx(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());

        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/><Relationship Id="rIdExt" Type="hyperlink" Target="https://example.invalid/" TargetMode="External"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdInternal" Type="image" Target="media/image1.bin"/></Relationships>"#);
        add(&mut zip, options, "word/media/image1.bin", b"image-bytes");
        add(&mut zip, options, "word/document.xml", br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:cx="urn:custom"><w:body><w:p w14:paraId="00ABCDEF"><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:rPr><w:rStyle w:val="Strong"/><w:b/><w:i/><w:u w:val="single"/></w:rPr><w:t xml:space="preserve"> Hello </w:t><w:tab/><w:br/></w:r><w:r><w:t>World</w:t></w:r></w:p><w:p/><w:tbl><w:tr><w:tc><w:tcPr><w:gridSpan w:val="2"/></w:tcPr><w:p><w:r><w:t>Cell 1</w:t></w:r></w:p></w:tc><w:tc><w:tbl><w:tr><w:tc><w:p><w:r><w:t>Nested</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:tc></w:tr></w:tbl><w:p><cx:unknown>kept raw</cx:unknown></w:p></w:body></w:document>"#);
        zip.finish().unwrap();
        path
    }

    fn write_style_numbering_docx(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());

        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="styles" Target="styles.xml"/><Relationship Id="rIdNumbering" Type="numbering" Target="numbering.xml"/></Relationships>"#);
        add(&mut zip, options, "word/document.xml", br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:pPr><w:pStyle w:val="BodyText"/><w:numPr><w:ilvl w:val="1"/><w:numId w:val="20"/></w:numPr></w:pPr><w:r><w:rPr><w:rStyle w:val="Strong"/><w:b/></w:rPr><w:t>Styled numbered</w:t></w:r></w:p><w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="404"/></w:numPr></w:pPr></w:p><w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="21"/></w:numPr></w:pPr></w:p><w:p><w:pPr><w:numPr><w:ilvl w:val="9"/><w:numId w:val="20"/></w:numPr></w:pPr></w:p></w:body></w:document>"#);
        add(&mut zip, options, "word/styles.xml", br#"<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:cx="urn:style-extra"><w:style w:type="paragraph" w:styleId="Normal" w:default="1"><w:name w:val="Normal"/><w:rPr><w:b/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="BodyText" w:customStyle="1"><w:name w:val="Body Text"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:link w:val="Strong"/><w:qFormat/><w:uiPriority w:val="9"/><w:rPr><w:i/></w:rPr></w:style><w:style w:type="character" w:styleId="Strong"><w:name w:val="Strong"/><w:rPr><w:i/></w:rPr></w:style><w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/></w:style><w:style w:type="numbering" w:styleId="ListStyle"><w:name w:val="List Style"/></w:style><w:style w:type="paragraph" w:styleId="CycleA"><w:basedOn w:val="CycleB"/></w:style><w:style w:type="paragraph" w:styleId="CycleB"><w:basedOn w:val="CycleA"/></w:style><w:style w:type="paragraph" w:styleId="MissingBase"><w:basedOn w:val="NoSuchStyle"/></w:style><cx:unknown/></w:styles>"#);
        add(&mut zip, options, "word/numbering.xml", br#"<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:cx="urn:numbering-extra"><w:abstractNum w:abstractNumId="10"><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:suff w:val="tab"/><w:pStyle w:val="BodyText"/></w:lvl><w:lvl w:ilvl="1"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="*"/><w:lvlRestart w:val="1"/><w:rPr><w:b/></w:rPr></w:lvl></w:abstractNum><w:num w:numId="20"><w:abstractNumId w:val="10"/><w:lvlOverride w:ilvl="1"><w:startOverride w:val="5"/></w:lvlOverride></w:num><w:num w:numId="21"><w:abstractNumId w:val="999"/></w:num><cx:unknown/></w:numbering>"#);
        zip.finish().unwrap();
        path
    }

    fn write_story_docx(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());

        add(
            &mut zip,
            options,
            "[Content_Types].xml",
            br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/headerFirst.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/word/footerEven.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/><Override PartName="/word/endnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml"/><Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/></Types>"#,
        );
        add(
            &mut zip,
            options,
            "_rels/.rels",
            br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#,
        );
        add(
            &mut zip,
            options,
            "word/_rels/document.xml.rels",
            br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdHeader1" Type="header" Target="header1.xml"/><Relationship Id="rIdHeaderFirst" Type="header" Target="headerFirst.xml"/><Relationship Id="rIdFooter1" Type="footer" Target="footer1.xml"/><Relationship Id="rIdFooterEven" Type="footer" Target="footerEven.xml"/><Relationship Id="rIdFootnotes" Type="footnotes" Target="footnotes.xml"/><Relationship Id="rIdEndnotes" Type="endnotes" Target="endnotes.xml"/><Relationship Id="rIdComments" Type="comments" Target="comments.xml"/></Relationships>"#,
        );
        add(
            &mut zip,
            options,
            "word/document.xml",
            br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:cx="urn:story-extra"><w:body><w:p w14:paraId="11111111"><w:r><w:t>Main story</w:t></w:r><w:r><w:footnoteReference w:id="1"/><w:endnoteReference w:id="2"/><w:commentRangeStart w:id="4"/><w:t>commented</w:t><w:commentRangeEnd w:id="4"/><w:commentReference w:id="4"/></w:r></w:p><w:p><w:pPr><w:sectPr><w:headerReference r:id="rIdHeader1" w:type="default"/><w:footerReference r:id="rIdFooter1" w:type="default"/><w:headerReference r:id="rIdHeaderFirst" w:type="first"/><w:footerReference r:id="rIdFooterEven" w:type="even"/></w:sectPr></w:pPr></w:p></w:body></w:document>"#,
        );
        add(
            &mut zip,
            options,
            "word/header1.xml",
            br#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:cx="urn:story-extra"><w:p><w:r><w:t>Header</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>Header cell</w:t></w:r></w:p></w:tc></w:tr></w:tbl><cx:unknown/></w:hdr>"#,
        );
        add(
            &mut zip,
            options,
            "word/headerFirst.xml",
            br#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Header first</w:t></w:r></w:p></w:hdr>"#,
        );
        add(
            &mut zip,
            options,
            "word/footer1.xml",
            br#"<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Footer</w:t></w:r></w:p></w:ftr>"#,
        );
        add(
            &mut zip,
            options,
            "word/footerEven.xml",
            br#"<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Footer even</w:t></w:r></w:p></w:ftr>"#,
        );
        add(
            &mut zip,
            options,
            "word/footnotes.xml",
            br#"<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:cx="urn:story-extra"><w:footnote w:id="-1"/><w:footnote w:id="1"><w:p><w:r><w:t>Footnote one</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>Nested note</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:footnote><cx:unknown/></w:footnotes>"#,
        );
        add(
            &mut zip,
            options,
            "word/endnotes.xml",
            br#"<w:endnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:endnote w:id="2"><w:p><w:r><w:t>Endnote two</w:t></w:r></w:p></w:endnote></w:endnotes>"#,
        );
        add(
            &mut zip,
            options,
            "word/comments.xml",
            br#"<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:cx="urn:story-extra"><w:comment w:id="4" w:author="Alice" w:initials="AL" w:date="2026-01-01T00:00:00Z"><w:p><w:r><w:t>Comment body</w:t></w:r></w:p></w:comment><cx:unknown/></w:comments>"#,
        );
        zip.finish().unwrap();
        path
    }

    fn write_track_changes_docx(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());

        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdHeader1" Type="header" Target="header1.xml"/><Relationship Id="rIdFootnotes" Type="footnotes" Target="footnotes.xml"/></Relationships>"#);
        add(&mut zip, options, "word/document.xml", br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:w16du="http://schemas.microsoft.com/office/word/2018/wordml/cex"><w:body><w:p w14:paraId="11111111"><w:ins w:id="1" w:author="Alice" w:date="2026-01-01T00:00:00Z" w16du:dateUtc="2026-01-01T00:00:00Z"><w:r><w:t>inserted</w:t></w:r></w:ins><w:del w:id="2" w:author="Bob" w:date="not-a-date" w:rsidDel="00A1"><w:r><w:delText>deleted</w:delText></w:r></w:del><w:moveFrom w:id="3"><w:r><w:t>moved from</w:t></w:r></w:moveFrom><w:moveTo w:id="3"><w:r><w:t>moved to</w:t></w:r></w:moveTo></w:p><w:moveFromRangeStart w:id="9"/><w:moveToRangeStart w:id="10"/><w:moveToRangeEnd w:id="10"/><w:p><w:pPr><w:pPrChange w:id="11"><w:pPr><w:pStyle w:val="BodyText"/></w:pPr></w:pPrChange></w:pPr><w:r><w:rPrChange w:id="12"><w:rPr><w:b/></w:rPr></w:rPrChange></w:r></w:p><w:tbl><w:tr><w:trPr><w:trPrChange w:id="13"><w:trPr/></w:trPrChange></w:trPr><w:tc><w:tcPr><w:tcPrChange w:id="14"><w:tcPr/></w:tcPrChange></w:tcPr><w:p><w:r><w:t>table</w:t></w:r></w:p></w:tc></w:tr></w:tbl><w:sectPr><w:sectPrChange w:id="15"><w:sectPr/></w:sectPrChange></w:sectPr><w:headerReference r:id="rIdHeader1" w:type="default"/><w:footnoteReference w:id="1"/></w:body></w:document>"#);
        add(&mut zip, options, "word/header1.xml", br#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:ins w:id="20" w:author="Header"><w:r><w:t>header inserted</w:t></w:r></w:ins></w:p></w:hdr>"#);
        add(&mut zip, options, "word/footnotes.xml", br#"<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:footnote w:id="-1"/><w:footnote w:id="1"><w:p><w:del w:id="21" w:author="Footnote"><w:r><w:delText>footnote deleted</w:delText></w:r></w:del></w:p></w:footnote></w:footnotes>"#);
        zip.finish().unwrap();
        path
    }

    fn write_mce_docx(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());
        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdHeader1" Type="header" Target="header1.xml"/><Relationship Id="rIdFootnotes" Type="footnotes" Target="footnotes.xml"/></Relationships>"#);
        add(&mut zip, options, "word/document.xml", br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:wStrict="http://purl.oclc.org/ooxml/wordprocessingml/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:cx="urn:unsupported" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" mc:Ignorable="cx" mc:ProcessContent="cx:wrapper" mc:PreserveElements="cx:keep" mc:PreserveAttributes="cx:attr"><w:body><mc:AlternateContent mc:Ignorable="cx" mc:ProcessContent="cx:wrapper" mc:PreserveElements="cx:keep" mc:PreserveAttributes="cx:attr"><mc:Choice Requires="cx"><w:p><w:r><w:t>unsupported choice</w:t></w:r></w:p></mc:Choice><mc:Choice Requires="w wStrict"><w:p><w:r><w:t>supported second choice</w:t><mc:AlternateContent><mc:Choice Requires="w"><w:t>nested choice</w:t></mc:Choice><mc:Fallback><w:t>nested fallback</w:t></mc:Fallback></mc:AlternateContent><w:del w:id="31" w:author="MCE"><w:r><w:t>deleted in mce</w:t></w:r></w:del></w:r></w:p></mc:Choice><mc:Fallback><w:p><w:r><w:t>fallback not selected</w:t></w:r></w:p></mc:Fallback></mc:AlternateContent><w:p><w:r><mc:AlternateContent><mc:Choice Requires="cx"><w:t>bad inline</w:t></mc:Choice><mc:Fallback><w:t>inline fallback</w:t><w:tab/><w:br/></mc:Fallback></mc:AlternateContent></w:r></w:p><mc:AlternateContent><mc:Choice Requires="cx"><w:p><w:r><w:t>unsupported table choice</w:t></w:r></w:p></mc:Choice><mc:Fallback><w:tbl><w:tr><w:tc><w:p><w:r><w:t>fallback table</w:t></w:r></w:p></w:tc></w:tr></w:tbl></mc:Fallback></mc:AlternateContent><w:p><w:ins w:id="30" w:author="Alice"><w:r><mc:AlternateContent><mc:Choice Requires="w"><w:t>tracked mce insertion</w:t></mc:Choice></mc:AlternateContent></w:r></w:ins></w:p><w:tbl><w:tr><w:tc><mc:AlternateContent><mc:Choice Requires="missing"><w:p><w:r><w:t>bad table</w:t></w:r></w:p></mc:Choice></mc:AlternateContent></w:tc></w:tr></w:tbl><w:p><w:pPr><w:sectPr><w:headerReference r:id="rIdHeader1" w:type="default"/></w:sectPr></w:pPr></w:p><w:p><w:r><w:footnoteReference w:id="1"/></w:r></w:p></w:body></w:document>"#);
        add(&mut zip, options, "word/header1.xml", br#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"><mc:AlternateContent><mc:Choice Requires="w"><w:p><w:r><w:t>header choice</w:t></w:r></w:p></mc:Choice><mc:Fallback><w:p><w:r><w:t>header fallback</w:t></w:r></w:p></mc:Fallback></mc:AlternateContent></w:hdr>"#);
        add(&mut zip, options, "word/footnotes.xml", br#"<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"><w:footnote w:id="1"><mc:AlternateContent><mc:Choice Requires="w"><w:p><w:r><w:t>footnote choice</w:t></w:r></w:p></mc:Choice></mc:AlternateContent></w:footnote></w:footnotes>"#);
        zip.finish().unwrap();
        path
    }

    fn write_references_docx(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());
        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdHeader1" Type="header" Target="header1.xml"/><Relationship Id="rIdFootnotes" Type="footnotes" Target="footnotes.xml"/><Relationship Id="rIdExt" Type="hyperlink" Target="https://example.invalid/reference?a=1&amp;b=2" TargetMode="External"/><Relationship Id="rIdInternal" Type="hyperlink" Target="footnotes.xml"/></Relationships>"#);
        add(&mut zip, options, "word/document.xml", br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"><w:body><w:p><w:r><w:bookmarkStart w:id="1" w:name="BookmarkOne"/></w:r><w:r><w:t>bookmark one</w:t></w:r><w:r><w:bookmarkEnd w:id="1"/></w:r></w:p><w:p><w:r><w:bookmarkStart w:id="2" w:name="DupName"/></w:r><w:r><w:t>dup a</w:t></w:r><w:r><w:bookmarkEnd w:id="2"/></w:r></w:p><w:p><w:r><w:bookmarkStart w:id="3" w:name="DupName"/></w:r><w:r><w:t>dup b</w:t></w:r><w:r><w:bookmarkEnd w:id="3"/></w:r></w:p><w:p><w:r><w:bookmarkStart w:id="4" w:name="MissingEnd"/></w:r><w:r><w:t>missing end</w:t></w:r></w:p><w:p><w:bookmarkStart w:id="5" w:name="DirectBookmark"/><w:r><w:t>direct bookmark</w:t></w:r><w:bookmarkEnd w:id="5"/></w:p><w:p><w:r><w:hyperlink r:id="rIdExt"><w:r><w:t>external link</w:t></w:r></w:hyperlink></w:r></w:p><w:p><w:hyperlink r:id="rIdExt" w:anchor="DirectBookmark"><w:r><w:t>direct external link</w:t></w:r></w:hyperlink></w:p><w:p><w:r><w:hyperlink r:id="rIdInternal" w:anchor="BookmarkOne" w:tooltip="tip"><w:r><w:t>mixed link</w:t></w:r><w:ins w:id="40" w:author="Alice"><w:r><w:t> tracked insertion </w:t></w:r></w:ins><mc:AlternateContent><mc:Choice Requires="w"><w:r><w:t>mce link</w:t></w:r></mc:Choice><mc:Fallback><w:r><w:t>mce fallback</w:t></w:r></mc:Fallback></mc:AlternateContent></w:hyperlink></w:r></w:p><w:p><w:r><w:hyperlink r:id="rIdMissing"><w:r><w:t>missing link</w:t></w:r></w:hyperlink></w:r></w:p><w:p><w:r><w:fldSimple w:instr=" REF BookmarkOne "><w:r><w:t>simple ref result</w:t></w:r></w:fldSimple></w:r></w:p><w:p><w:fldSimple w:instr=" REF DirectBookmark "><w:r><w:t>direct simple ref result</w:t></w:r></w:fldSimple></w:p><w:p><w:r><w:fldSimple w:instr=" HYPERLINK &quot;javascript:alert(1)&quot; "><w:r><w:t>script result</w:t></w:r></w:fldSimple></w:r></w:p><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> REF BookmarkOne </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>complex result</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> REF BookmarkOne </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>outer </w:t></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> HYPERLINK \l &quot;BookmarkOne&quot; </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>inner</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p><w:p><w:r><w:fldSimple w:instr=" DDEAUTO cmd /x "><w:r><w:t>dde blocked</w:t></w:r></w:fldSimple></w:r></w:p><w:p><w:r><w:fldSimple w:instr=" INCLUDETEXT &quot;file:///tmp/blocked.docx&quot; "><w:r><w:t>include blocked</w:t></w:r></w:fldSimple></w:r></w:p><w:p><w:ins w:id="41" w:author="Bob"><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> REF BookmarkOne </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>tracked field</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:ins></w:p><mc:AlternateContent><mc:Choice Requires="w"><w:p><w:r><w:fldSimple w:instr=" REF BookmarkOne "><w:r><w:t>mce field</w:t></w:r></w:fldSimple></w:r></w:p></mc:Choice><mc:Fallback><w:p><w:r><w:t>fallback field</w:t></w:r></w:p></mc:Fallback></mc:AlternateContent><w:p><w:pPr><w:sectPr><w:headerReference r:id="rIdHeader1" w:type="default"/></w:sectPr></w:pPr></w:p><w:p><w:r><w:footnoteReference w:id="1"/></w:r></w:p></w:body></w:document>"#);
        add(&mut zip, options, "word/header1.xml", br#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:hyperlink w:anchor="BookmarkOne"><w:r><w:t>header link</w:t></w:r></w:hyperlink></w:r></w:p></w:hdr>"#);
        add(&mut zip, options, "word/footnotes.xml", br#"<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:footnote w:id="-1"/><w:footnote w:id="1"><w:p><w:r><w:bookmarkStart w:id="9" w:name="FootnoteMark"/></w:r><w:r><w:t>footnote text</w:t></w:r><w:r><w:bookmarkEnd w:id="9"/></w:r></w:p></w:footnote></w:footnotes>"#);
        zip.finish().unwrap();
        path
    }

    fn write_drawing_docx(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());
        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Default Extension="jpg" ContentType="image/jpeg"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdHeader1" Type="header" Target="header1.xml"/><Relationship Id="rIdFootnotes" Type="footnotes" Target="footnotes.xml"/><Relationship Id="rIdImgPng" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.png"/><Relationship Id="rIdImgJpg" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image2.jpg"/><Relationship Id="rIdImgExt" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://example.invalid/image?a=1&amp;b=2" TargetMode="External"/><Relationship Id="rIdImgMissingPart" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/missing.png"/><Relationship Id="rIdWrongType" Type="hyperlink" Target="media/image1.png"/><Relationship Id="rIdHyper" Type="hyperlink" Target="https://example.invalid/link" TargetMode="External"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/header1.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdHeaderImg" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.png"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/footnotes.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdFootImg" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.png"/></Relationships>"#);
        add(&mut zip, options, "word/document.xml", br##"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office"><w:body><w:p><w:r><w:drawing><wp:inline><wp:extent cx="990000" cy="792000"/><wp:docPr id="100" name="InlineImage" descr="inline desc" title="inline title" hidden="0"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImgPng"/><a:srcRect l="1000" t="2000" r="3000" b="4000"/></pic:blipFill><pic:spPr><a:xfrm rot="60000" flipH="1" flipV="0"><a:off x="111" y="222"/><a:ext cx="333" cy="444"/></a:xfrm></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:drawing><wp:anchor simplePos="0" relativeHeight="251658240" behindDoc="0" locked="1" layoutInCell="1" allowOverlap="0" distT="10" distB="20" distL="30" distR="40"><wp:positionH relativeFrom="margin"><wp:posOffset>123</wp:posOffset></wp:positionH><wp:positionV relativeFrom="paragraph"><wp:align>top</wp:align></wp:positionV><wp:wrapSquare distL="12" distR="13" distT="14" distB="15"/><wp:extent cx="1110000" cy="888000"/><wp:docPr id="101" name="AnchorImage" descr="anchor desc" title="anchor title" hidden="1"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImgJpg"/></pic:blipFill><pic:spPr><a:xfrm rot="120000" flipH="0" flipV="1"><a:off x="333" y="444"/><a:ext cx="555" cy="666"/></a:xfrm></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:anchor></w:drawing></w:r></w:p><w:p><w:r><w:drawing><wp:inline><wp:docPr id="102" name="ExternalImage"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:link="rIdImgExt"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:drawing><wp:inline><wp:docPr id="103" name="EmbedAndLink"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImgPng" r:link="rIdImgExt"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:drawing><wp:inline><wp:docPr id="104" name="MissingRelationship"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdMissing"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:drawing><wp:inline><wp:docPr id="105" name="MissingPart"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImgMissingPart"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:drawing><wp:inline><wp:docPr id="106" name="WrongType"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdWrongType"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:drawing><wp:inline><wp:docPr id="107" name="UnsupportedGraphic"/><a:graphic><a:graphicData uri="urn:unsupported:graphic"><foo:shape xmlns:foo="urn:unsupported:graphic"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:pict><v:shape id="VML1" type="#_x0000_t75" style="position:absolute;left:10pt;top:20pt;width:30pt;height:40pt;rotation:90"><v:imagedata r:id="rIdImgPng" o:title="VML title"/></v:shape></w:pict></w:r></w:p><w:p><w:r><w:pict><v:shape id="VML2" type="#_x0000_t75" style="position:absolute;bogus"><v:imagedata r:id="rIdImgPng"/></v:shape></w:pict></w:r></w:p><w:p><w:r><w:pict><o:OLEObject ProgID="Package"/></w:pict></w:r></w:p><w:p><w:hyperlink r:id="rIdHyper"><w:r><w:drawing><wp:inline><wp:docPr id="108" name="HyperlinkDrawing"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImgPng"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:hyperlink></w:p><w:p><w:r><w:fldSimple w:instr=" REF BookmarkOne "><w:r><w:drawing><wp:inline><wp:docPr id="109" name="FieldDrawing"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImgPng"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:fldSimple></w:r></w:p><w:p><w:ins w:id="51" w:author="Alice"><w:r><w:drawing><wp:inline><wp:docPr id="110" name="TrackedDrawing"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImgPng"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:ins></w:p><mc:AlternateContent><mc:Choice Requires="w"><w:p><w:r><w:drawing><wp:inline><wp:docPr id="111" name="MceDrawing"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdImgPng"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></mc:Choice><mc:Fallback><w:p><w:r><w:t>fallback</w:t></w:r></w:p></mc:Fallback></mc:AlternateContent><w:p><w:pPr><w:sectPr><w:headerReference r:id="rIdHeader1" w:type="default"/></w:sectPr></w:pPr></w:p><w:p><w:r><w:footnoteReference w:id="1"/></w:r></w:p></w:body></w:document>"##);
        add(&mut zip, options, "word/header1.xml", br#"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:p><w:r><w:drawing><wp:inline><wp:docPr id="112" name="HeaderDrawing"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdHeaderImg"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></w:hdr>"#);
        add(&mut zip, options, "word/footnotes.xml", br#"<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:footnote w:id="-1"/><w:footnote w:id="1"><w:p><w:r><w:drawing><wp:inline><wp:docPr id="113" name="FootnoteDrawing"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:blipFill><a:blip r:embed="rIdFootImg"/></pic:blipFill></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></w:footnote></w:footnotes>"#);
        add(
            &mut zip,
            options,
            "word/media/image1.png",
            b"not-a-real-png-but-stable",
        );
        add(
            &mut zip,
            options,
            "word/media/image2.jpg",
            b"not-a-real-jpeg-but-stable",
        );
        zip.finish().unwrap();
        path
    }

    fn write_embedded_visual_objects_docx(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("tuff-cvn-{name}-{}.docx", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());
        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Default Extension="bin" ContentType="application/octet-stream"/><Default Extension="docx" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document"/><Default Extension="xlsx" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/><Override PartName="/word/charts/chart1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/><Override PartName="/word/diagrams/data1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.diagramData+xml"/><Override PartName="/word/diagrams/layout1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.diagramLayout+xml"/><Override PartName="/word/diagrams/style1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.diagramStyle+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdHeader1" Type="header" Target="header1.xml"/><Relationship Id="rIdFootnotes" Type="footnotes" Target="footnotes.xml"/><Relationship Id="rIdChart1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart" Target="charts/chart1.xml"/><Relationship Id="rIdDiagramData" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramData" Target="diagrams/data1.xml"/><Relationship Id="rIdDiagramLayout" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramLayout" Target="diagrams/layout1.xml"/><Relationship Id="rIdDiagramStyle" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramQuickStyle" Target="diagrams/style1.xml"/><Relationship Id="rIdDiagramColors" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramColors" Target="diagrams/missing-colors1.xml"/><Relationship Id="rIdOle1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/><Relationship Id="rIdOleLink" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="https://example.invalid/ole-object" TargetMode="External"/><Relationship Id="rIdPackage1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="embeddings/package1.docx"/><Relationship Id="rIdControl1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/control" Target="activeX/activeX1.bin"/><Relationship Id="rIdPreview" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/preview.png"/><Relationship Id="rIdWrongType" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart" Target="charts/chart1.xml"/><Relationship Id="rIdMissingPart" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/missing.bin"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/header1.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdHeaderObject" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/><Relationship Id="rIdHeaderChart" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart" Target="charts/chart1.xml"/></Relationships>"#);
        add(&mut zip, options, "word/_rels/footnotes.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdFootObject" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="embeddings/package1.docx"/><Relationship Id="rIdFootDiagramData" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramData" Target="diagrams/data1.xml"/><Relationship Id="rIdFootDiagramLayout" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramLayout" Target="diagrams/layout1.xml"/><Relationship Id="rIdFootDiagramStyle" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramQuickStyle" Target="diagrams/style1.xml"/><Relationship Id="rIdFootDiagramColors" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/diagramColors" Target="diagrams/missing-colors1.xml"/></Relationships>"#);
        add(&mut zip, options, "word/document.xml", br##"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office"><w:body><w:p><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart r:id="rIdChart1"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/diagram"><dgm:relIds r:dm="rIdDiagramData" r:lo="rIdDiagramLayout" r:qs="rIdDiagramStyle" r:cs="rIdDiagramColors"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:p><w:r><w:object><v:shape id="OleShape1"><v:imagedata r:id="rIdPreview" o:title="Previewed object"/></v:shape><o:OLEObject Type="Embed" ProgID="Word.Document.12" ShapeID="_x0000_i1025" DrawAspect="Content" ObjectID="_1" UpdateMode="Always" r:id="rIdOle1"/></w:object></w:r></w:p><w:p><w:r><w:object><o:OLEObject Type="Link" ProgID="Excel.Sheet.12" ShapeID="_x0000_i1026" ObjectID="_2" r:id="rIdOleLink"/></w:object></w:r></w:p><w:p><w:r><w:object><o:OLEObject Type="Embed" ProgID="Package" ShapeID="_x0000_i1027" ObjectID="_3" r:id="rIdPackage1"/></w:object></w:r></w:p><w:p><w:r><w:object><o:control r:id="rIdControl1"/><o:OLEObject Type="Embed" ProgID="Forms.CommandButton.1" ShapeID="_x0000_i1028" ObjectID="_4" r:id="rIdControl1"/></w:object></w:r></w:p><w:p><w:r><w:object><o:OLEObject Type="Embed" ProgID="Word.Document.12" ObjectID="_5" r:id="rIdMissingObject"/></w:object></w:r></w:p><w:p><w:r><w:object><o:OLEObject Type="Embed" ProgID="Word.Document.12" ObjectID="_6" r:id="rIdWrongType"/></w:object></w:r></w:p><w:p><w:r><w:object><o:OLEObject Type="Embed" ProgID="Word.Document.12" ObjectID="_7" r:id="rIdMissingPart"/></w:object></w:r></w:p><w:p><w:hyperlink w:anchor="LocalAnchor"><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart r:id="rIdChart1"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:hyperlink></w:p><w:p><w:r><w:fldSimple w:instr=" REF LocalAnchor "><w:r><w:object><o:OLEObject Type="Embed" ProgID="Package" ObjectID="_8" r:id="rIdPackage1"/></w:object></w:r></w:fldSimple></w:r></w:p><w:p><w:r><w:fldSimple w:instr=" REF LocalAnchor "><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/diagram"><dgm:relIds r:dm="rIdDiagramData" r:lo="rIdDiagramLayout" r:qs="rIdDiagramStyle" r:cs="rIdDiagramColors"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:fldSimple></w:r></w:p><w:p><w:ins w:id="61" w:author="Alice"><w:r><w:object><o:OLEObject Type="Embed" ProgID="Word.Document.12" ObjectID="_9" r:id="rIdOle1"/></w:object></w:r></w:ins></w:p><w:p><w:ins w:id="62" w:author="Alice"><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart r:id="rIdChart1"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:ins></w:p><mc:AlternateContent><mc:Choice Requires="w"><w:p><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart r:id="rIdChart1"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></mc:Choice><mc:Fallback><w:p><w:r><w:t>fallback</w:t></w:r></w:p></mc:Fallback></mc:AlternateContent><mc:AlternateContent><mc:Choice Requires="w"><w:p><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/diagram"><dgm:relIds r:dm="rIdDiagramData" r:lo="rIdDiagramLayout" r:qs="rIdDiagramStyle" r:cs="rIdDiagramColors"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></mc:Choice><mc:Fallback><w:p><w:r><w:t>fallback-2</w:t></w:r></w:p></mc:Fallback></mc:AlternateContent><w:p><w:pPr><w:sectPr><w:headerReference r:id="rIdHeader1" w:type="default"/></w:sectPr></w:pPr></w:p><w:p><w:r><w:footnoteReference w:id="1"/></w:r></w:p></w:body></w:document>"##);
        add(&mut zip, options, "word/header1.xml", br##"<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart"><w:p><w:r><w:object><o:OLEObject Type="Embed" ProgID="Word.Document.12" ObjectID="_10" r:id="rIdHeaderObject"/></w:object></w:r></w:p><w:p><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart r:id="rIdHeaderChart"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></w:hdr>"##);
        add(&mut zip, options, "word/footnotes.xml", br##"<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram"><w:footnote w:id="-1"/><w:footnote w:id="1"><w:p><w:r><w:object><o:OLEObject Type="Embed" ProgID="Package" ObjectID="_11" r:id="rIdFootObject"/></w:object></w:r></w:p><w:p><w:r><w:drawing><wp:inline><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/diagram"><dgm:relIds r:dm="rIdFootDiagramData" r:lo="rIdFootDiagramLayout" r:qs="rIdFootDiagramStyle" r:cs="rIdFootDiagramColors"/></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></w:footnote></w:footnotes>"##);
        add(&mut zip, options, "word/charts/chart1.xml", br##"<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><c:chart><c:title><c:tx><c:rich><a:p><a:r><a:t>Chart Title</a:t></a:r></a:p></c:rich></c:tx></c:title><c:plotArea><c:barChart><c:ser><c:tx><c:v>Series 1</c:v></c:tx><c:cat><c:strRef><c:f>Sheet1!$A$1:$A$2</c:f><c:strCache><c:pt idx="0"><c:v>Cat A</c:v></c:pt><c:pt idx="1"><c:v>Cat B</c:v></c:pt></c:strCache></c:strRef></c:cat><c:val><c:numRef><c:f>Sheet1!$B$1:$B$2</c:f><c:numCache><c:pt idx="0"><c:v>10</c:v></c:pt><c:pt idx="1"><c:v>20</c:v></c:pt></c:numCache></c:numRef></c:val></c:ser></c:barChart></c:plotArea><c:externalData r:id="rIdChartExt"><c:autoUpdate val="1"/></c:externalData></c:chart></c:chartSpace>"##);
        add(&mut zip, options, "word/charts/_rels/chart1.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdWorkbook" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="../embeddings/workbook1.xlsx"/><Relationship Id="rIdChartExt" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package" Target="https://example.invalid/chart-data.xlsx" TargetMode="External"/></Relationships>"#);
        add(&mut zip, options, "word/diagrams/data1.xml", br##"<dgm:dataModel xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><dgm:ptLst><dgm:pt modelId="0"><dgm:t><a:t>Node A</a:t></dgm:t></dgm:pt><dgm:pt modelId="2"><dgm:t><a:t>Node B</a:t></dgm:t></dgm:pt></dgm:ptLst><dgm:cxnLst><dgm:cxn modelId="1" srcId="0" destId="2"/></dgm:cxnLst></dgm:dataModel>"##);
        add(&mut zip, options, "word/diagrams/layout1.xml", br#"<dgm:layoutDef xmlns:dgm=\"http://schemas.openxmlformats.org/drawingml/2006/diagram\" uniqueId=\"layout-1\"/>"#);
        add(&mut zip, options, "word/diagrams/style1.xml", br#"<dgm:styleDef xmlns:dgm=\"http://schemas.openxmlformats.org/drawingml/2006/diagram\" uniqueId=\"style-1\"/>"#);
        add(
            &mut zip,
            options,
            "word/embeddings/oleObject1.bin",
            b"ole-object-stable",
        );
        add(
            &mut zip,
            options,
            "word/embeddings/package1.docx",
            b"embedded-docx-stable",
        );
        add(
            &mut zip,
            options,
            "word/embeddings/workbook1.xlsx",
            b"embedded-workbook-stable",
        );
        add(
            &mut zip,
            options,
            "word/activeX/activeX1.bin",
            b"activex-stable",
        );
        add(
            &mut zip,
            options,
            "word/media/preview.png",
            b"preview-png-stable",
        );
        zip.finish().unwrap();
        path
    }

    fn collect_semantic_ids(document: &SemanticDocument) -> Vec<String> {
        let mut ids = Vec::new();
        for block in &document.blocks {
            collect_block_ids(block, &mut ids);
        }
        ids
    }

    #[test]
    fn story_parts_are_projected_deterministically() {
        let docx = write_story_docx("story-deterministic");
        let package1 = import_docx(&docx).unwrap();
        let package2 = import_docx(&docx).unwrap();

        assert_eq!(
            package1.document.semantic.stories,
            package2.document.semantic.stories
        );

        let out1 =
            std::env::temp_dir().join(format!("tuff-cvn-story-out-1-{}", std::process::id()));
        let out2 =
            std::env::temp_dir().join(format!("tuff-cvn-story-out-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
        cvn_package::write_package(&out1, &package1).unwrap();
        cvn_package::write_package(&out2, &package2).unwrap();

        let bytes1 = cvn_package::read_cvn_json_bytes(&out1).unwrap();
        let bytes2 = cvn_package::read_cvn_json_bytes(&out2).unwrap();
        assert_eq!(bytes1, bytes2);

        let report1 = cvn_package::verify_package_integrity(&out1).unwrap();
        let report2 = cvn_package::verify_package_integrity(&out2).unwrap();
        assert_eq!(report1.root_actual, report2.root_actual);

        let stories = package1.document.semantic.stories.as_ref().unwrap();
        assert!(stories
            .parts
            .iter()
            .any(|part| matches!(part.kind, StoryPartKind::HeaderDefault)));
        assert!(stories
            .parts
            .iter()
            .any(|part| matches!(part.kind, StoryPartKind::FooterDefault)));
        assert!(stories
            .parts
            .iter()
            .any(|part| matches!(part.kind, StoryPartKind::Footnotes)));
        assert!(stories
            .parts
            .iter()
            .any(|part| matches!(part.kind, StoryPartKind::Endnotes)));
        assert!(stories
            .parts
            .iter()
            .any(|part| matches!(part.kind, StoryPartKind::Comments)));

        let _ = fs::remove_dir_all(&docx);
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
    }

    #[test]
    fn story_projection_absent_is_allowed() {
        let docx = write_semantic_docx("no-story-parts");
        let package = import_docx(&docx).unwrap();
        assert!(package.document.semantic.stories.is_none());
        let _ = fs::remove_file(docx);
    }

    #[test]
    fn track_changes_fixture_is_projected_and_deterministic() {
        let docx = write_track_changes_docx("track-changes");
        let first = import_docx(&docx).unwrap();
        let second = import_docx(&docx).unwrap();

        assert_eq!(first.document.track_changes, second.document.track_changes);
        let track_changes = first.document.track_changes.as_ref().unwrap();
        assert!(track_changes
            .changes
            .iter()
            .any(|change| matches!(change.kind, TrackedChangeKind::Insertion)));
        assert!(track_changes
            .changes
            .iter()
            .any(|change| matches!(change.kind, TrackedChangeKind::Deletion)));
        assert!(track_changes
            .changes
            .iter()
            .any(|change| matches!(change.kind, TrackedChangeKind::MoveFrom)));
        assert!(track_changes
            .changes
            .iter()
            .any(|change| matches!(change.kind, TrackedChangeKind::MoveTo)));

        let out1 =
            std::env::temp_dir().join(format!("tuff-cvn-track-out-1-{}", std::process::id()));
        let out2 =
            std::env::temp_dir().join(format!("tuff-cvn-track-out-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
        cvn_package::write_package(&out1, &first).unwrap();
        cvn_package::write_package(&out2, &second).unwrap();
        assert_eq!(
            cvn_package::read_cvn_json_bytes(&out1).unwrap(),
            cvn_package::read_cvn_json_bytes(&out2).unwrap()
        );
        assert_eq!(
            cvn_package::verify_package_integrity(&out1)
                .unwrap()
                .root_actual,
            cvn_package::verify_package_integrity(&out2)
                .unwrap()
                .root_actual
        );
        let _ = fs::remove_dir_all(&docx);
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
    }

    #[test]
    fn mce_alternate_content_is_projected_selected_and_deterministic() {
        let docx = write_mce_docx("mce");
        let first = import_docx(&docx).unwrap();
        let second = import_docx(&docx).unwrap();

        assert_eq!(first.document.mce, second.document.mce);
        assert_eq!(first.document.semantic, second.document.semantic);
        let mce = first.document.mce.as_ref().unwrap();
        assert_eq!(mce.capability_version, MCE_CAPABILITY_VERSION);
        assert!(mce.alternate_contents.len() >= 5);
        assert!(mce.alternate_contents.iter().any(|ac| ac.branch_kind
            == MceSelection::SelectedChoice
            && ac.branches.iter().any(|branch| branch.selected
                && branch
                    .requires
                    .iter()
                    .all(|requirement| requirement.supported))));
        assert!(mce
            .alternate_contents
            .iter()
            .any(|ac| ac.branch_kind == MceSelection::SelectedFallback));
        assert!(mce
            .alternate_contents
            .iter()
            .any(|ac| ac.branch_kind == MceSelection::Unresolved));
        assert!(mce
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_MCE_REQUIRES_NAMESPACE_UNSUPPORTED"));
        assert!(mce
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_MCE_REQUIRES_PREFIX_UNRESOLVED"));
        assert!(mce
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_MCE_FALLBACK_MISSING"));
        assert!(mce.alternate_contents.iter().any(|ac| ac
            .compatibility
            .as_ref()
            .map(|compat| {
                compat.ignorable_namespaces == vec!["urn:unsupported".to_owned()]
                    && compat.process_content.len() == 1
                    && compat.preserve_elements.len() == 1
                    && compat.preserve_attributes.len() == 1
            })
            .unwrap_or(false)));

        let text = semantic_and_story_text(&first.document.semantic);
        assert!(text.contains("supported second choice"));
        assert!(text.contains("inline fallback"));
        assert!(text.contains("nested choice"));
        assert!(text.contains("fallback table"));
        assert!(text.contains("header choice"));
        assert!(text.contains("footnote choice"));
        assert!(!text.contains("unsupported choice"));
        assert!(!text.contains("fallback not selected"));
        assert!(!text.contains("unsupported table choice"));

        let mut block_wrappers = Vec::new();
        collect_mce_block_wrappers(&first.document.semantic.blocks, &mut block_wrappers);
        if let Some(stories) = first.document.semantic.stories.as_ref() {
            for part in &stories.parts {
                collect_mce_block_wrappers(&part.blocks, &mut block_wrappers);
                for note in &part.notes {
                    collect_mce_block_wrappers(&note.blocks, &mut block_wrappers);
                }
                for comment in &part.comments {
                    collect_mce_block_wrappers(&comment.blocks, &mut block_wrappers);
                }
            }
        }
        assert!(block_wrappers.iter().any(|wrapper| {
            wrapper.selected_branch_kind == MceSelection::SelectedChoice
                && wrapper.selected_branch_index == Some(1)
                && wrapper
                    .blocks
                    .iter()
                    .any(|block| block_text(block).contains("supported second choice"))
        }));
        assert!(block_wrappers.iter().any(|wrapper| {
            wrapper.selected_branch_kind == MceSelection::SelectedFallback
                && wrapper.blocks.iter().any(|block| {
                    matches!(block, SemanticBlock::Table(_))
                        && block_text(block).contains("fallback table")
                })
        }));
        assert!(block_wrappers.iter().any(|wrapper| {
            wrapper.selected_branch_kind == MceSelection::Unresolved && wrapper.blocks.is_empty()
        }));
        assert!(block_wrappers.iter().any(|wrapper| {
            wrapper.blocks.iter().any(|block| {
                block_mce_wrappers(block).iter().any(|nested| {
                    nested.selected_branch_kind == MceSelection::SelectedChoice
                        && inline_text(&nested.inlines).contains("nested choice")
                })
            })
        }));
        assert!(block_wrappers.iter().any(|wrapper| {
            wrapper.source_part_path() == "word/header1.xml"
                && wrapper
                    .blocks
                    .iter()
                    .any(|block| block_text(block).contains("header choice"))
        }));
        assert!(block_wrappers.iter().any(|wrapper| {
            wrapper.source_part_path() == "word/footnotes.xml"
                && wrapper
                    .blocks
                    .iter()
                    .any(|block| block_text(block).contains("footnote choice"))
        }));

        let mut inline_wrappers = Vec::new();
        collect_mce_inline_wrappers(&first.document.semantic.blocks, &mut inline_wrappers);
        if let Some(stories) = first.document.semantic.stories.as_ref() {
            for part in &stories.parts {
                collect_mce_inline_wrappers(&part.blocks, &mut inline_wrappers);
                for note in &part.notes {
                    collect_mce_inline_wrappers(&note.blocks, &mut inline_wrappers);
                }
                for comment in &part.comments {
                    collect_mce_inline_wrappers(&comment.blocks, &mut inline_wrappers);
                }
            }
        }
        assert!(inline_wrappers.iter().any(|wrapper| {
            wrapper.selected_branch_kind == MceSelection::SelectedFallback
                && inline_text(&wrapper.inlines).contains("inline fallback")
                && wrapper
                    .inlines
                    .iter()
                    .any(|inline| matches!(inline, SemanticInline::Tab))
                && wrapper
                    .inlines
                    .iter()
                    .any(|inline| matches!(inline, SemanticInline::LineBreak { .. }))
        }));
        assert!(inline_wrappers
            .iter()
            .any(|wrapper| { inline_text(&wrapper.inlines).contains("tracked mce insertion") }));
        assert!(block_wrappers.iter().any(|wrapper| {
            wrapper.inlines.iter().any(|inline| {
                matches!(inline, SemanticInline::TrackedChange { change }
                    if change.kind == TrackedChangeKind::Deletion)
            })
        }));

        let out1 = std::env::temp_dir().join(format!("tuff-cvn-mce-out-1-{}", std::process::id()));
        let out2 = std::env::temp_dir().join(format!("tuff-cvn-mce-out-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
        cvn_package::write_package(&out1, &first).unwrap();
        cvn_package::write_package(&out2, &second).unwrap();
        assert_eq!(
            cvn_package::read_cvn_json_bytes(&out1).unwrap(),
            cvn_package::read_cvn_json_bytes(&out2).unwrap()
        );
        assert!(cvn_package::verify_package_integrity(&out1).unwrap().passed);
        assert_eq!(
            cvn_package::verify_package_integrity(&out1)
                .unwrap()
                .root_actual,
            cvn_package::verify_package_integrity(&out2)
                .unwrap()
                .root_actual
        );
        let _ = fs::remove_file(&docx);
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
    }

    #[test]
    fn document_references_projection_is_deterministic_and_connected() {
        let docx = write_references_docx("references");
        let first = import_docx(&docx).unwrap();
        let second = import_docx(&docx).unwrap();

        assert_eq!(
            first.document.semantic.references,
            second.document.semantic.references
        );
        let ids_first = collect_reference_semantic_ids(&first.document.semantic);
        let ids_second = collect_reference_semantic_ids(&second.document.semantic);
        assert_eq!(ids_first, ids_second);

        let references = first.document.semantic.references.as_ref().unwrap();
        assert!(references.hyperlinks.iter().any(|hyperlink| {
            hyperlink.relationship_id.as_deref() == Some("rIdExt")
                && hyperlink.target.raw_target.as_deref()
                    == Some("https://example.invalid/reference?a=1&b=2")
                && hyperlink.target.risk_class.as_deref() == Some("ordinary_web")
        }));
        assert!(references.hyperlinks.iter().any(|hyperlink| {
            hyperlink.relationship_id.as_deref() == Some("rIdInternal")
                && hyperlink.anchor.as_deref() == Some("BookmarkOne")
                && hyperlink.tooltip.as_deref() == Some("tip")
                && inline_text(&hyperlink.children).contains("tracked insertion")
                && inline_text(&hyperlink.children).contains("mce link")
        }));
        assert!(references
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_HYPERLINK_RELATIONSHIP_MISSING"));
        assert!(references
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_HYPERLINK_EXTERNAL_TARGET_INERT"));
        assert!(references
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_BOOKMARK_END_MISSING"));
        assert!(references
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_BOOKMARK_NAME_AMBIGUOUS"));
        assert!(references
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_FIELD_EXECUTION_BLOCKED"));

        assert!(references.bookmark_ranges.iter().any(|range| {
            range.bookmark_id == "1"
                && range.name.as_deref() == Some("BookmarkOne")
                && range.end.is_some()
        }));
        assert!(references.bookmark_ranges.iter().any(|range| {
            range.bookmark_id == "5"
                && range.name.as_deref() == Some("DirectBookmark")
                && range.end.is_some()
        }));
        assert!(references.bookmark_ranges.iter().any(|range| {
            range.source_part == "word/footnotes.xml"
                && range.name.as_deref() == Some("FootnoteMark")
        }));

        let simple_ref = references
            .fields
            .iter()
            .find(|field| inline_text(&field.result.children).contains("simple ref result"))
            .unwrap();
        assert_eq!(simple_ref.field_kind, FieldKind::Ref);
        assert_eq!(
            simple_ref
                .cross_reference
                .as_ref()
                .and_then(|projection| projection.target_bookmark_name.as_deref()),
            Some("BookmarkOne")
        );
        assert_eq!(
            simple_ref
                .cross_reference
                .as_ref()
                .and_then(|projection| projection.resolved_bookmark_id.as_deref()),
            Some("1")
        );

        let direct_simple_ref = references
            .fields
            .iter()
            .find(|field| inline_text(&field.result.children).contains("direct simple ref result"))
            .unwrap();
        assert_eq!(direct_simple_ref.field_kind, FieldKind::Ref);
        assert_eq!(
            direct_simple_ref
                .cross_reference
                .as_ref()
                .and_then(|projection| projection.target_bookmark_name.as_deref()),
            Some("DirectBookmark")
        );
        assert_eq!(
            direct_simple_ref
                .cross_reference
                .as_ref()
                .and_then(|projection| projection.resolved_bookmark_id.as_deref()),
            Some("5")
        );

        let hyperlink_field = references
            .fields
            .iter()
            .find(|field| inline_text(&field.result.children).contains("script result"))
            .unwrap();
        assert_eq!(hyperlink_field.field_kind, FieldKind::Hyperlink);
        assert_eq!(
            hyperlink_field
                .cross_reference
                .as_ref()
                .and_then(|projection| projection.hyperlink_target.as_ref())
                .and_then(|target| target.risk_class.as_deref()),
            Some("active_or_script_scheme")
        );

        let nested_field = references
            .fields
            .iter()
            .find(|field| inline_text(&field.result.children).contains("outer"))
            .unwrap();
        assert!(nested_field
            .result
            .children
            .iter()
            .any(|inline| matches!(inline, SemanticInline::Field(_))));
        assert!(references
            .fields
            .iter()
            .any(|field| inline_text(&field.result.children).contains("tracked field")));
        assert!(references
            .fields
            .iter()
            .any(|field| inline_text(&field.result.children).contains("mce field")));
        assert!(references.hyperlinks.iter().any(|hyperlink| {
            hyperlink.anchor.as_deref() == Some("DirectBookmark")
                && inline_text(&hyperlink.children).contains("direct external link")
        }));

        assert!(semantic_contains_hyperlink_wrapper(
            &first.document.semantic
        ));
        assert!(semantic_contains_field_wrapper(&first.document.semantic));

        let out1 =
            std::env::temp_dir().join(format!("tuff-cvn-references-out-1-{}", std::process::id()));
        let out2 =
            std::env::temp_dir().join(format!("tuff-cvn-references-out-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
        cvn_package::write_package(&out1, &first).unwrap();
        cvn_package::write_package(&out2, &second).unwrap();
        assert_eq!(
            cvn_package::read_cvn_json_bytes(&out1).unwrap(),
            cvn_package::read_cvn_json_bytes(&out2).unwrap()
        );
        assert_eq!(
            cvn_package::verify_package_integrity(&out1)
                .unwrap()
                .root_actual,
            cvn_package::verify_package_integrity(&out2)
                .unwrap()
                .root_actual
        );

        let _ = fs::remove_file(&docx);
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
    }

    #[test]
    fn drawing_projection_is_deterministic_and_connected() {
        let docx = write_drawing_docx("drawings");
        let first = import_docx(&docx).unwrap();
        let second = import_docx(&docx).unwrap();

        assert_eq!(
            first.document.semantic.drawings,
            second.document.semantic.drawings
        );
        assert_eq!(
            collect_drawing_semantic_ids(&first.document.semantic),
            collect_drawing_semantic_ids(&second.document.semantic)
        );

        let registry = first.document.semantic.drawings.as_ref().unwrap();
        assert_eq!(registry.source_part, "word/document.xml");
        assert!(registry
            .drawings
            .iter()
            .any(|drawing| drawing.kind == DrawingKind::DrawingmlInlineImage));
        assert!(registry
            .drawings
            .iter()
            .any(|drawing| drawing.kind == DrawingKind::DrawingmlAnchoredImage));
        assert!(registry
            .drawings
            .iter()
            .any(|drawing| drawing.kind == DrawingKind::VmlImage));
        assert!(registry
            .drawings
            .iter()
            .any(|drawing| drawing.kind == DrawingKind::UnsupportedGraphic));

        let inline = registry
            .drawings
            .iter()
            .find(|drawing| {
                drawing
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.name.as_deref())
                    == Some("InlineImage")
            })
            .unwrap();
        let inline_metadata = inline.metadata.as_ref().unwrap();
        let inline_geometry = inline.geometry.as_ref().unwrap();
        let inline_transform = inline_geometry.transform.as_ref().unwrap();
        let inline_target = inline
            .targets
            .iter()
            .find(|target| target.relationship_id.as_deref() == Some("rIdImgPng"))
            .unwrap();
        let inline_resource = inline_target.resource.as_ref().unwrap();
        assert_eq!(inline_metadata.doc_pr_id.as_deref(), Some("100"));
        assert_eq!(inline_metadata.description.as_deref(), Some("inline desc"));
        assert_eq!(inline_metadata.title.as_deref(), Some("inline title"));
        assert_eq!(inline_metadata.hidden, Some(false));
        assert_eq!(
            inline_geometry.extent.as_ref().and_then(|extent| extent.cx),
            Some(990000)
        );
        assert_eq!(
            inline_geometry.extent.as_ref().and_then(|extent| extent.cy),
            Some(792000)
        );
        assert_eq!(inline_transform.rotation, Some(60000));
        assert!(inline_transform.flip_h);
        assert!(!inline_transform.flip_v);
        assert_eq!(
            inline_transform.offset.as_ref().and_then(|offset| offset.x),
            Some(111)
        );
        assert_eq!(
            inline_transform.offset.as_ref().and_then(|offset| offset.y),
            Some(222)
        );
        assert_eq!(
            inline_transform
                .extent
                .as_ref()
                .and_then(|extent| extent.cx),
            Some(333)
        );
        assert_eq!(
            inline_transform
                .extent
                .as_ref()
                .and_then(|extent| extent.cy),
            Some(444)
        );
        assert_eq!(
            inline_geometry.crop.as_ref().and_then(|crop| crop.left),
            Some(1000)
        );
        assert_eq!(
            inline_geometry.crop.as_ref().and_then(|crop| crop.top),
            Some(2000)
        );
        assert_eq!(
            inline_geometry.crop.as_ref().and_then(|crop| crop.right),
            Some(3000)
        );
        assert_eq!(
            inline_geometry.crop.as_ref().and_then(|crop| crop.bottom),
            Some(4000)
        );
        assert_eq!(inline_target.kind, DrawingTargetKind::EmbeddedPart);
        assert_eq!(
            inline_target.resolved_part_path.as_deref(),
            Some("word/media/image1.png")
        );
        assert_eq!(
            inline_resource.part_path.as_deref(),
            Some("word/media/image1.png")
        );
        assert_eq!(inline_resource.content_type.as_deref(), Some("image/png"));
        assert_eq!(
            inline_resource.length,
            Some(b"not-a-real-png-but-stable".len() as u64)
        );
        assert!(inline_resource.object_digest.is_some());

        let anchor = registry
            .drawings
            .iter()
            .find(|drawing| {
                drawing
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.name.as_deref())
                    == Some("AnchorImage")
            })
            .unwrap();
        let anchor_metadata = anchor.metadata.as_ref().unwrap();
        let anchor_geometry = anchor.geometry.as_ref().unwrap();
        let anchor_transform = anchor_geometry.transform.as_ref().unwrap();
        assert_eq!(anchor.kind, DrawingKind::DrawingmlAnchoredImage);
        assert_eq!(anchor_metadata.hidden, Some(true));
        assert_eq!(anchor_transform.rotation, Some(120000));
        assert!(!anchor_transform.flip_h);
        assert!(anchor_transform.flip_v);
        match &anchor.placement {
            DrawingPlacement::Anchor {
                simple_pos,
                relative_height,
                behind_doc,
                locked,
                layout_in_cell,
                allow_overlap,
                dist_t,
                dist_b,
                dist_l,
                dist_r,
                position_h,
                position_v,
                wrap,
            } => {
                assert_eq!(*simple_pos, Some(false));
                assert_eq!(relative_height.as_deref(), Some("251658240"));
                assert_eq!(*behind_doc, Some(false));
                assert_eq!(*locked, Some(true));
                assert_eq!(*layout_in_cell, Some(true));
                assert_eq!(*allow_overlap, Some(false));
                assert_eq!(dist_t.as_deref(), Some("10"));
                assert_eq!(dist_b.as_deref(), Some("20"));
                assert_eq!(dist_l.as_deref(), Some("30"));
                assert_eq!(dist_r.as_deref(), Some("40"));
                assert_eq!(
                    position_h
                        .as_ref()
                        .and_then(|position| position.relative_from.as_deref()),
                    Some("margin")
                );
                assert_eq!(
                    position_h.as_ref().and_then(|position| position.pos_offset),
                    Some(123)
                );
                assert_eq!(
                    position_v
                        .as_ref()
                        .and_then(|position| position.relative_from.as_deref()),
                    Some("paragraph")
                );
                assert_eq!(
                    position_v
                        .as_ref()
                        .and_then(|position| position.align.as_deref()),
                    Some("top")
                );
                assert_eq!(
                    wrap.as_ref().map(|wrap| wrap.kind.as_str()),
                    Some("wrapSquare")
                );
                assert_eq!(
                    wrap.as_ref().and_then(|wrap| wrap.dist_l.as_deref()),
                    Some("12")
                );
                assert_eq!(
                    wrap.as_ref().and_then(|wrap| wrap.dist_r.as_deref()),
                    Some("13")
                );
                assert_eq!(
                    wrap.as_ref().and_then(|wrap| wrap.dist_t.as_deref()),
                    Some("14")
                );
                assert_eq!(
                    wrap.as_ref().and_then(|wrap| wrap.dist_b.as_deref()),
                    Some("15")
                );
            }
            other => panic!("expected anchor placement, got {other:?}"),
        }

        let external = registry
            .drawings
            .iter()
            .find(|drawing| {
                drawing
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.name.as_deref())
                    == Some("ExternalImage")
            })
            .unwrap();
        assert!(external.targets.iter().any(|target| {
            target.kind == DrawingTargetKind::ExternalRelationship
                && target.relationship_id.as_deref() == Some("rIdImgExt")
                && target.raw_target.as_deref() == Some("https://example.invalid/image?a=1&b=2")
                && target.risk_class.as_deref() == Some("ordinary_web")
        }));

        let embed_and_link = registry
            .drawings
            .iter()
            .find(|drawing| {
                drawing
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.name.as_deref())
                    == Some("EmbedAndLink")
            })
            .unwrap();
        assert_eq!(embed_and_link.targets.len(), 2);
        assert!(embed_and_link
            .targets
            .iter()
            .any(|target| target.relationship_id.as_deref() == Some("rIdImgPng")));
        assert!(embed_and_link
            .targets
            .iter()
            .any(|target| target.relationship_id.as_deref() == Some("rIdImgExt")));

        let shared_digest = inline_resource.object_digest.as_deref().unwrap();
        assert!(
            registry
                .drawings
                .iter()
                .flat_map(|drawing| drawing.targets.iter())
                .filter_map(|target| target.resource.as_ref())
                .filter(|resource| resource.object_digest.as_deref() == Some(shared_digest))
                .count()
                >= 5
        );

        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_DRAWING_RELATIONSHIP_MISSING"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_DRAWING_MEDIA_PART_MISSING"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_DRAWING_RELATIONSHIP_TYPE_MISMATCH"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_DRAWING_GRAPHIC_DATA_UNSUPPORTED"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_DRAWING_VML_STYLE_INVALID"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_DRAWING_EXTERNAL_TARGET_INERT"));

        assert!(semantic_contains_drawing_wrapper(&first.document.semantic));
        let main_drawings = collect_drawings_from_blocks_for_test(&first.document.semantic.blocks);
        assert!(main_drawings.iter().any(|drawing| {
            drawing
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.name.as_deref())
                == Some("HyperlinkDrawing")
        }));
        assert!(main_drawings.iter().any(|drawing| {
            drawing
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.name.as_deref())
                == Some("FieldDrawing")
        }));
        assert!(main_drawings.iter().any(|drawing| {
            drawing
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.name.as_deref())
                == Some("TrackedDrawing")
        }));
        assert!(main_drawings.iter().any(|drawing| {
            drawing
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.name.as_deref())
                == Some("MceDrawing")
        }));
        assert!(
            story_part_drawings(&first.document.semantic, StoryPartKind::HeaderDefault)
                .iter()
                .any(|drawing| {
                    drawing
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.name.as_deref())
                        == Some("HeaderDrawing")
                })
        );
        assert!(
            story_part_drawings(&first.document.semantic, StoryPartKind::Footnotes)
                .iter()
                .any(|drawing| {
                    drawing
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.name.as_deref())
                        == Some("FootnoteDrawing")
                })
        );

        let out1 =
            std::env::temp_dir().join(format!("tuff-cvn-drawings-out-1-{}", std::process::id()));
        let out2 =
            std::env::temp_dir().join(format!("tuff-cvn-drawings-out-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
        cvn_package::write_package(&out1, &first).unwrap();
        cvn_package::write_package(&out2, &second).unwrap();
        assert_eq!(
            cvn_package::read_cvn_json_bytes(&out1).unwrap(),
            cvn_package::read_cvn_json_bytes(&out2).unwrap()
        );
        assert_eq!(
            cvn_package::verify_package_integrity(&out1)
                .unwrap()
                .root_actual,
            cvn_package::verify_package_integrity(&out2)
                .unwrap()
                .root_actual
        );

        let _ = fs::remove_file(&docx);
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
    }

    #[test]
    fn embedded_visual_objects_projection_is_deterministic_and_connected() {
        let docx = write_embedded_visual_objects_docx("embedded-objects");
        let first = import_docx(&docx).unwrap();
        let second = import_docx(&docx).unwrap();

        assert_eq!(
            first.document.semantic.embedded_visual_objects,
            second.document.semantic.embedded_visual_objects
        );
        assert_eq!(
            collect_object_semantic_ids(&first.document.semantic),
            collect_object_semantic_ids(&second.document.semantic)
        );

        let registry = first
            .document
            .semantic
            .embedded_visual_objects
            .as_ref()
            .unwrap();
        assert_eq!(registry.source_part, "word/document.xml");
        assert!(registry
            .objects
            .iter()
            .any(|object| object.kind == EmbeddedVisualObjectKind::Chart));
        assert!(registry
            .objects
            .iter()
            .any(|object| object.kind == EmbeddedVisualObjectKind::SmartartDiagram));
        assert!(registry
            .objects
            .iter()
            .any(|object| object.kind == EmbeddedVisualObjectKind::OleEmbeddedObject));
        assert!(registry
            .objects
            .iter()
            .any(|object| object.kind == EmbeddedVisualObjectKind::OleLinkedObject));
        assert!(registry
            .objects
            .iter()
            .any(|object| object.kind == EmbeddedVisualObjectKind::EmbeddedPackage));
        assert!(registry
            .objects
            .iter()
            .any(|object| object.kind == EmbeddedVisualObjectKind::ActivexBlocked));

        let chart = registry
            .objects
            .iter()
            .find(|object| object.kind == EmbeddedVisualObjectKind::Chart)
            .unwrap();
        let chart_projection = chart.chart.as_ref().unwrap();
        assert_eq!(chart_projection.chart_type, "bar");
        assert_eq!(
            chart_projection
                .title
                .as_ref()
                .map(|title| title.text.as_str()),
            Some("Chart Title")
        );
        assert_eq!(chart_projection.series.len(), 1);
        assert_eq!(
            chart_projection.series[0].title.as_deref(),
            Some("Series 1")
        );
        assert_eq!(
            chart_projection.series[0]
                .category_reference
                .as_ref()
                .and_then(|value| value.formula.as_deref()),
            Some("Sheet1!$A$1:$A$2")
        );
        assert_eq!(
            chart_projection.series[0]
                .value_reference
                .as_ref()
                .and_then(|value| value.formula.as_deref()),
            Some("Sheet1!$B$1:$B$2")
        );
        assert_eq!(
            chart_projection
                .embedded_workbook
                .as_ref()
                .and_then(|resource| { resource.part_path.as_deref() }),
            Some("word/embeddings/workbook1.xlsx")
        );
        assert_eq!(
            chart_projection
                .external_data
                .as_ref()
                .and_then(|target| target.raw_target.as_deref()),
            Some("https://example.invalid/chart-data.xlsx")
        );

        let diagram = registry
            .objects
            .iter()
            .find(|object| object.kind == EmbeddedVisualObjectKind::SmartartDiagram)
            .unwrap();
        let diagram_projection = diagram.diagram.as_ref().unwrap();
        assert_eq!(
            diagram_projection
                .data_part
                .as_ref()
                .and_then(|part| part.part_path.as_deref()),
            Some("word/diagrams/data1.xml")
        );
        assert_eq!(diagram_projection.points.len(), 2);
        assert!(diagram_projection.texts.iter().any(|text| text == "Node A"));
        assert!(diagram_projection
            .connections
            .iter()
            .any(|connection| connection == "1:0:2"));

        let previewed_ole = registry
            .objects
            .iter()
            .find(|object| {
                object.kind == EmbeddedVisualObjectKind::OleEmbeddedObject
                    && object.preview_image.is_some()
            })
            .unwrap();
        assert_eq!(
            previewed_ole
                .preview_image
                .as_ref()
                .and_then(|resource| resource.part_path.as_deref()),
            Some("word/media/preview.png")
        );
        assert_eq!(
            previewed_ole
                .targets
                .iter()
                .find(|target| target.role.as_deref() == Some("object"))
                .and_then(|target| target.resource.as_ref())
                .and_then(|resource| resource.part_path.as_deref()),
            Some("word/embeddings/oleObject1.bin")
        );
        assert_eq!(
            previewed_ole
                .ole
                .as_ref()
                .and_then(|ole| ole.metadata.prog_id.as_deref()),
            Some("Word.Document.12")
        );

        assert!(registry.objects.iter().any(|object| {
            object.kind == EmbeddedVisualObjectKind::OleLinkedObject
                && object
                    .targets
                    .iter()
                    .any(|target| target.kind == EmbeddedObjectTargetKind::ExternalRelationship)
        }));
        assert!(registry.objects.iter().any(|object| {
            object.kind == EmbeddedVisualObjectKind::EmbeddedPackage
                && object.package_resource.is_some()
        }));

        let shared_digest = previewed_ole
            .targets
            .iter()
            .find(|target| target.role.as_deref() == Some("object"))
            .and_then(|target| target.resource.as_ref())
            .and_then(|resource| resource.object_digest.as_deref())
            .unwrap();
        assert!(
            registry
                .objects
                .iter()
                .flat_map(|object| object.targets.iter())
                .filter_map(|target| target.resource.as_ref())
                .filter(|resource| resource.object_digest.as_deref() == Some(shared_digest))
                .count()
                >= 2
        );

        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "CVN_EMBEDDED_OBJECT_RELATIONSHIP_MISSING" }));
        assert!(registry.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "CVN_EMBEDDED_OBJECT_RELATIONSHIP_TYPE_MISMATCH"
        }));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_EMBEDDED_OBJECT_PART_MISSING"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_EMBEDDED_OBJECT_EXTERNAL_TARGET_INERT"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_EMBEDDED_OBJECT_ACTIVEX_BLOCKED"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_CHART_FORMULA_NOT_EVALUATED"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_CHART_EXTERNAL_DATA_INERT"));
        assert!(registry
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CVN_DIAGRAM_PART_MISSING"));

        assert!(semantic_contains_object_wrapper(&first.document.semantic));
        let top_level_chart = drawing_inline_at(&first.document.semantic.blocks, 0, 0, 0);
        assert!(drawing_contains_object_kind(
            top_level_chart,
            EmbeddedVisualObjectKind::Chart
        ));
        let top_level_chart_object = top_level_chart
            .embedded_visual_objects
            .iter()
            .find(|object| object.kind == EmbeddedVisualObjectKind::Chart)
            .unwrap();
        assert_ne!(top_level_chart.id, top_level_chart_object.id);

        let top_level_diagram = drawing_inline_at(&first.document.semantic.blocks, 1, 0, 0);
        assert!(drawing_contains_object_kind(
            top_level_diagram,
            EmbeddedVisualObjectKind::SmartartDiagram
        ));
        assert!(matches!(
            inline_at(&first.document.semantic.blocks, 2, 0, 0),
            SemanticInline::EmbeddedVisualObject(object)
                if object.kind == EmbeddedVisualObjectKind::OleEmbeddedObject
        ));
        assert!(contains_hyperlink_with_drawing_object_kind(
            &first.document.semantic.blocks,
            EmbeddedVisualObjectKind::Chart
        ));
        assert!(contains_field_with_drawing_object_kind(
            &first.document.semantic.blocks,
            EmbeddedVisualObjectKind::SmartartDiagram
        ));
        assert!(contains_tracked_change_with_drawing_object_kind(
            &first.document.semantic.blocks,
            EmbeddedVisualObjectKind::Chart
        ));
        assert!(contains_mce_with_drawing_object_kind(
            &first.document.semantic.blocks,
            EmbeddedVisualObjectKind::SmartartDiagram
        ));
        let main_objects = collect_objects_from_blocks_for_test(&first.document.semantic.blocks);
        assert!(main_objects.len() >= 10);
        assert!(
            main_objects
                .iter()
                .filter(|object| object.kind == EmbeddedVisualObjectKind::Chart)
                .count()
                >= 4
        );
        assert!(
            story_part_objects(&first.document.semantic, StoryPartKind::HeaderDefault).len() >= 2
        );
        assert!(
            story_part_drawings(&first.document.semantic, StoryPartKind::HeaderDefault)
                .iter()
                .any(|drawing| {
                    drawing_contains_object_kind(drawing, EmbeddedVisualObjectKind::Chart)
                })
        );
        assert!(story_part_objects(&first.document.semantic, StoryPartKind::Footnotes).len() >= 2);
        assert!(
            story_part_drawings(&first.document.semantic, StoryPartKind::Footnotes)
                .iter()
                .any(|drawing| {
                    drawing_contains_object_kind(drawing, EmbeddedVisualObjectKind::SmartartDiagram)
                })
        );

        let out1 =
            std::env::temp_dir().join(format!("tuff-cvn-objects-out-1-{}", std::process::id()));
        let out2 =
            std::env::temp_dir().join(format!("tuff-cvn-objects-out-2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
        cvn_package::write_package(&out1, &first).unwrap();
        cvn_package::write_package(&out2, &second).unwrap();
        assert_eq!(
            cvn_package::read_cvn_json_bytes(&out1).unwrap(),
            cvn_package::read_cvn_json_bytes(&out2).unwrap()
        );
        assert_eq!(
            cvn_package::verify_package_integrity(&out1)
                .unwrap()
                .root_actual,
            cvn_package::verify_package_integrity(&out2)
                .unwrap()
                .root_actual
        );

        let _ = fs::remove_file(&docx);
        let _ = fs::remove_dir_all(&out1);
        let _ = fs::remove_dir_all(&out2);
    }

    fn collect_block_ids(block: &SemanticBlock, ids: &mut Vec<String>) {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                ids.push(paragraph.id.as_str().to_owned());
                for run in &paragraph.runs {
                    ids.push(run.id.as_str().to_owned());
                }
            }
            SemanticBlock::Table(table) => {
                ids.push(table.id.as_str().to_owned());
                for row in &table.rows {
                    ids.push(row.id.as_str().to_owned());
                    for cell in &row.cells {
                        ids.push(cell.id.as_str().to_owned());
                        for block in &cell.blocks {
                            collect_block_ids(block, ids);
                        }
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => {
                ids.push(change.semantic_node_id.as_str().to_owned());
                if let TrackedContent::Block { blocks } = &change.content {
                    for block in blocks {
                        collect_block_ids(block, ids);
                    }
                }
            }
            SemanticBlock::MceSelectedContent(content) => {
                ids.push(content.projection.id.as_str().to_owned());
                for block in &content.blocks {
                    collect_block_ids(block, ids);
                }
            }
        }
    }

    fn collect_reference_semantic_ids(document: &SemanticDocument) -> Vec<String> {
        let mut ids = Vec::new();
        collect_reference_ids_from_blocks(&document.blocks, &mut ids);
        if let Some(stories) = document.stories.as_ref() {
            for part in &stories.parts {
                collect_reference_ids_from_blocks(&part.blocks, &mut ids);
                for note in &part.notes {
                    collect_reference_ids_from_blocks(&note.blocks, &mut ids);
                }
                for comment in &part.comments {
                    collect_reference_ids_from_blocks(&comment.blocks, &mut ids);
                }
            }
        }
        ids.sort();
        ids
    }

    fn collect_reference_ids_from_blocks(blocks: &[SemanticBlock], ids: &mut Vec<String>) {
        for block in blocks {
            match block {
                SemanticBlock::Paragraph(paragraph) => {
                    for run in &paragraph.runs {
                        collect_reference_ids_from_inlines(&run.inlines, ids);
                    }
                }
                SemanticBlock::Table(table) => {
                    for row in &table.rows {
                        for cell in &row.cells {
                            collect_reference_ids_from_blocks(&cell.blocks, ids);
                        }
                    }
                }
                SemanticBlock::TrackedChange(change) => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_reference_ids_from_inlines(items, ids);
                    }
                    TrackedContent::Block { blocks } => {
                        collect_reference_ids_from_blocks(blocks, ids);
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticBlock::MceSelectedContent(content) => {
                    collect_reference_ids_from_blocks(&content.blocks, ids);
                    collect_reference_ids_from_inlines(&content.inlines, ids);
                }
            }
        }
    }

    fn collect_reference_ids_from_inlines(inlines: &[SemanticInline], ids: &mut Vec<String>) {
        for inline in inlines {
            match inline {
                SemanticInline::Hyperlink(hyperlink) => {
                    ids.push(hyperlink.id.as_str().to_owned());
                    collect_reference_ids_from_inlines(&hyperlink.children, ids);
                }
                SemanticInline::BookmarkStart(bookmark) | SemanticInline::BookmarkEnd(bookmark) => {
                    ids.push(bookmark.id.as_str().to_owned());
                }
                SemanticInline::Field(field) => {
                    ids.push(field.id.as_str().to_owned());
                    collect_reference_ids_from_inlines(&field.result.children, ids);
                }
                SemanticInline::Drawing(drawing) => {
                    ids.push(drawing.id.as_str().to_owned());
                }
                SemanticInline::EmbeddedVisualObject(object) => {
                    ids.push(object.id.as_str().to_owned());
                }
                SemanticInline::TrackedChange { change } => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_reference_ids_from_inlines(items, ids);
                    }
                    TrackedContent::Block { blocks } => {
                        collect_reference_ids_from_blocks(blocks, ids);
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticInline::MceSelectedContent(content) => {
                    collect_reference_ids_from_blocks(&content.blocks, ids);
                    collect_reference_ids_from_inlines(&content.inlines, ids);
                }
                SemanticInline::Text(_)
                | SemanticInline::Tab
                | SemanticInline::LineBreak { .. }
                | SemanticInline::FootnoteReference { .. }
                | SemanticInline::EndnoteReference { .. }
                | SemanticInline::CommentReference { .. }
                | SemanticInline::CommentRangeStart { .. }
                | SemanticInline::CommentRangeEnd { .. } => {}
            }
        }
    }

    fn semantic_contains_hyperlink_wrapper(document: &SemanticDocument) -> bool {
        contains_inline_wrapper(&document.blocks, |inline| {
            matches!(inline, SemanticInline::Hyperlink(_))
        }) || document.stories.as_ref().is_some_and(|stories| {
            stories.parts.iter().any(|part| {
                contains_inline_wrapper(&part.blocks, |inline| {
                    matches!(inline, SemanticInline::Hyperlink(_))
                }) || part.notes.iter().any(|note| {
                    contains_inline_wrapper(&note.blocks, |inline| {
                        matches!(inline, SemanticInline::Hyperlink(_))
                    })
                }) || part.comments.iter().any(|comment| {
                    contains_inline_wrapper(&comment.blocks, |inline| {
                        matches!(inline, SemanticInline::Hyperlink(_))
                    })
                })
            })
        })
    }

    fn semantic_contains_field_wrapper(document: &SemanticDocument) -> bool {
        contains_inline_wrapper(&document.blocks, |inline| {
            matches!(inline, SemanticInline::Field(_))
        }) || document.stories.as_ref().is_some_and(|stories| {
            stories.parts.iter().any(|part| {
                contains_inline_wrapper(&part.blocks, |inline| {
                    matches!(inline, SemanticInline::Field(_))
                }) || part.notes.iter().any(|note| {
                    contains_inline_wrapper(&note.blocks, |inline| {
                        matches!(inline, SemanticInline::Field(_))
                    })
                }) || part.comments.iter().any(|comment| {
                    contains_inline_wrapper(&comment.blocks, |inline| {
                        matches!(inline, SemanticInline::Field(_))
                    })
                })
            })
        })
    }

    fn semantic_contains_drawing_wrapper(document: &SemanticDocument) -> bool {
        contains_inline_wrapper(&document.blocks, |inline| {
            matches!(inline, SemanticInline::Drawing(_))
        }) || document.stories.as_ref().is_some_and(|stories| {
            stories.parts.iter().any(|part| {
                contains_inline_wrapper(&part.blocks, |inline| {
                    matches!(inline, SemanticInline::Drawing(_))
                }) || part.notes.iter().any(|note| {
                    contains_inline_wrapper(&note.blocks, |inline| {
                        matches!(inline, SemanticInline::Drawing(_))
                    })
                }) || part.comments.iter().any(|comment| {
                    contains_inline_wrapper(&comment.blocks, |inline| {
                        matches!(inline, SemanticInline::Drawing(_))
                    })
                })
            })
        })
    }

    fn semantic_contains_object_wrapper(document: &SemanticDocument) -> bool {
        !collect_objects_from_blocks_for_test(&document.blocks).is_empty()
            || document.stories.as_ref().is_some_and(|stories| {
                stories.parts.iter().any(|part| {
                    !collect_objects_from_blocks_for_test(&part.blocks).is_empty()
                        || part.notes.iter().any(|note| {
                            !collect_objects_from_blocks_for_test(&note.blocks).is_empty()
                        })
                        || part.comments.iter().any(|comment| {
                            !collect_objects_from_blocks_for_test(&comment.blocks).is_empty()
                        })
                })
            })
    }

    fn collect_drawing_semantic_ids(document: &SemanticDocument) -> Vec<String> {
        let mut ids = Vec::new();
        collect_drawing_ids_from_blocks(&document.blocks, &mut ids);
        if let Some(stories) = document.stories.as_ref() {
            for part in &stories.parts {
                collect_drawing_ids_from_blocks(&part.blocks, &mut ids);
                for note in &part.notes {
                    collect_drawing_ids_from_blocks(&note.blocks, &mut ids);
                }
                for comment in &part.comments {
                    collect_drawing_ids_from_blocks(&comment.blocks, &mut ids);
                }
            }
        }
        ids.sort();
        ids
    }

    fn collect_object_semantic_ids(document: &SemanticDocument) -> Vec<String> {
        let mut ids = Vec::new();
        collect_object_ids_from_blocks(&document.blocks, &mut ids);
        if let Some(stories) = document.stories.as_ref() {
            for part in &stories.parts {
                collect_object_ids_from_blocks(&part.blocks, &mut ids);
                for note in &part.notes {
                    collect_object_ids_from_blocks(&note.blocks, &mut ids);
                }
                for comment in &part.comments {
                    collect_object_ids_from_blocks(&comment.blocks, &mut ids);
                }
            }
        }
        ids.sort();
        ids
    }

    fn collect_drawing_ids_from_blocks(blocks: &[SemanticBlock], ids: &mut Vec<String>) {
        for block in blocks {
            match block {
                SemanticBlock::Paragraph(paragraph) => {
                    for run in &paragraph.runs {
                        collect_drawing_ids_from_inlines(&run.inlines, ids);
                    }
                }
                SemanticBlock::Table(table) => {
                    for row in &table.rows {
                        for cell in &row.cells {
                            collect_drawing_ids_from_blocks(&cell.blocks, ids);
                        }
                    }
                }
                SemanticBlock::TrackedChange(change) => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_drawing_ids_from_inlines(items, ids);
                    }
                    TrackedContent::Block { blocks } => {
                        collect_drawing_ids_from_blocks(blocks, ids);
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticBlock::MceSelectedContent(content) => {
                    collect_drawing_ids_from_blocks(&content.blocks, ids);
                    collect_drawing_ids_from_inlines(&content.inlines, ids);
                }
            }
        }
    }

    fn collect_drawing_ids_from_inlines(inlines: &[SemanticInline], ids: &mut Vec<String>) {
        for inline in inlines {
            match inline {
                SemanticInline::Drawing(drawing) => {
                    ids.push(drawing.id.as_str().to_owned());
                }
                SemanticInline::Hyperlink(hyperlink) => {
                    collect_drawing_ids_from_inlines(&hyperlink.children, ids);
                }
                SemanticInline::Field(field) => {
                    collect_drawing_ids_from_inlines(&field.result.children, ids);
                }
                SemanticInline::TrackedChange { change } => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_drawing_ids_from_inlines(items, ids);
                    }
                    TrackedContent::Block { blocks } => {
                        collect_drawing_ids_from_blocks(blocks, ids);
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticInline::MceSelectedContent(content) => {
                    collect_drawing_ids_from_blocks(&content.blocks, ids);
                    collect_drawing_ids_from_inlines(&content.inlines, ids);
                }
                SemanticInline::BookmarkStart(_)
                | SemanticInline::BookmarkEnd(_)
                | SemanticInline::EmbeddedVisualObject(_)
                | SemanticInline::Text(_)
                | SemanticInline::Tab
                | SemanticInline::LineBreak { .. }
                | SemanticInline::FootnoteReference { .. }
                | SemanticInline::EndnoteReference { .. }
                | SemanticInline::CommentReference { .. }
                | SemanticInline::CommentRangeStart { .. }
                | SemanticInline::CommentRangeEnd { .. } => {}
            }
        }
    }

    fn collect_object_ids_from_blocks(blocks: &[SemanticBlock], ids: &mut Vec<String>) {
        for block in blocks {
            match block {
                SemanticBlock::Paragraph(paragraph) => {
                    for run in &paragraph.runs {
                        collect_object_ids_from_inlines(&run.inlines, ids);
                    }
                }
                SemanticBlock::Table(table) => {
                    for row in &table.rows {
                        for cell in &row.cells {
                            collect_object_ids_from_blocks(&cell.blocks, ids);
                        }
                    }
                }
                SemanticBlock::TrackedChange(change) => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_object_ids_from_inlines(items, ids);
                    }
                    TrackedContent::Block { blocks } => {
                        collect_object_ids_from_blocks(blocks, ids);
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticBlock::MceSelectedContent(content) => {
                    collect_object_ids_from_blocks(&content.blocks, ids);
                    collect_object_ids_from_inlines(&content.inlines, ids);
                }
            }
        }
    }

    fn collect_object_ids_from_inlines(inlines: &[SemanticInline], ids: &mut Vec<String>) {
        for inline in inlines {
            match inline {
                SemanticInline::EmbeddedVisualObject(object) => {
                    ids.push(object.id.as_str().to_owned());
                }
                SemanticInline::Hyperlink(hyperlink) => {
                    collect_object_ids_from_inlines(&hyperlink.children, ids);
                }
                SemanticInline::Field(field) => {
                    collect_object_ids_from_inlines(&field.result.children, ids);
                }
                SemanticInline::TrackedChange { change } => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_object_ids_from_inlines(items, ids);
                    }
                    TrackedContent::Block { blocks } => {
                        collect_object_ids_from_blocks(blocks, ids);
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticInline::MceSelectedContent(content) => {
                    collect_object_ids_from_blocks(&content.blocks, ids);
                    collect_object_ids_from_inlines(&content.inlines, ids);
                }
                SemanticInline::Drawing(drawing) => {
                    for object in &drawing.embedded_visual_objects {
                        ids.push(object.id.as_str().to_owned());
                    }
                }
                SemanticInline::BookmarkStart(_)
                | SemanticInline::BookmarkEnd(_)
                | SemanticInline::Text(_)
                | SemanticInline::Tab
                | SemanticInline::LineBreak { .. }
                | SemanticInline::FootnoteReference { .. }
                | SemanticInline::EndnoteReference { .. }
                | SemanticInline::CommentReference { .. }
                | SemanticInline::CommentRangeStart { .. }
                | SemanticInline::CommentRangeEnd { .. } => {}
            }
        }
    }

    fn story_part_drawings<'a>(
        document: &'a SemanticDocument,
        kind: StoryPartKind,
    ) -> Vec<&'a DrawingProjection> {
        let mut drawings = Vec::new();
        if let Some(stories) = document.stories.as_ref() {
            for part in &stories.parts {
                if part.kind != kind {
                    continue;
                }
                drawings.extend(collect_drawings_from_blocks_for_test(&part.blocks));
                for note in &part.notes {
                    drawings.extend(collect_drawings_from_blocks_for_test(&note.blocks));
                }
                for comment in &part.comments {
                    drawings.extend(collect_drawings_from_blocks_for_test(&comment.blocks));
                }
            }
        }
        drawings
    }

    fn story_part_objects<'a>(
        document: &'a SemanticDocument,
        kind: StoryPartKind,
    ) -> Vec<&'a EmbeddedVisualObjectProjection> {
        let mut objects = Vec::new();
        if let Some(stories) = document.stories.as_ref() {
            for part in &stories.parts {
                if part.kind != kind {
                    continue;
                }
                objects.extend(collect_objects_from_blocks_for_test(&part.blocks));
                for note in &part.notes {
                    objects.extend(collect_objects_from_blocks_for_test(&note.blocks));
                }
                for comment in &part.comments {
                    objects.extend(collect_objects_from_blocks_for_test(&comment.blocks));
                }
            }
        }
        objects
    }

    fn inline_at(
        blocks: &[SemanticBlock],
        paragraph_index: usize,
        run_index: usize,
        inline_index: usize,
    ) -> &SemanticInline {
        let SemanticBlock::Paragraph(paragraph) = &blocks[paragraph_index] else {
            panic!("expected paragraph at block index {paragraph_index}");
        };
        &paragraph.runs[run_index].inlines[inline_index]
    }

    fn drawing_inline_at(
        blocks: &[SemanticBlock],
        paragraph_index: usize,
        run_index: usize,
        inline_index: usize,
    ) -> &DrawingProjection {
        match inline_at(blocks, paragraph_index, run_index, inline_index) {
            SemanticInline::Drawing(drawing) => drawing,
            other => panic!("expected drawing inline, found {other:?}"),
        }
    }

    fn drawing_contains_object_kind(
        drawing: &DrawingProjection,
        kind: EmbeddedVisualObjectKind,
    ) -> bool {
        drawing
            .embedded_visual_objects
            .iter()
            .any(|object| object.kind == kind)
    }

    fn contains_hyperlink_with_drawing_object_kind(
        blocks: &[SemanticBlock],
        kind: EmbeddedVisualObjectKind,
    ) -> bool {
        contains_inline_wrapper(blocks, |inline| {
            match inline {
            SemanticInline::Hyperlink(hyperlink) => hyperlink.children.iter().any(|child| {
                matches!(child, SemanticInline::Drawing(drawing) if drawing_contains_object_kind(drawing, kind))
            }),
            _ => false,
        }
        })
    }

    fn contains_field_with_drawing_object_kind(
        blocks: &[SemanticBlock],
        kind: EmbeddedVisualObjectKind,
    ) -> bool {
        contains_inline_wrapper(blocks, |inline| {
            match inline {
            SemanticInline::Field(field) => field.result.children.iter().any(|child| {
                matches!(child, SemanticInline::Drawing(drawing) if drawing_contains_object_kind(drawing, kind))
            }),
            _ => false,
        }
        })
    }

    fn contains_tracked_change_with_drawing_object_kind(
        blocks: &[SemanticBlock],
        kind: EmbeddedVisualObjectKind,
    ) -> bool {
        contains_drawing_object_kind_in_blocks(blocks, kind, false)
    }

    fn tracked_content_contains_drawing_object_kind(
        content: &TrackedContent,
        kind: EmbeddedVisualObjectKind,
    ) -> bool {
        match content {
            TrackedContent::Inline { items } => {
                contains_drawing_object_kind_in_inlines(items, kind, true)
            }
            TrackedContent::Block { blocks } => {
                contains_drawing_object_kind_in_blocks(blocks, kind, true)
            }
            TrackedContent::PropertyChange { .. } => false,
        }
    }

    fn contains_drawing_object_kind_in_blocks(
        blocks: &[SemanticBlock],
        kind: EmbeddedVisualObjectKind,
        within_tracked_change: bool,
    ) -> bool {
        blocks.iter().any(|block| match block {
            SemanticBlock::Paragraph(paragraph) => paragraph.runs.iter().any(|run| {
                contains_drawing_object_kind_in_inlines(&run.inlines, kind, within_tracked_change)
            }),
            SemanticBlock::Table(table) => table.rows.iter().any(|row| {
                row.cells.iter().any(|cell| {
                    contains_drawing_object_kind_in_blocks(
                        &cell.blocks,
                        kind,
                        within_tracked_change,
                    )
                })
            }),
            SemanticBlock::TrackedChange(change) => {
                tracked_content_contains_drawing_object_kind(&change.content, kind)
            }
            SemanticBlock::MceSelectedContent(content) => {
                contains_drawing_object_kind_in_blocks(&content.blocks, kind, within_tracked_change)
                    || contains_drawing_object_kind_in_inlines(
                        &content.inlines,
                        kind,
                        within_tracked_change,
                    )
            }
        })
    }

    fn contains_drawing_object_kind_in_inlines(
        inlines: &[SemanticInline],
        kind: EmbeddedVisualObjectKind,
        within_tracked_change: bool,
    ) -> bool {
        inlines.iter().any(|inline| match inline {
            SemanticInline::Drawing(drawing) => {
                within_tracked_change && drawing_contains_object_kind(drawing, kind)
            }
            SemanticInline::Hyperlink(hyperlink) => contains_drawing_object_kind_in_inlines(
                &hyperlink.children,
                kind,
                within_tracked_change,
            ),
            SemanticInline::Field(field) => contains_drawing_object_kind_in_inlines(
                &field.result.children,
                kind,
                within_tracked_change,
            ),
            SemanticInline::TrackedChange { change } => {
                tracked_content_contains_drawing_object_kind(&change.content, kind)
            }
            SemanticInline::MceSelectedContent(content) => {
                contains_drawing_object_kind_in_blocks(&content.blocks, kind, within_tracked_change)
                    || contains_drawing_object_kind_in_inlines(
                        &content.inlines,
                        kind,
                        within_tracked_change,
                    )
            }
            SemanticInline::EmbeddedVisualObject(_)
            | SemanticInline::BookmarkStart(_)
            | SemanticInline::BookmarkEnd(_)
            | SemanticInline::Text(_)
            | SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::FootnoteReference { .. }
            | SemanticInline::EndnoteReference { .. }
            | SemanticInline::CommentReference { .. }
            | SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. } => false,
        })
    }

    fn contains_mce_with_drawing_object_kind(
        blocks: &[SemanticBlock],
        kind: EmbeddedVisualObjectKind,
    ) -> bool {
        blocks.iter().any(|block| match block {
            SemanticBlock::MceSelectedContent(content) => {
                content.blocks.iter().any(|inner| match inner {
                    SemanticBlock::Paragraph(paragraph) => paragraph.runs.iter().any(|run| {
                        run.inlines.iter().any(|inline| {
                            matches!(inline, SemanticInline::Drawing(drawing) if drawing_contains_object_kind(drawing, kind))
                        })
                    }),
                    SemanticBlock::Table(table) => table.rows.iter().any(|row| {
                        row.cells
                            .iter()
                            .any(|cell| contains_mce_with_drawing_object_kind(&cell.blocks, kind))
                    }),
                    SemanticBlock::TrackedChange(change) => {
                        tracked_content_contains_drawing_object_kind(&change.content, kind)
                    }
                    SemanticBlock::MceSelectedContent(content) => {
                        contains_mce_with_drawing_object_kind(&content.blocks, kind)
                    }
                }) || content.inlines.iter().any(|inline| {
                    matches!(inline, SemanticInline::Drawing(drawing) if drawing_contains_object_kind(drawing, kind))
                })
            }
            SemanticBlock::Paragraph(paragraph) => paragraph.runs.iter().any(|run| {
                run.inlines.iter().any(|inline| match inline {
                    SemanticInline::MceSelectedContent(content) => {
                        content.inlines.iter().any(|child| {
                            matches!(child, SemanticInline::Drawing(drawing) if drawing_contains_object_kind(drawing, kind))
                        }) || contains_mce_with_drawing_object_kind(&content.blocks, kind)
                    }
                    _ => false,
                })
            }),
            SemanticBlock::Table(table) => table.rows.iter().any(|row| {
                row.cells
                    .iter()
                    .any(|cell| contains_mce_with_drawing_object_kind(&cell.blocks, kind))
            }),
            SemanticBlock::TrackedChange(change) => match &change.content {
                TrackedContent::Block { blocks } => contains_mce_with_drawing_object_kind(blocks, kind),
                TrackedContent::Inline { items } => items.iter().any(|inline| match inline {
                    SemanticInline::MceSelectedContent(content) => {
                        content.inlines.iter().any(|child| {
                            matches!(child, SemanticInline::Drawing(drawing) if drawing_contains_object_kind(drawing, kind))
                        }) || contains_mce_with_drawing_object_kind(&content.blocks, kind)
                    }
                    _ => false,
                }),
                TrackedContent::PropertyChange { .. } => false,
            },
        })
    }

    fn collect_drawings_from_blocks_for_test<'a>(
        blocks: &'a [SemanticBlock],
    ) -> Vec<&'a DrawingProjection> {
        let mut drawings = Vec::new();
        for block in blocks {
            match block {
                SemanticBlock::Paragraph(paragraph) => {
                    for run in &paragraph.runs {
                        collect_drawings_from_inlines_for_test(&run.inlines, &mut drawings);
                    }
                }
                SemanticBlock::Table(table) => {
                    for row in &table.rows {
                        for cell in &row.cells {
                            drawings.extend(collect_drawings_from_blocks_for_test(&cell.blocks));
                        }
                    }
                }
                SemanticBlock::TrackedChange(change) => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_drawings_from_inlines_for_test(items, &mut drawings);
                    }
                    TrackedContent::Block { blocks } => {
                        drawings.extend(collect_drawings_from_blocks_for_test(blocks));
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticBlock::MceSelectedContent(content) => {
                    drawings.extend(collect_drawings_from_blocks_for_test(&content.blocks));
                    collect_drawings_from_inlines_for_test(&content.inlines, &mut drawings);
                }
            }
        }
        drawings
    }

    fn collect_objects_from_blocks_for_test<'a>(
        blocks: &'a [SemanticBlock],
    ) -> Vec<&'a EmbeddedVisualObjectProjection> {
        let mut objects = Vec::new();
        for block in blocks {
            match block {
                SemanticBlock::Paragraph(paragraph) => {
                    for run in &paragraph.runs {
                        collect_objects_from_inlines_for_test(&run.inlines, &mut objects);
                    }
                }
                SemanticBlock::Table(table) => {
                    for row in &table.rows {
                        for cell in &row.cells {
                            objects.extend(collect_objects_from_blocks_for_test(&cell.blocks));
                        }
                    }
                }
                SemanticBlock::TrackedChange(change) => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_objects_from_inlines_for_test(items, &mut objects);
                    }
                    TrackedContent::Block { blocks } => {
                        objects.extend(collect_objects_from_blocks_for_test(blocks));
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticBlock::MceSelectedContent(content) => {
                    objects.extend(collect_objects_from_blocks_for_test(&content.blocks));
                    collect_objects_from_inlines_for_test(&content.inlines, &mut objects);
                }
            }
        }
        objects
    }

    fn collect_drawings_from_inlines_for_test<'a>(
        inlines: &'a [SemanticInline],
        drawings: &mut Vec<&'a DrawingProjection>,
    ) {
        for inline in inlines {
            match inline {
                SemanticInline::Drawing(drawing) => drawings.push(drawing),
                SemanticInline::EmbeddedVisualObject(_) => {}
                SemanticInline::Hyperlink(hyperlink) => {
                    collect_drawings_from_inlines_for_test(&hyperlink.children, drawings);
                }
                SemanticInline::Field(field) => {
                    collect_drawings_from_inlines_for_test(&field.result.children, drawings);
                }
                SemanticInline::TrackedChange { change } => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_drawings_from_inlines_for_test(items, drawings);
                    }
                    TrackedContent::Block { blocks } => {
                        drawings.extend(collect_drawings_from_blocks_for_test(blocks));
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticInline::MceSelectedContent(content) => {
                    drawings.extend(collect_drawings_from_blocks_for_test(&content.blocks));
                    collect_drawings_from_inlines_for_test(&content.inlines, drawings);
                }
                SemanticInline::BookmarkStart(_)
                | SemanticInline::BookmarkEnd(_)
                | SemanticInline::Text(_)
                | SemanticInline::Tab
                | SemanticInline::LineBreak { .. }
                | SemanticInline::FootnoteReference { .. }
                | SemanticInline::EndnoteReference { .. }
                | SemanticInline::CommentReference { .. }
                | SemanticInline::CommentRangeStart { .. }
                | SemanticInline::CommentRangeEnd { .. } => {}
            }
        }
    }

    fn collect_objects_from_inlines_for_test<'a>(
        inlines: &'a [SemanticInline],
        objects: &mut Vec<&'a EmbeddedVisualObjectProjection>,
    ) {
        for inline in inlines {
            match inline {
                SemanticInline::Drawing(drawing) => {
                    objects.extend(drawing.embedded_visual_objects.iter());
                }
                SemanticInline::EmbeddedVisualObject(object) => objects.push(object),
                SemanticInline::Hyperlink(hyperlink) => {
                    collect_objects_from_inlines_for_test(&hyperlink.children, objects);
                }
                SemanticInline::Field(field) => {
                    collect_objects_from_inlines_for_test(&field.result.children, objects);
                }
                SemanticInline::TrackedChange { change } => match &change.content {
                    TrackedContent::Inline { items } => {
                        collect_objects_from_inlines_for_test(items, objects);
                    }
                    TrackedContent::Block { blocks } => {
                        objects.extend(collect_objects_from_blocks_for_test(blocks));
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticInline::MceSelectedContent(content) => {
                    objects.extend(collect_objects_from_blocks_for_test(&content.blocks));
                    collect_objects_from_inlines_for_test(&content.inlines, objects);
                }
                SemanticInline::BookmarkStart(_)
                | SemanticInline::BookmarkEnd(_)
                | SemanticInline::Text(_)
                | SemanticInline::Tab
                | SemanticInline::LineBreak { .. }
                | SemanticInline::FootnoteReference { .. }
                | SemanticInline::EndnoteReference { .. }
                | SemanticInline::CommentReference { .. }
                | SemanticInline::CommentRangeStart { .. }
                | SemanticInline::CommentRangeEnd { .. } => {}
            }
        }
    }

    fn contains_inline_wrapper(
        blocks: &[SemanticBlock],
        predicate: impl Copy + Fn(&SemanticInline) -> bool,
    ) -> bool {
        for block in blocks {
            match block {
                SemanticBlock::Paragraph(paragraph) => {
                    for run in &paragraph.runs {
                        if contains_inline_wrapper_in_inlines(&run.inlines, predicate) {
                            return true;
                        }
                    }
                }
                SemanticBlock::Table(table) => {
                    for row in &table.rows {
                        for cell in &row.cells {
                            if contains_inline_wrapper(&cell.blocks, predicate) {
                                return true;
                            }
                        }
                    }
                }
                SemanticBlock::TrackedChange(change) => match &change.content {
                    TrackedContent::Inline { items } => {
                        if contains_inline_wrapper_in_inlines(items, predicate) {
                            return true;
                        }
                    }
                    TrackedContent::Block { blocks } => {
                        if contains_inline_wrapper(blocks, predicate) {
                            return true;
                        }
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticBlock::MceSelectedContent(content) => {
                    if contains_inline_wrapper(&content.blocks, predicate)
                        || contains_inline_wrapper_in_inlines(&content.inlines, predicate)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn contains_inline_wrapper_in_inlines(
        inlines: &[SemanticInline],
        predicate: impl Copy + Fn(&SemanticInline) -> bool,
    ) -> bool {
        for inline in inlines {
            if predicate(inline) {
                return true;
            }
            match inline {
                SemanticInline::Hyperlink(hyperlink) => {
                    if contains_inline_wrapper_in_inlines(&hyperlink.children, predicate) {
                        return true;
                    }
                }
                SemanticInline::Field(field) => {
                    if contains_inline_wrapper_in_inlines(&field.result.children, predicate) {
                        return true;
                    }
                }
                SemanticInline::Drawing(_) | SemanticInline::EmbeddedVisualObject(_) => {}
                SemanticInline::TrackedChange { change } => match &change.content {
                    TrackedContent::Inline { items } => {
                        if contains_inline_wrapper_in_inlines(items, predicate) {
                            return true;
                        }
                    }
                    TrackedContent::Block { blocks } => {
                        if contains_inline_wrapper(blocks, predicate) {
                            return true;
                        }
                    }
                    TrackedContent::PropertyChange { .. } => {}
                },
                SemanticInline::MceSelectedContent(content) => {
                    if contains_inline_wrapper(&content.blocks, predicate)
                        || contains_inline_wrapper_in_inlines(&content.inlines, predicate)
                    {
                        return true;
                    }
                }
                SemanticInline::BookmarkStart(_)
                | SemanticInline::BookmarkEnd(_)
                | SemanticInline::Text(_)
                | SemanticInline::Tab
                | SemanticInline::LineBreak { .. }
                | SemanticInline::FootnoteReference { .. }
                | SemanticInline::EndnoteReference { .. }
                | SemanticInline::CommentReference { .. }
                | SemanticInline::CommentRangeStart { .. }
                | SemanticInline::CommentRangeEnd { .. } => {}
            }
        }
        false
    }

    fn semantic_text(document: &SemanticDocument) -> String {
        let mut text = String::new();
        for block in &document.blocks {
            collect_block_text(block, &mut text);
        }
        text
    }

    fn semantic_and_story_text(document: &SemanticDocument) -> String {
        let mut text = semantic_text(document);
        if let Some(stories) = document.stories.as_ref() {
            for part in &stories.parts {
                for block in &part.blocks {
                    collect_block_text(block, &mut text);
                }
                for note in &part.notes {
                    for block in &note.blocks {
                        collect_block_text(block, &mut text);
                    }
                }
                for comment in &part.comments {
                    for block in &comment.blocks {
                        collect_block_text(block, &mut text);
                    }
                }
            }
        }
        text
    }

    fn collect_block_text(block: &SemanticBlock, text: &mut String) {
        match block {
            SemanticBlock::Paragraph(paragraph) => {
                for run in &paragraph.runs {
                    for inline in &run.inlines {
                        collect_inline_text(inline, text);
                    }
                }
            }
            SemanticBlock::Table(table) => {
                for row in &table.rows {
                    for cell in &row.cells {
                        for block in &cell.blocks {
                            collect_block_text(block, text);
                        }
                    }
                }
            }
            SemanticBlock::TrackedChange(change) => {
                if let TrackedContent::Inline { items } = &change.content {
                    for inline in items {
                        collect_inline_text(inline, text);
                    }
                }
            }
            SemanticBlock::MceSelectedContent(content) => {
                for block in &content.blocks {
                    collect_block_text(block, text);
                }
                for inline in &content.inlines {
                    collect_inline_text(inline, text);
                }
            }
        }
    }

    fn collect_inline_text(inline: &SemanticInline, text: &mut String) {
        match inline {
            SemanticInline::Text(value) => text.push_str(&value.value),
            SemanticInline::Hyperlink(hyperlink) => {
                for child in &hyperlink.children {
                    collect_inline_text(child, text);
                }
            }
            SemanticInline::Field(field) => {
                for child in &field.result.children {
                    collect_inline_text(child, text);
                }
            }
            SemanticInline::Drawing(_) | SemanticInline::EmbeddedVisualObject(_) => {}
            SemanticInline::TrackedChange { change } => {
                if let TrackedContent::Inline { items } = &change.content {
                    for inline in items {
                        collect_inline_text(inline, text);
                    }
                }
            }
            SemanticInline::MceSelectedContent(content) => {
                for block in &content.blocks {
                    collect_block_text(block, text);
                }
                for inline in &content.inlines {
                    collect_inline_text(inline, text);
                }
            }
            SemanticInline::BookmarkStart(_) | SemanticInline::BookmarkEnd(_) => {}
            SemanticInline::Tab
            | SemanticInline::LineBreak { .. }
            | SemanticInline::FootnoteReference { .. }
            | SemanticInline::EndnoteReference { .. }
            | SemanticInline::CommentReference { .. }
            | SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. } => {}
        }
    }

    fn block_text(block: &SemanticBlock) -> String {
        let mut text = String::new();
        collect_block_text(block, &mut text);
        text
    }

    fn inline_text(inlines: &[SemanticInline]) -> String {
        let mut text = String::new();
        for inline in inlines {
            collect_inline_text(inline, &mut text);
        }
        text
    }

    fn collect_mce_block_wrappers<'a>(
        blocks: &'a [SemanticBlock],
        wrappers: &mut Vec<&'a MceSelectedContent>,
    ) {
        for block in blocks {
            match block {
                SemanticBlock::MceSelectedContent(content) => {
                    wrappers.push(content);
                    collect_mce_block_wrappers(&content.blocks, wrappers);
                    collect_mce_inline_wrappers_from_inlines(&content.inlines, wrappers);
                }
                SemanticBlock::Paragraph(paragraph) => {
                    for run in &paragraph.runs {
                        collect_mce_inline_wrappers_from_inlines(&run.inlines, wrappers);
                    }
                }
                SemanticBlock::Table(table) => {
                    for row in &table.rows {
                        for cell in &row.cells {
                            collect_mce_block_wrappers(&cell.blocks, wrappers);
                        }
                    }
                }
                SemanticBlock::TrackedChange(change) => {
                    if let TrackedContent::Block { blocks } = &change.content {
                        collect_mce_block_wrappers(blocks, wrappers);
                    }
                }
            }
        }
    }

    fn collect_mce_inline_wrappers<'a>(
        blocks: &'a [SemanticBlock],
        wrappers: &mut Vec<&'a MceSelectedContent>,
    ) {
        for block in blocks {
            match block {
                SemanticBlock::Paragraph(paragraph) => {
                    for run in &paragraph.runs {
                        collect_mce_inline_wrappers_from_inlines(&run.inlines, wrappers);
                    }
                }
                SemanticBlock::Table(table) => {
                    for row in &table.rows {
                        for cell in &row.cells {
                            collect_mce_inline_wrappers(&cell.blocks, wrappers);
                        }
                    }
                }
                SemanticBlock::TrackedChange(change) => {
                    if let TrackedContent::Inline { items } = &change.content {
                        collect_mce_inline_wrappers_from_inlines(items, wrappers);
                    }
                }
                SemanticBlock::MceSelectedContent(content) => {
                    collect_mce_inline_wrappers(&content.blocks, wrappers);
                    collect_mce_inline_wrappers_from_inlines(&content.inlines, wrappers);
                }
            }
        }
    }

    fn collect_mce_inline_wrappers_from_inlines<'a>(
        inlines: &'a [SemanticInline],
        wrappers: &mut Vec<&'a MceSelectedContent>,
    ) {
        for inline in inlines {
            match inline {
                SemanticInline::MceSelectedContent(content) => {
                    wrappers.push(content);
                    collect_mce_inline_wrappers(&content.blocks, wrappers);
                    collect_mce_inline_wrappers_from_inlines(&content.inlines, wrappers);
                }
                SemanticInline::TrackedChange { change } => {
                    if let TrackedContent::Inline { items } = &change.content {
                        collect_mce_inline_wrappers_from_inlines(items, wrappers);
                    }
                }
                SemanticInline::Hyperlink(hyperlink) => {
                    collect_mce_inline_wrappers_from_inlines(&hyperlink.children, wrappers);
                }
                SemanticInline::Field(field) => {
                    collect_mce_inline_wrappers_from_inlines(&field.result.children, wrappers);
                }
                SemanticInline::Drawing(_) | SemanticInline::EmbeddedVisualObject(_) => {}
                SemanticInline::Text(_)
                | SemanticInline::BookmarkStart(_)
                | SemanticInline::BookmarkEnd(_)
                | SemanticInline::Tab
                | SemanticInline::LineBreak { .. }
                | SemanticInline::FootnoteReference { .. }
                | SemanticInline::EndnoteReference { .. }
                | SemanticInline::CommentReference { .. }
                | SemanticInline::CommentRangeStart { .. }
                | SemanticInline::CommentRangeEnd { .. } => {}
            }
        }
    }

    fn block_mce_wrappers(block: &SemanticBlock) -> Vec<&MceSelectedContent> {
        let mut wrappers = Vec::new();
        collect_mce_block_wrappers(std::slice::from_ref(block), &mut wrappers);
        wrappers
    }

    trait MceTestSourcePart {
        fn source_part_path(&self) -> &str;
    }

    impl MceTestSourcePart for MceSelectedContent {
        fn source_part_path(&self) -> &str {
            &self.projection.source_anchor.source_part_path
        }
    }

    fn add<W: Write + std::io::Seek>(
        zip: &mut ZipWriter<W>,
        options: FileOptions,
        path: &str,
        bytes: &[u8],
    ) {
        zip.start_file(path, options).unwrap();
        zip.write_all(bytes).unwrap();
    }

    fn cleanup_dir(path: &std::path::Path) {
        if path.exists() {
            fs::remove_dir_all(path).unwrap();
        }
    }
}
