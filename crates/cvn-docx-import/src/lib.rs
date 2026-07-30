//! DOCX import entry point for TUFF-CVN.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use base64::Engine;
use cvn_core::{
    AbstractNumberingProjection, CommentProjection, CommentRangeProjection, ContentTypeDefault,
    ContentTypeOverride, ContentTypesProjection, CvnDocument, DocumentId,
    HeaderFooterReferenceProjection, MceAlternateContentProjection, MceBranchKind,
    MceBranchProjection, MceCapabilities, MceCompatibilityAttributes, MceNamespaceRequirement,
    MceProjection, MceQualifiedName, MceResolutionDiagnostic, MceSelectedContent, MceSelection,
    NoteProjection, NumberFormatProjection, NumberingInstanceProjection, NumberingLevelProjection,
    NumberingReference, NumberingRegistryProjection, NumberingResolutionDiagnostic,
    OfficeSignatureInfoProjection, OpaqueEntry, OpcPackageProjection, OpcPart, OpcRelationship,
    OpcSignatureOriginProjection, OpcSignatureProjection, OpcSignatureRegistryProjection,
    ParagraphPropertiesProjection, PreservationMode, ResolvedStyleProjection,
    RsaKeyValueProjection, RunPropertiesProjection, SemanticBlock, SemanticDocument,
    SemanticInline, SemanticNodeId, SemanticParagraph, SemanticRun, SemanticTable,
    SemanticTableCell, SemanticTableRow, SemanticText, SignatureDiagnostic,
    SignatureKeyInfoProjection, SignatureReferenceProjection, SignatureReferenceVerification,
    SignatureTransformProjection, SignatureVerificationReport, SignatureVerificationStatus,
    SignedInfoProjection, SourceAnchor, SourceDescriptor, SourceFormat, StoryPartKind,
    StoryPartProjection, StoryReference, StoryReferenceKind, StoryRegistryProjection,
    StoryResolutionDiagnostic, StyleDefinitionProjection, StyleReference, StyleRegistryProjection,
    StyleResolutionDiagnostic, StyleType, TargetMode, TrackChangesProjection, TrackedChange,
    TrackedChangeId, TrackedChangeKind, TrackedChangeMetadata, TrackedContent,
    UnsupportedFeatureHandling, UnsupportedSemanticFeature, X509CertificateProjection,
    ZipEntryMetadata,
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
    resolve_semantic_references(&mut document.semantic, &document.opc.relationships);

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
                            SemanticInline::Text(_)
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
        SemanticInline::Text(_) | SemanticInline::Tab | SemanticInline::LineBreak { .. } => false,
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
    if target.starts_with('/') || target.starts_with('\\') || target.contains("..") {
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
        Ok((_, certificate)) => X509CertificateProjection {
            der_sha256,
            subject: Some(certificate.subject().to_string()),
            issuer: Some(certificate.issuer().to_string()),
            serial: Some(certificate.raw_serial_as_string()),
            not_before: certificate.validity().not_before.to_rfc2822().ok(),
            not_after: certificate.validity().not_after.to_rfc2822().ok(),
            public_key_algorithm: Some(certificate.public_key().algorithm.algorithm.to_string()),
            malformed: false,
        },
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
        malformed: true,
    }
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
    let (signature_value_status, key_fingerprint) = verify_signature_value(
        &xml_signature.signed_info.signature_method,
        &signed_info_bytes,
        &xml_signature.signature_value,
        &xml_signature.key_info,
        signature_part_path,
        &mut diagnostics,
    );
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
        key_fingerprint,
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
) -> (SignatureVerificationStatus, Option<String>) {
    if signed_info_bytes.is_empty() {
        return (SignatureVerificationStatus::Malformed, None);
    }
    if signature_digest_for_method(signature_method).is_none() {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_METHOD_UNSUPPORTED",
            signature_part_path,
            "SignatureMethod is unsupported",
        ));
        return (SignatureVerificationStatus::UnsupportedAlgorithm, None);
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
            return (SignatureVerificationStatus::Invalid, None);
        }
    };
    let Some((public_key, fingerprint)) =
        public_key_from_key_info(key_info, diagnostics, signature_part_path)
    else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_KEY_MISSING",
            signature_part_path,
            "no supported RSA public key is available",
        ));
        return (SignatureVerificationStatus::MissingKey, None);
    };
    let Ok(signature) = RsaPkcs1v15Signature::try_from(signature_bytes.as_slice()) else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_VALUE_MISMATCH",
            signature_part_path,
            "SignatureValue length is invalid for RSA",
        ));
        return (SignatureVerificationStatus::Invalid, Some(fingerprint));
    };
    let verified = match signature_method {
        RSA_SHA1 => VerifyingKey::<Sha1>::new(public_key).verify(signed_info_bytes, &signature),
        RSA_SHA256 => VerifyingKey::<Sha256>::new(public_key).verify(signed_info_bytes, &signature),
        RSA_SHA384 => VerifyingKey::<Sha384>::new(public_key).verify(signed_info_bytes, &signature),
        RSA_SHA512 => VerifyingKey::<Sha512>::new(public_key).verify(signed_info_bytes, &signature),
        _ => unreachable!("checked earlier"),
    };
    if verified.is_ok() {
        (SignatureVerificationStatus::Valid, Some(fingerprint))
    } else {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_VALUE_MISMATCH",
            signature_part_path,
            "SignatureValue does not verify against SignedInfo and KeyInfo",
        ));
        (SignatureVerificationStatus::Invalid, Some(fingerprint))
    }
}

fn public_key_from_key_info(
    key_info: &SignatureKeyInfoProjection,
    diagnostics: &mut Vec<SignatureDiagnostic>,
    signature_part_path: &str,
) -> Option<(RsaPublicKey, String)> {
    if let Some(key_value) = &key_info.key_value_rsa {
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
        let key = RsaPublicKey::new(
            BigUint::from_bytes_be(&modulus),
            BigUint::from_bytes_be(&exponent),
        )
        .ok()?;
        return Some((key, key_value.fingerprint.clone()));
    }
    for certificate in &key_info.x509_certificates {
        if certificate.malformed {
            continue;
        }
        let Ok(der) =
            base64::engine::general_purpose::STANDARD.decode(certificate.der_sha256.as_bytes())
        else {
            continue;
        };
        let _ = der;
    }
    if !key_info.x509_certificates.is_empty() {
        diagnostics.push(signature_diag(
            "CVN_SIGNATURE_KEY_MISSING",
            signature_part_path,
            "X.509 metadata was projected, but RSA public key extraction is unavailable without KeyValue",
        ));
    }
    None
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
    _reader: &Reader<Cursor<&[u8]>>,
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<BTreeMap<String, String>, quick_xml::Error> {
    let mut attrs = BTreeMap::new();
    for attr in event.attributes() {
        let attr = attr?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = String::from_utf8_lossy(attr.value.as_ref()).into_owned();
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
        let value = String::from_utf8_lossy(attr.value.as_ref()).into_owned();
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
    let mut text_preserve_stack: Vec<bool> = Vec::new();
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
                    if !run_stack.is_empty() {
                        if let Some(change) = active_change.as_mut() {
                            change
                                .inline_items
                                .push(SemanticInline::MceSelectedContent(content.clone()));
                        }
                        if let Some(run) = run_stack.last_mut() {
                            run.inlines
                                .push(SemanticInline::MceSelectedContent(content));
                        }
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
                        if let Some(change) = active_change.as_mut() {
                            change.inline_items.push(SemanticInline::Tab);
                        }
                        if let Some(run) = run_stack.last_mut() {
                            run.inlines.push(SemanticInline::Tab);
                        }
                    }
                    "footnoteReference" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            let note_id = attr_named(&attrs, "id")
                                .cloned()
                                .or_else(|| attrs.get("w:id").cloned())
                                .unwrap_or_default();
                            run.inlines.push(SemanticInline::FootnoteReference {
                                note_id,
                                resolved_part_path: None,
                            });
                        }
                    }
                    "endnoteReference" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            let note_id = attr_named(&attrs, "id")
                                .cloned()
                                .or_else(|| attrs.get("w:id").cloned())
                                .unwrap_or_default();
                            run.inlines.push(SemanticInline::EndnoteReference {
                                note_id,
                                resolved_part_path: None,
                            });
                        }
                    }
                    "commentRangeStart" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            let comment_id = attr_named(&attrs, "id")
                                .cloned()
                                .or_else(|| attrs.get("w:id").cloned())
                                .unwrap_or_default();
                            run.inlines
                                .push(SemanticInline::CommentRangeStart { comment_id });
                        }
                    }
                    "commentRangeEnd" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            let comment_id = attr_named(&attrs, "id")
                                .cloned()
                                .or_else(|| attrs.get("w:id").cloned())
                                .unwrap_or_default();
                            run.inlines
                                .push(SemanticInline::CommentRangeEnd { comment_id });
                        }
                    }
                    "commentReference" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            let comment_id = attr_named(&attrs, "id")
                                .cloned()
                                .or_else(|| attrs.get("w:id").cloned())
                                .unwrap_or_default();
                            run.inlines.push(SemanticInline::CommentReference {
                                comment_id,
                                resolved_part_path: None,
                            });
                        }
                    }
                    "br" | "cr" if name.is_wordprocessingml() => {
                        if let Some(change) = active_change.as_mut() {
                            change.inline_items.push(SemanticInline::LineBreak {
                                break_kind: name.local_name.clone(),
                            });
                        }
                        if let Some(run) = run_stack.last_mut() {
                            run.inlines.push(SemanticInline::LineBreak {
                                break_kind: name.local_name.clone(),
                            });
                        }
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
                    "t" if name.is_wordprocessingml() => push_text(
                        &mut run_stack,
                        "",
                        attrs
                            .get("xml:space")
                            .map(|value| value == "preserve")
                            .unwrap_or(false),
                    ),
                    "tab" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            run.inlines.push(SemanticInline::Tab);
                        }
                    }
                    "br" | "cr" if name.is_wordprocessingml() => {
                        if let Some(run) = run_stack.last_mut() {
                            run.inlines.push(SemanticInline::LineBreak {
                                break_kind: name.local_name.clone(),
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
                let preserve = text_preserve_stack.last().copied().unwrap_or(false);
                if let Some(change) = active_change.as_mut() {
                    change.inline_items.push(SemanticInline::Text(SemanticText {
                        value: value.clone(),
                        preserve_space: preserve,
                    }));
                }
                if active_change
                    .as_ref()
                    .map(|change| {
                        change.kind == TrackedChangeKind::Deletion
                            || change.kind == TrackedChangeKind::MoveFrom
                    })
                    .unwrap_or(false)
                {
                    continue;
                }
                push_text(&mut run_stack, &value, preserve);
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
                        tracked_changes.push(change.finish(
                            document_id,
                            &name.local_name,
                            &source_part_path.to_owned(),
                            &document_digest,
                            &mut id_set,
                        )?);
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
                if let Some(paragraph) = paragraph_stack.last_mut() {
                    let id = semantic_id(
                        document_id,
                        source_part_path,
                        "run",
                        None,
                        &run.anchor.xml_path,
                        document_digest,
                        id_set,
                    )?;
                    paragraph.runs.push(SemanticRun {
                        id,
                        source_identifier: None,
                        source_anchor: run.anchor,
                        properties: run.properties,
                        resolved_style: None,
                        inlines: run.inlines,
                    });
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
                    runs: paragraph.runs,
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

fn push_text(run_stack: &mut [RunBuilder], value: &str, preserve_space: bool) {
    if let Some(run) = run_stack.last_mut() {
        run.inlines.push(SemanticInline::Text(SemanticText {
            value: value.to_owned(),
            preserve_space,
        }));
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
    runs: Vec<SemanticRun>,
}

#[derive(Debug)]
struct RunBuilder {
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

fn resolve_semantic_references(semantic: &mut SemanticDocument, relationships: &[OpcRelationship]) {
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
            SemanticInline::CommentRangeStart { .. }
            | SemanticInline::CommentRangeEnd { .. }
            | SemanticInline::Text(_)
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
                    SemanticInline::Text(_)
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
            SemanticInline::Text(_) | SemanticInline::Tab | SemanticInline::LineBreak { .. } => {}
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
                            SemanticInline::Text(_)
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
                    SemanticInline::Text(_)
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
            SemanticInline::Text(_)
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
                && rel.target == "https://example.invalid/image?a=1&amp;b=2"));

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
}
