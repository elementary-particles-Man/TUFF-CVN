//! DOCX import entry point for TUFF-CVN.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use cvn_core::{
    ContentTypeDefault, ContentTypeOverride, ContentTypesProjection, CvnDocument, DocumentId,
    OpaqueEntry, OpcPackageProjection, OpcPart, OpcRelationship, ParagraphPropertiesProjection,
    PreservationMode, RunPropertiesProjection, SemanticBlock, SemanticDocument, SemanticInline,
    SemanticNodeId, SemanticParagraph, SemanticRun, SemanticTable, SemanticTableCell,
    SemanticTableRow, SemanticText, SourceAnchor, SourceDescriptor, SourceFormat, TargetMode,
    UnsupportedFeatureHandling, UnsupportedSemanticFeature, ZipEntryMetadata,
};
use cvn_package::{sha256_hex, write_package, CvnPackage, PackageObject};
use quick_xml::events::Event;
use quick_xml::Reader;
use sha2::{Digest, Sha256};
use thiserror::Error;
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
    if let Some(bytes) = object_bytes_for_part(&raw_parts, &objects_by_digest, "word/document.xml")
    {
        document.semantic = parse_semantic_document(&document.document_id, bytes)?;
    }

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

fn object_bytes_for_part<'a>(
    parts: &[RawPart],
    objects: &'a BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Option<&'a [u8]> {
    let digest = &parts.iter().find(|part| part.path == path)?.digest;
    objects.get(digest).map(Vec::as_slice)
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

fn parse_semantic_document(
    document_id: &DocumentId,
    bytes: &[u8],
) -> Result<SemanticDocument, DocxImportError> {
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
    let mut text_preserve_stack: Vec<bool> = Vec::new();
    let mut namespace_stack: Vec<BTreeMap<String, String>> = Vec::new();
    let mut id_set = BTreeSet::new();

    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(event) => {
                namespace_stack.push(namespace_declarations(&event)?);
                let name = qname(event.name().as_ref(), &namespace_stack);
                let attrs = attributes(&reader, &event)?;
                let path = next_path(&mut path_stack, &mut child_counts, &name.local_name);
                let anchor = SourceAnchor {
                    source_part_path: "word/document.xml".to_owned(),
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
                            runs: Vec::new(),
                        });
                    }
                    "pStyle" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            paragraph.properties.style_id = attr_val(&attrs);
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
                    }
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
                    source_part_path: "word/document.xml".to_owned(),
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
                            runs: Vec::new(),
                        });
                    }
                    "pStyle" if name.is_wordprocessingml() => {
                        if let Some(paragraph) = paragraph_stack.last_mut() {
                            paragraph.properties.style_id = attr_val(&attrs);
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
                push_text(
                    &mut run_stack,
                    &value,
                    text_preserve_stack.last().copied().unwrap_or(false),
                );
            }
            Event::DocType(_) => {
                return Err(DocxImportError::DoctypeNotAllowed {
                    path: "word/document.xml".to_owned(),
                });
            }
            Event::End(event) => {
                let name = qname(event.name().as_ref(), &namespace_stack);
                if name.local_name == "t" && name.is_wordprocessingml() {
                    text_preserve_stack.pop();
                }
                end_element(
                    document_id,
                    &document_digest,
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
    Ok(SemanticDocument {
        source_part: "word/document.xml".to_owned(),
        blocks,
        unsupported_features,
    })
}

#[allow(clippy::too_many_arguments)]
fn end_element(
    document_id: &DocumentId,
    document_digest: &str,
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
                        inlines: run.inlines,
                    });
                }
            }
        }
        "p" => {
            if let Some(paragraph) = paragraph_stack.pop() {
                let id = semantic_id(
                    document_id,
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
                    runs: paragraph.runs,
                });
                push_block(block, table_stack, blocks);
            }
        }
        "tbl" => {
            if let Some(table) = table_stack.pop() {
                let id = semantic_id(
                    document_id,
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
    kind: &str,
    source_identifier: Option<&str>,
    xml_path: &str,
    document_digest: &str,
    id_set: &mut BTreeSet<String>,
) -> Result<SemanticNodeId, DocxImportError> {
    let material = match source_identifier {
        Some(source_identifier) => format!(
            "{}|word/document.xml|{kind}|source:{source_identifier}",
            document_id.as_str()
        ),
        None => format!(
            "{}|word/document.xml|{kind}|path:{xml_path}|doc-sha256:{document_digest}",
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
        "document" | "body" | "pPr" | "rPr" | "tblPr" | "tblGrid" | "gridCol" | "tcPr" | "sectPr"
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

#[cfg(test)]
mod tests {
    use std::io::Write;

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

    fn collect_semantic_ids(document: &SemanticDocument) -> Vec<String> {
        let mut ids = Vec::new();
        for block in &document.blocks {
            collect_block_ids(block, &mut ids);
        }
        ids
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
