//! DOCX import entry point for TUFF-CVN.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use cvn_core::{
    ContentTypeDefault, ContentTypeOverride, ContentTypesProjection, CvnDocument, DocumentId,
    OpaqueEntry, OpcPackageProjection, OpcPart, OpcRelationship, PreservationMode,
    SourceDescriptor, SourceFormat, TargetMode, ZipEntryMetadata,
};
use cvn_package::{sha256_hex, write_package, CvnPackage, PackageObject};
use quick_xml::events::Event;
use quick_xml::Reader;
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
        attrs.insert(key, value);
    }
    Ok(attrs)
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
