//! DOCX export entry point for TUFF-CVN.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use cvn_package::{object_bytes, read_package};
use thiserror::Error;
use zip::write::FileOptions;
use zip::ZipWriter;

/// DOCX export error.
#[derive(Debug, Error)]
pub enum DocxExportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("package error: {0}")]
    Package(#[from] cvn_package::PackageError),
    #[error("missing package object for part {part}: sha256:{digest}")]
    MissingObject { part: String, digest: String },
}

/// Returns whether DOCX export is implemented.
pub fn is_implemented() -> bool {
    true
}

/// Exports a CVN preservation package directory back to a DOCX ZIP.
pub fn export_package_to_docx(
    input_cvn: impl AsRef<Path>,
    output_docx: impl AsRef<Path>,
) -> Result<usize, DocxExportError> {
    let package = read_package(input_cvn)?;
    let file = File::create(output_docx)?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());

    let mut parts = package.document.opc.parts.clone();
    parts.sort_by(|left, right| left.original_path.cmp(&right.original_path));

    for part in &parts {
        let bytes = object_bytes(&package, &part.content_digest).ok_or_else(|| {
            DocxExportError::MissingObject {
                part: part.original_path.clone(),
                digest: part.content_digest.clone(),
            }
        })?;
        zip.start_file(&part.original_path, options)?;
        zip.write_all(bytes)?;
    }

    zip.finish()?;
    Ok(parts.len())
}

#[cfg(test)]
mod tests {
    use cvn_docx_import::import_docx_to_package;

    use super::*;

    #[test]
    fn docx_export_is_implemented() {
        assert!(is_implemented());
    }

    #[test]
    fn exports_preserved_raw_parts() {
        let temp = std::env::temp_dir();
        let input = temp.join(format!("tuff-cvn-export-input-{}.docx", std::process::id()));
        let package = temp.join(format!(
            "tuff-cvn-export-package-{}.cvn",
            std::process::id()
        ));
        let output = temp.join(format!(
            "tuff-cvn-export-output-{}.docx",
            std::process::id()
        ));
        write_test_docx(&input);

        import_docx_to_package(&input, &package).unwrap();
        let part_count = export_package_to_docx(&package, &output).unwrap();

        assert_eq!(part_count, 5);
        assert!(output.exists());
        assert_eq!(
            zip_part_bytes(&input, "word/document.xml"),
            zip_part_bytes(&output, "word/document.xml")
        );

        std::fs::remove_file(input).unwrap();
        std::fs::remove_file(output).unwrap();
        std::fs::remove_dir_all(package).unwrap();
    }

    fn write_test_docx(path: &Path) {
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());

        add(&mut zip, options, "[Content_Types].xml", br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#);
        add(&mut zip, options, "_rels/.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="officeDocument" Target="word/document.xml"/></Relationships>"#);
        add(
            &mut zip,
            options,
            "word/document.xml",
            br#"<w:document b="2" a="1">  <w:body>Hello</w:body></w:document>"#,
        );
        add(&mut zip, options, "word/_rels/document.xml.rels", br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdExt" Type="hyperlink" Target="https://example.invalid/image" TargetMode="External"/></Relationships>"#);
        add(&mut zip, options, "word/media/image1.bin", b"image-bytes");
        zip.finish().unwrap();
    }

    fn zip_part_bytes(path: &Path, part: &str) -> Vec<u8> {
        let file = File::open(path).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        let mut entry = zip.by_name(part).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes).unwrap();
        bytes
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
