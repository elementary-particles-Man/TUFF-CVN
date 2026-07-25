//! Package/container support for TUFF-CVN.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cvn_core::CvnDocument;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Default package extension for canonical documents.
pub const DEFAULT_PACKAGE_EXTENSION: &str = "cvn";

/// Metadata file name inside a CVN preservation package.
pub const MANIFEST_FILE: &str = "cvn.json";

/// Content-addressed object prefix inside a CVN preservation package.
pub const SHA256_OBJECT_PREFIX: &str = "objects/sha256";

/// CVN preservation package error.
#[derive(Debug, Error)]
pub enum PackageError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid lowercase SHA-256 digest: {0}")]
    InvalidDigest(String),
    #[error("object digest collision for sha256:{0}")]
    DigestCollision(String),
    #[error("invalid package object path: {0}")]
    InvalidObjectPath(String),
}

/// In-memory CVN preservation package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvnPackage {
    pub document: CvnDocument,
    pub objects: Vec<PackageObject>,
}

/// Content-addressed package object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageObject {
    pub digest: String,
    pub bytes: Vec<u8>,
}

/// Computes lowercase hex SHA-256 for raw bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Validates a lowercase hex SHA-256 digest.
pub fn validate_sha256_digest(digest: &str) -> Result<(), PackageError> {
    let valid = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());

    if valid {
        Ok(())
    } else {
        Err(PackageError::InvalidDigest(digest.to_owned()))
    }
}

/// Writes a package directory with `cvn.json` and `objects/sha256/<digest>`.
///
/// The package is built in a sibling temporary directory and then renamed into
/// place. Existing output directories are removed only after the temporary
/// package was successfully written.
pub fn write_package(path: impl AsRef<Path>, package: &CvnPackage) -> Result<(), PackageError> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("package.cvn");
    let tmp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    if tmp_path.exists() {
        fs::remove_dir_all(&tmp_path)?;
    }
    fs::create_dir_all(tmp_path.join(SHA256_OBJECT_PREFIX))?;

    let manifest_bytes = serde_json::to_vec_pretty(&package.document)?;
    fs::write(tmp_path.join(MANIFEST_FILE), manifest_bytes)?;

    for object in &package.objects {
        validate_sha256_digest(&object.digest)?;
        let actual = sha256_hex(&object.bytes);
        if actual != object.digest {
            return Err(PackageError::DigestCollision(object.digest.clone()));
        }

        let object_path = object_path(&tmp_path, &object.digest)?;
        if object_path.exists() {
            let existing = fs::read(&object_path)?;
            if existing != object.bytes {
                return Err(PackageError::DigestCollision(object.digest.clone()));
            }
            continue;
        }
        fs::write(object_path, &object.bytes)?;
    }

    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Reads a CVN preservation package directory.
pub fn read_package(path: impl AsRef<Path>) -> Result<CvnPackage, PackageError> {
    let path = path.as_ref();
    let manifest = fs::read(path.join(MANIFEST_FILE))?;
    let document = serde_json::from_slice(&manifest)?;

    let object_root = path.join(SHA256_OBJECT_PREFIX);
    let mut objects = Vec::new();
    if object_root.exists() {
        for entry in fs::read_dir(object_root)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                return Err(PackageError::InvalidObjectPath(
                    entry.path().display().to_string(),
                ));
            }
            let digest = entry.file_name().to_string_lossy().into_owned();
            validate_sha256_digest(&digest)?;
            let bytes = fs::read(entry.path())?;
            let actual = sha256_hex(&bytes);
            if actual != digest {
                return Err(PackageError::DigestCollision(digest));
            }
            objects.push(PackageObject { digest, bytes });
        }
    }
    objects.sort_by(|left, right| left.digest.cmp(&right.digest));

    Ok(CvnPackage { document, objects })
}

/// Returns object bytes by digest from a package.
pub fn object_bytes<'a>(package: &'a CvnPackage, digest: &str) -> Option<&'a [u8]> {
    package
        .objects
        .iter()
        .find(|object| object.digest == digest)
        .map(|object| object.bytes.as_slice())
}

fn object_path(root: &Path, digest: &str) -> Result<PathBuf, PackageError> {
    validate_sha256_digest(digest)?;
    let path = root.join(SHA256_OBJECT_PREFIX).join(digest);
    if !path.starts_with(root) {
        return Err(PackageError::InvalidObjectPath(digest.to_owned()));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cvn_core::DocumentId;

    use super::*;

    #[test]
    fn package_extension_is_defined() {
        assert_eq!(DEFAULT_PACKAGE_EXTENSION, "cvn");
    }

    #[test]
    fn write_package_deduplicates_identical_objects() {
        let temp =
            std::env::temp_dir().join(format!("tuff-cvn-package-test-{}", std::process::id()));
        if temp.exists() {
            fs::remove_dir_all(&temp).unwrap();
        }

        let bytes = b"same".to_vec();
        let digest = sha256_hex(&bytes);
        let package = CvnPackage {
            document: CvnDocument::minimal(DocumentId::new("doc-1").unwrap()),
            objects: vec![
                PackageObject {
                    digest: digest.clone(),
                    bytes: bytes.clone(),
                },
                PackageObject {
                    digest: digest.clone(),
                    bytes,
                },
            ],
        };

        write_package(&temp, &package).unwrap();
        let entries = fs::read_dir(temp.join(SHA256_OBJECT_PREFIX))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries
                .into_iter()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([digest])
        );

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn invalid_digest_is_rejected() {
        assert!(validate_sha256_digest("../bad").is_err());
        assert!(validate_sha256_digest(&"A".repeat(64)).is_err());
    }
}
