//! Package/container support for TUFF-CVN.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use cvn_canonical::{to_canonical_bytes, CanonicalError};
use cvn_core::{
    CanonicalPayloadView, ContentTypesProjection, CvnDocument, CvnJson, DigestAlgorithm,
    IntegrityManifest, IntegrityNode, IntegrityNodeKind, IntegrityRoot, OpcRelationship,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Default package extension for canonical documents.
pub const DEFAULT_PACKAGE_EXTENSION: &str = "cvn";

/// Metadata file name inside a CVN preservation package.
pub const MANIFEST_FILE: &str = "cvn.json";

/// Content-addressed object prefix inside a CVN preservation package.
pub const SHA256_OBJECT_PREFIX: &str = "objects/sha256";
pub const INTEGRITY_VERSION: &str = "cvn-integrity-v11-embedded-visual-objects";

const DOMAIN_PAYLOAD: &[u8] = b"TUFF-CVN\0payload\0";
const DOMAIN_PART_MAP: &[u8] = b"TUFF-CVN\0part-map\0";
const DOMAIN_RELATIONS: &[u8] = b"TUFF-CVN\0relations\0";
const DOMAIN_CONTENT_TYPES: &[u8] = b"TUFF-CVN\0content-types\0";
const DOMAIN_SEMANTIC: &[u8] = b"TUFF-CVN\0semantic\0";
const DOMAIN_STYLES: &[u8] = b"TUFF-CVN\0styles\0";
const DOMAIN_NUMBERING: &[u8] = b"TUFF-CVN\0numbering\0";
const DOMAIN_STORIES: &[u8] = b"TUFF-CVN\0stories\0";
const DOMAIN_TRACK_CHANGES: &[u8] = b"TUFF-CVN\0track-changes\0";
const DOMAIN_MCE: &[u8] = b"TUFF-CVN\0mce\0";
const DOMAIN_OPC_SIGNATURES: &[u8] = b"TUFF-CVN\0opc-signatures\0";
const DOMAIN_DOCUMENT_REFERENCES: &[u8] = b"TUFF-CVN\0document-references\0";
const DOMAIN_DRAWING_IMAGES: &[u8] = b"TUFF-CVN\0drawing-images\0";
const DOMAIN_EMBEDDED_VISUAL_OBJECTS: &[u8] = b"TUFF-CVN\0embedded-visual-objects\0";
const DOMAIN_OBJECTS: &[u8] = b"TUFF-CVN\0objects\0";
const DOMAIN_ROOT: &[u8] = b"TUFF-CVN\0root\0";

/// CVN preservation package error.
#[derive(Debug, Error)]
pub enum PackageError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonicalization error: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("invalid lowercase SHA-256 digest: {0}")]
    InvalidDigest(String),
    #[error("object digest collision for sha256:{0}")]
    DigestCollision(String),
    #[error("invalid package object path: {0}")]
    InvalidObjectPath(String),
    #[error("missing integrity manifest")]
    MissingIntegrity,
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

/// CanonicalPackageIntegrity verification report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPackageIntegrityReport {
    pub passed: bool,
    pub root_expected: Option<String>,
    pub root_actual: Option<String>,
    pub node_results: Vec<IntegrityNodeResult>,
    pub object_failures: Vec<IntegrityFailure>,
    pub canonicalization_failures: Vec<IntegrityFailure>,
    pub package_failures: Vec<IntegrityFailure>,
}

/// Per-node integrity result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityNodeResult {
    pub kind: IntegrityNodeKind,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub passed: bool,
}

/// Integrity failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityFailure {
    pub code: String,
    pub path: String,
    pub message: String,
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

    let mut objects = package.objects.clone();
    objects.sort_by(|left, right| left.digest.cmp(&right.digest));
    for object in &objects {
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
        let mut file = File::create(object_path)?;
        file.write_all(&object.bytes)?;
        file.sync_all()?;
    }

    let integrity = build_integrity_manifest(&package.document, &objects)?;
    let cvn_json = CvnJson {
        payload: package.document.clone(),
        integrity,
    };
    let manifest_bytes = to_canonical_bytes(&cvn_json)?;
    let manifest_path = tmp_path.join(MANIFEST_FILE);
    let mut manifest_file = File::create(manifest_path)?;
    manifest_file.write_all(&manifest_bytes)?;
    manifest_file.sync_all()?;

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
    let cvn_json: CvnJson = serde_json::from_slice(&manifest)?;
    let objects = read_valid_objects(path)?;
    Ok(CvnPackage {
        document: cvn_json.payload,
        objects,
    })
}

/// Reads raw `cvn.json` bytes.
pub fn read_cvn_json_bytes(path: impl AsRef<Path>) -> Result<Vec<u8>, PackageError> {
    Ok(fs::read(path.as_ref().join(MANIFEST_FILE))?)
}

/// Returns object bytes by digest from a package.
pub fn object_bytes<'a>(package: &'a CvnPackage, digest: &str) -> Option<&'a [u8]> {
    package
        .objects
        .iter()
        .find(|object| object.digest == digest)
        .map(|object| object.bytes.as_slice())
}

/// Builds an integrity manifest for a payload and object set.
pub fn build_integrity_manifest(
    document: &CvnDocument,
    objects: &[PackageObject],
) -> Result<IntegrityManifest, PackageError> {
    let nodes = calculate_integrity_nodes(document, objects)?;
    let root_digest = calculate_root_digest(&nodes)?;
    Ok(IntegrityManifest {
        version: INTEGRITY_VERSION.to_owned(),
        algorithm: DigestAlgorithm::Sha256,
        root: IntegrityRoot {
            digest: root_digest,
        },
        nodes,
    })
}

/// Verifies CanonicalPackageIntegrity for a package directory.
pub fn verify_package_integrity(
    path: impl AsRef<Path>,
) -> Result<CanonicalPackageIntegrityReport, PackageError> {
    let path = path.as_ref();
    let mut object_failures = Vec::new();
    let mut canonicalization_failures = Vec::new();
    let mut package_failures = Vec::new();

    let manifest = fs::read(path.join(MANIFEST_FILE))?;
    let cvn_json: CvnJson = serde_json::from_slice(&manifest)?;
    if cvn_json.integrity.version != INTEGRITY_VERSION {
        package_failures.push(failure(
            "CVN_UNSUPPORTED_INTEGRITY_VERSION",
            "$.integrity.version",
            "integrity manifest version is not supported by this verifier",
        ));
    }
    let objects = scan_objects(path, &mut object_failures, &mut package_failures)?;

    let actual_nodes = match calculate_integrity_nodes(&cvn_json.payload, &objects) {
        Ok(nodes) => nodes,
        Err(error) => {
            canonicalization_failures.push(failure(
                "CVN_CANONICALIZATION_FAILED",
                "$",
                &error.to_string(),
            ));
            Vec::new()
        }
    };

    let root_actual = if actual_nodes.is_empty() {
        None
    } else {
        match calculate_root_digest(&actual_nodes) {
            Ok(digest) => Some(digest),
            Err(error) => {
                canonicalization_failures.push(failure(
                    "CVN_CANONICALIZATION_FAILED",
                    "$.integrity.root",
                    &error.to_string(),
                ));
                None
            }
        }
    };
    let root_expected = Some(cvn_json.integrity.root.digest.clone());

    let expected_by_kind = cvn_json
        .integrity
        .nodes
        .iter()
        .map(|node| (node.kind, node.digest.clone()))
        .collect::<BTreeMap<_, _>>();
    let actual_by_kind = actual_nodes
        .iter()
        .map(|node| (node.kind, node.digest.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut node_results = Vec::new();
    for kind in integrity_node_order() {
        let expected = expected_by_kind.get(&kind).cloned();
        let actual = actual_by_kind.get(&kind).cloned();
        let passed = expected.is_some() && expected == actual;
        if !passed {
            package_failures.push(failure(
                mismatch_code(kind),
                &format!("$.integrity.nodes.{}", kind.as_str()),
                "integrity node digest mismatch",
            ));
        }
        node_results.push(IntegrityNodeResult {
            kind,
            expected,
            actual,
            passed,
        });
    }

    if root_expected != root_actual {
        package_failures.push(failure(
            "CVN_ROOT_DIGEST_MISMATCH",
            "$.integrity.root.digest",
            "root digest mismatch",
        ));
    }

    let expected_objects = expected_object_inventory(&cvn_json.payload);
    let actual_objects = objects
        .iter()
        .map(|object| (object.digest.clone(), object.bytes.len() as u64))
        .collect::<BTreeMap<_, _>>();
    for (digest, expected_length) in &expected_objects {
        match actual_objects.get(digest) {
            None => object_failures.push(failure(
                "CVN_OBJECT_MISSING",
                &format!("objects/sha256/{digest}"),
                "expected object is missing",
            )),
            Some(actual_length) if actual_length != expected_length => {
                object_failures.push(failure(
                    "CVN_OBJECT_LENGTH_MISMATCH",
                    &format!("objects/sha256/{digest}"),
                    "object length mismatch",
                ))
            }
            Some(_) => {}
        }
    }
    for digest in actual_objects.keys() {
        if !expected_objects.contains_key(digest) {
            object_failures.push(failure(
                "CVN_OBJECT_UNEXPECTED",
                &format!("objects/sha256/{digest}"),
                "unexpected object is present",
            ));
        }
    }

    let passed = root_expected == root_actual
        && node_results.iter().all(|result| result.passed)
        && object_failures.is_empty()
        && canonicalization_failures.is_empty()
        && package_failures
            .iter()
            .all(|failure| failure.code != "CVN_ROOT_DIGEST_MISMATCH");

    Ok(CanonicalPackageIntegrityReport {
        passed,
        root_expected,
        root_actual,
        node_results,
        object_failures,
        canonicalization_failures,
        package_failures,
    })
}

fn calculate_integrity_nodes(
    document: &CvnDocument,
    objects: &[PackageObject],
) -> Result<Vec<IntegrityNode>, PackageError> {
    let projections = [
        (
            IntegrityNodeKind::CanonicalPayload,
            DOMAIN_PAYLOAD,
            to_canonical_bytes(&CanonicalPayloadView { payload: document })?,
        ),
        (
            IntegrityNodeKind::PartMap,
            DOMAIN_PART_MAP,
            to_canonical_bytes(&part_map_projection(document))?,
        ),
        (
            IntegrityNodeKind::Relations,
            DOMAIN_RELATIONS,
            to_canonical_bytes(&relations_projection(document))?,
        ),
        (
            IntegrityNodeKind::ContentTypes,
            DOMAIN_CONTENT_TYPES,
            to_canonical_bytes(&content_types_projection(document))?,
        ),
        (
            IntegrityNodeKind::SemanticProjection,
            DOMAIN_SEMANTIC,
            to_canonical_bytes(&semantic_projection(document))?,
        ),
        (
            IntegrityNodeKind::StyleProjection,
            DOMAIN_STYLES,
            to_canonical_bytes(&document.semantic.styles)?,
        ),
        (
            IntegrityNodeKind::NumberingProjection,
            DOMAIN_NUMBERING,
            to_canonical_bytes(&document.semantic.numbering)?,
        ),
        (
            IntegrityNodeKind::StoryProjection,
            DOMAIN_STORIES,
            to_canonical_bytes(&document.semantic.stories)?,
        ),
        (
            IntegrityNodeKind::TrackChangesProjection,
            DOMAIN_TRACK_CHANGES,
            to_canonical_bytes(&document.track_changes)?,
        ),
        (
            IntegrityNodeKind::MceProjection,
            DOMAIN_MCE,
            to_canonical_bytes(&document.mce)?,
        ),
        (
            IntegrityNodeKind::OpcSignatureProjection,
            DOMAIN_OPC_SIGNATURES,
            to_canonical_bytes(&document.signatures)?,
        ),
        (
            IntegrityNodeKind::DocumentReferencesProjection,
            DOMAIN_DOCUMENT_REFERENCES,
            to_canonical_bytes(&document.semantic.references)?,
        ),
        (
            IntegrityNodeKind::DrawingImageProjection,
            DOMAIN_DRAWING_IMAGES,
            to_canonical_bytes(&document.semantic.drawings)?,
        ),
        (
            IntegrityNodeKind::EmbeddedVisualObjectsProjection,
            DOMAIN_EMBEDDED_VISUAL_OBJECTS,
            to_canonical_bytes(&document.semantic.embedded_visual_objects)?,
        ),
        (
            IntegrityNodeKind::Objects,
            DOMAIN_OBJECTS,
            to_canonical_bytes(&object_inventory_projection(objects))?,
        ),
    ];

    Ok(projections
        .into_iter()
        .map(|(kind, domain, bytes)| IntegrityNode {
            kind,
            digest: domain_hash(domain, &bytes),
        })
        .collect())
}

fn calculate_root_digest(nodes: &[IntegrityNode]) -> Result<String, PackageError> {
    let by_kind = nodes
        .iter()
        .map(|node| (node.kind, node.digest.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut input = Vec::new();
    for kind in integrity_node_order() {
        let digest = by_kind.get(&kind).ok_or(PackageError::MissingIntegrity)?;
        validate_sha256_digest(digest)?;
        input.extend_from_slice(kind.as_str().as_bytes());
        input.push(0);
        let digest_bytes =
            hex::decode(digest).map_err(|_| PackageError::InvalidDigest((*digest).to_owned()))?;
        input.extend_from_slice(&digest_bytes);
    }
    Ok(domain_hash(DOMAIN_ROOT, &input))
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn integrity_node_order() -> [IntegrityNodeKind; 15] {
    [
        IntegrityNodeKind::CanonicalPayload,
        IntegrityNodeKind::PartMap,
        IntegrityNodeKind::Relations,
        IntegrityNodeKind::ContentTypes,
        IntegrityNodeKind::SemanticProjection,
        IntegrityNodeKind::StyleProjection,
        IntegrityNodeKind::NumberingProjection,
        IntegrityNodeKind::StoryProjection,
        IntegrityNodeKind::TrackChangesProjection,
        IntegrityNodeKind::MceProjection,
        IntegrityNodeKind::OpcSignatureProjection,
        IntegrityNodeKind::DocumentReferencesProjection,
        IntegrityNodeKind::DrawingImageProjection,
        IntegrityNodeKind::EmbeddedVisualObjectsProjection,
        IntegrityNodeKind::Objects,
    ]
}

fn mismatch_code(kind: IntegrityNodeKind) -> &'static str {
    match kind {
        IntegrityNodeKind::CanonicalPayload => "CVN_PAYLOAD_DIGEST_MISMATCH",
        IntegrityNodeKind::PartMap => "CVN_PART_MAP_DIGEST_MISMATCH",
        IntegrityNodeKind::Relations => "CVN_RELATIONS_DIGEST_MISMATCH",
        IntegrityNodeKind::ContentTypes => "CVN_CONTENT_TYPES_DIGEST_MISMATCH",
        IntegrityNodeKind::SemanticProjection => "CVN_SEMANTIC_PROJECTION_DIGEST_MISMATCH",
        IntegrityNodeKind::StyleProjection => "CVN_STYLE_PROJECTION_DIGEST_MISMATCH",
        IntegrityNodeKind::NumberingProjection => "CVN_NUMBERING_PROJECTION_DIGEST_MISMATCH",
        IntegrityNodeKind::StoryProjection => "CVN_STORY_PROJECTION_DIGEST_MISMATCH",
        IntegrityNodeKind::TrackChangesProjection => "CVN_TRACK_CHANGES_PROJECTION_DIGEST_MISMATCH",
        IntegrityNodeKind::MceProjection => "CVN_MCE_PROJECTION_DIGEST_MISMATCH",
        IntegrityNodeKind::OpcSignatureProjection => "CVN_SIGNATURE_PROJECTION_DIGEST_MISMATCH",
        IntegrityNodeKind::DocumentReferencesProjection => {
            "CVN_DOCUMENT_REFERENCES_PROJECTION_DIGEST_MISMATCH"
        }
        IntegrityNodeKind::DrawingImageProjection => "CVN_DRAWING_IMAGE_PROJECTION_DIGEST_MISMATCH",
        IntegrityNodeKind::EmbeddedVisualObjectsProjection => {
            "CVN_EMBEDDED_VISUAL_OBJECTS_PROJECTION_DIGEST_MISMATCH"
        }
        IntegrityNodeKind::Objects => "CVN_OBJECT_INVENTORY_DIGEST_MISMATCH",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PartMapRecord {
    original_path: String,
    content_type: Option<String>,
    original_size: u64,
    content_digest: String,
}

fn part_map_projection(document: &CvnDocument) -> Vec<PartMapRecord> {
    let mut parts = document
        .opc
        .parts
        .iter()
        .map(|part| PartMapRecord {
            original_path: part.original_path.clone(),
            content_type: part.content_type.clone(),
            original_size: part.original_size,
            content_digest: part.content_digest.clone(),
        })
        .collect::<Vec<_>>();
    parts.sort_by(|left, right| left.original_path.cmp(&right.original_path));
    parts
}

fn relations_projection(document: &CvnDocument) -> Vec<OpcRelationship> {
    let mut relations = document.opc.relationships.clone();
    relations.sort_by(|left, right| {
        left.source_part
            .cmp(&right.source_part)
            .then(left.relationship_id.cmp(&right.relationship_id))
    });
    relations
}

fn content_types_projection(document: &CvnDocument) -> ContentTypesProjection {
    let mut projection = document.opc.content_types.clone();
    projection
        .defaults
        .sort_by(|left, right| left.extension.cmp(&right.extension));
    projection
        .overrides
        .sort_by(|left, right| left.part_name.cmp(&right.part_name));
    projection
}

fn semantic_projection(document: &CvnDocument) -> cvn_core::SemanticDocument {
    let mut semantic = document.semantic.clone();
    semantic.styles = None;
    semantic.numbering = None;
    semantic
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ObjectInventoryRecord {
    digest: String,
    length: u64,
}

fn object_inventory_projection(objects: &[PackageObject]) -> Vec<ObjectInventoryRecord> {
    let mut inventory = objects
        .iter()
        .map(|object| ObjectInventoryRecord {
            digest: object.digest.clone(),
            length: object.bytes.len() as u64,
        })
        .collect::<Vec<_>>();
    inventory.sort_by(|left, right| left.digest.cmp(&right.digest));
    inventory.dedup_by(|left, right| left.digest == right.digest && left.length == right.length);
    inventory
}

fn expected_object_inventory(document: &CvnDocument) -> BTreeMap<String, u64> {
    let lengths_by_digest = document
        .opaque
        .iter()
        .map(|entry| (entry.content_digest.clone(), entry.length))
        .collect::<BTreeMap<_, _>>();
    document
        .opc
        .parts
        .iter()
        .map(|part| {
            (
                part.content_digest.clone(),
                lengths_by_digest
                    .get(&part.content_digest)
                    .copied()
                    .unwrap_or(part.original_size),
            )
        })
        .collect()
}

fn read_valid_objects(path: &Path) -> Result<Vec<PackageObject>, PackageError> {
    let mut failures = Vec::new();
    let mut package_failures = Vec::new();
    let objects = scan_objects(path, &mut failures, &mut package_failures)?;
    if let Some(failure) = failures.into_iter().chain(package_failures).next() {
        return Err(PackageError::InvalidObjectPath(failure.message));
    }
    Ok(objects)
}

fn scan_objects(
    path: &Path,
    object_failures: &mut Vec<IntegrityFailure>,
    package_failures: &mut Vec<IntegrityFailure>,
) -> Result<Vec<PackageObject>, PackageError> {
    let object_root = path.join(SHA256_OBJECT_PREFIX);
    let mut objects = Vec::new();
    if !object_root.exists() {
        return Ok(objects);
    }

    for entry in fs::read_dir(object_root)? {
        let entry = entry?;
        let entry_path = entry.path();
        let file_type = entry.file_type()?;
        let digest = entry.file_name().to_string_lossy().into_owned();
        if !file_type.is_file() {
            package_failures.push(failure(
                "CVN_OBJECT_NAME_INVALID",
                &entry_path.display().to_string(),
                "object entry is not a regular file",
            ));
            continue;
        }
        if validate_sha256_digest(&digest).is_err() {
            object_failures.push(failure(
                "CVN_OBJECT_NAME_INVALID",
                &entry_path.display().to_string(),
                "object filename is not a lowercase SHA-256 digest",
            ));
            continue;
        }
        let bytes = fs::read(&entry_path)?;
        let actual = sha256_hex(&bytes);
        if actual != digest {
            object_failures.push(failure(
                "CVN_OBJECT_DIGEST_MISMATCH",
                &format!("objects/sha256/{digest}"),
                "object filename digest does not match object bytes",
            ));
            objects.push(PackageObject {
                digest: actual,
                bytes,
            });
            continue;
        }
        objects.push(PackageObject { digest, bytes });
    }
    objects.sort_by(|left, right| left.digest.cmp(&right.digest));
    Ok(objects)
}

fn object_path(root: &Path, digest: &str) -> Result<PathBuf, PackageError> {
    validate_sha256_digest(digest)?;
    let path = root.join(SHA256_OBJECT_PREFIX).join(digest);
    if !path.starts_with(root) {
        return Err(PackageError::InvalidObjectPath(digest.to_owned()));
    }
    Ok(path)
}

fn failure(code: &str, path: &str, message: &str) -> IntegrityFailure {
    IntegrityFailure {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use cvn_core::{
        ContentTypesProjection, DocumentId, MceCapabilities, MceProjection, OpaqueEntry,
        OpcPackageProjection, OpcPart, OpcRelationship, OpcSignatureRegistryProjection,
        PreservationMode, TargetMode, ZipEntryMetadata,
    };

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

    #[test]
    fn same_package_writes_identical_cvn_json_bytes_and_root() {
        let temp_a = temp_path("deterministic-a");
        let temp_b = temp_path("deterministic-b");
        cleanup(&temp_a);
        cleanup(&temp_b);
        let package = package_with_one_object();

        write_package(&temp_a, &package).unwrap();
        write_package(&temp_b, &package).unwrap();

        let bytes_a = fs::read(temp_a.join(MANIFEST_FILE)).unwrap();
        let bytes_b = fs::read(temp_b.join(MANIFEST_FILE)).unwrap();
        let report_a = verify_package_integrity(&temp_a).unwrap();
        let report_b = verify_package_integrity(&temp_b).unwrap();

        assert_eq!(bytes_a, bytes_b);
        assert_eq!(report_a.root_actual, report_b.root_actual);
        assert!(report_a.passed);
        assert!(report_b.passed);

        cleanup(&temp_a);
        cleanup(&temp_b);
    }

    #[test]
    fn payload_change_is_detected() {
        let temp = write_integrity_fixture("payload-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["document_id"] = serde_json::Value::String("doc-2".to_owned());
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(&report, "CVN_PAYLOAD_DIGEST_MISMATCH"));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn relation_change_is_detected() {
        let temp = write_integrity_fixture("relation-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["opc"]["relationships"][0]["target"] =
            serde_json::Value::String("changed.xml".to_owned());
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_RELATIONS_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn part_map_change_is_detected() {
        let temp = write_integrity_fixture("part-map-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["opc"]["parts"][0]["content_digest"] =
            serde_json::Value::String("b".repeat(64));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(&report, "CVN_PART_MAP_DIGEST_MISMATCH"));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn semantic_projection_change_is_detected() {
        let temp = write_integrity_fixture("semantic-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["semantic"]["source_part"] =
            serde_json::Value::String("changed/document.xml".to_owned());
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_SEMANTIC_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn style_projection_change_is_detected() {
        let temp = write_integrity_fixture("style-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["semantic"]["styles"] = serde_json::json!({
            "source_part": "word/styles.xml",
            "definitions": [],
            "diagnostics": [],
            "unsupported_features": []
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_STYLE_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn numbering_projection_change_is_detected() {
        let temp = write_integrity_fixture("numbering-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["semantic"]["numbering"] = serde_json::json!({
            "source_part": "word/numbering.xml",
            "abstract_numbers": [],
            "instances": [],
            "diagnostics": [],
            "unsupported_features": []
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_NUMBERING_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn story_projection_change_is_detected() {
        let temp = write_integrity_fixture("story-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["semantic"]["stories"] = serde_json::json!({
            "source_part": "docx-story-registry",
            "parts": [],
            "references": [],
            "diagnostics": [],
            "unsupported_features": []
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_STORY_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn mce_projection_change_is_detected() {
        let temp = write_integrity_fixture("mce-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["mce"]["capability_version"] =
            serde_json::Value::String("tampered".to_owned());
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_MCE_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn signature_projection_change_is_detected() {
        let temp = write_integrity_fixture("signature-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["signatures"]["source_part"] =
            serde_json::Value::String("tampered".to_owned());
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_SIGNATURE_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn document_references_projection_change_is_detected() {
        let temp = write_integrity_fixture("references-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["semantic"]["references"] = serde_json::json!({
            "source_part": "word/document.xml",
            "hyperlinks": [],
            "bookmarks": [],
            "bookmark_ranges": [],
            "fields": [],
            "cross_references": [],
            "diagnostics": []
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_DOCUMENT_REFERENCES_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn drawing_image_projection_change_is_detected() {
        let temp = write_integrity_fixture("drawings-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["semantic"]["drawings"] = serde_json::json!({
            "source_part": "word/document.xml",
            "drawings": [],
            "diagnostics": []
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_DRAWING_IMAGE_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn embedded_visual_objects_projection_change_is_detected() {
        let temp = write_integrity_fixture("embedded-visual-objects-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["payload"]["semantic"]["embedded_visual_objects"] = serde_json::json!({
            "source_part": "word/document.xml",
            "objects": [],
            "diagnostics": []
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(
            &report,
            "CVN_EMBEDDED_VISUAL_OBJECTS_PROJECTION_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn object_blob_change_is_detected() {
        let temp = write_integrity_fixture("object-change");
        let digest = package_with_one_object().objects[0].digest.clone();
        fs::write(temp.join(SHA256_OBJECT_PREFIX).join(&digest), b"tampered").unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_object_failure(&report, "CVN_OBJECT_DIGEST_MISMATCH"));
        assert!(has_package_failure(
            &report,
            "CVN_OBJECT_INVENTORY_DIGEST_MISMATCH"
        ));
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));

        cleanup(&temp);
    }

    #[test]
    fn missing_and_unexpected_objects_are_detected() {
        let temp = write_integrity_fixture("object-presence");
        let digest = package_with_one_object().objects[0].digest.clone();
        fs::remove_file(temp.join(SHA256_OBJECT_PREFIX).join(&digest)).unwrap();
        fs::write(
            temp.join(SHA256_OBJECT_PREFIX).join("c".repeat(64)),
            b"extra",
        )
        .unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_object_failure(&report, "CVN_OBJECT_MISSING"));
        assert!(has_object_failure(&report, "CVN_OBJECT_UNEXPECTED"));

        cleanup(&temp);
    }

    #[test]
    fn root_digest_change_is_detected_without_payload_change() {
        let temp = write_integrity_fixture("root-change");
        let path = temp.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["integrity"]["root"]["digest"] = serde_json::Value::String("d".repeat(64));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let report = verify_package_integrity(&temp).unwrap();

        assert!(!report.passed);
        assert!(has_package_failure(&report, "CVN_ROOT_DIGEST_MISMATCH"));
        assert!(report.node_results.iter().all(|node| node.passed));

        cleanup(&temp);
    }

    fn package_with_one_object() -> CvnPackage {
        let bytes = b"payload bytes".to_vec();
        let digest = sha256_hex(&bytes);
        let mut document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        document.mce = Some(MceProjection {
            source_part: "docx-mce".to_owned(),
            capability_version: "cvn-mce-capabilities-v1".to_owned(),
            capabilities: MceCapabilities {
                version: "cvn-mce-capabilities-v1".to_owned(),
                supported_namespaces: vec![
                    "http://purl.oclc.org/ooxml/wordprocessingml/main".to_owned(),
                    "http://schemas.openxmlformats.org/wordprocessingml/2006/main".to_owned(),
                ],
            },
            alternate_contents: Vec::new(),
            diagnostics: Vec::new(),
        });
        document.signatures = Some(OpcSignatureRegistryProjection {
            source_part: "opc-signature-registry".to_owned(),
            ..OpcSignatureRegistryProjection::default()
        });
        document.opaque.push(OpaqueEntry {
            id: cvn_core::OpaqueId::new(format!("sha256:{digest}")).unwrap(),
            media_type: "application/octet-stream".to_owned(),
            original_name: None,
            source_ref: None,
            content_digest: digest.clone(),
            length: bytes.len() as u64,
            preservation_mode: PreservationMode::PackageContentAddressed,
        });
        document.opc = OpcPackageProjection {
            parts: vec![OpcPart {
                original_path: "word/document.xml".to_owned(),
                content_type: Some("application/xml".to_owned()),
                original_size: bytes.len() as u64,
                content_digest: digest.clone(),
                compression: ZipEntryMetadata {
                    is_directory: false,
                    compressed_size: bytes.len() as u64,
                    uncompressed_size: bytes.len() as u64,
                    compression_method: "Stored".to_owned(),
                },
            }],
            content_types: ContentTypesProjection::default(),
            relationships: vec![OpcRelationship {
                source_part: None,
                relationship_id: "rId1".to_owned(),
                relationship_type: "officeDocument".to_owned(),
                target: "word/document.xml".to_owned(),
                target_mode: TargetMode::Internal,
            }],
        };
        CvnPackage {
            document,
            objects: vec![PackageObject { digest, bytes }],
        }
    }

    fn write_integrity_fixture(name: &str) -> PathBuf {
        let temp = temp_path(name);
        cleanup(&temp);
        write_package(&temp, &package_with_one_object()).unwrap();
        temp
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tuff-cvn-package-{name}-{}", std::process::id()))
    }

    fn cleanup(path: &Path) {
        if path.exists() {
            fs::remove_dir_all(path).unwrap();
        }
    }

    fn has_package_failure(report: &CanonicalPackageIntegrityReport, code: &str) -> bool {
        report
            .package_failures
            .iter()
            .any(|failure| failure.code == code)
    }

    fn has_object_failure(report: &CanonicalPackageIntegrityReport, code: &str) -> bool {
        report
            .object_failures
            .iter()
            .any(|failure| failure.code == code)
    }
}
