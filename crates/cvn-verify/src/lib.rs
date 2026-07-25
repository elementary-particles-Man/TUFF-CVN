//! Verification support for TUFF-CVN.

use std::collections::BTreeSet;

use cvn_canonical::{sha256_canonical, to_canonical_bytes};
use cvn_core::{ChecksumAlgorithm, ChecksumEntry, CvnDocument, Relation};

/// Structural verification report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub passed: bool,
    pub errors: Vec<VerificationError>,
    pub warnings: Vec<VerificationWarning>,
    pub canonical_bytes_available: bool,
    pub canonical_sha256_available: bool,
}

/// Typed verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationError {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Typed verification warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationWarning {
    pub code: String,
    pub path: String,
    pub message: String,
}

/// Verifies the minimal CVN structural invariants currently implemented.
pub fn verify_document(document: &CvnDocument) -> VerificationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if document.schema_version != cvn_core::CVN_V1 {
        errors.push(error(
            "unsupported_schema_version",
            "$.schema_version",
            "schema_version must be cvn-v1",
        ));
    }

    check_duplicates(
        document.content.nodes.iter().map(|node| node.id.as_str()),
        "$.content.nodes",
        "duplicate_node_id",
        &mut errors,
    );
    check_duplicates(
        document.assets.iter().map(|asset| asset.id.as_str()),
        "$.assets",
        "duplicate_asset_id",
        &mut errors,
    );
    check_duplicates(
        document.opaque.iter().map(|opaque| opaque.id.as_str()),
        "$.opaque",
        "duplicate_opaque_id",
        &mut errors,
    );
    check_duplicates(
        document
            .relations
            .iter()
            .map(|relation| relation.id.as_str()),
        "$.relations",
        "duplicate_relation_id",
        &mut errors,
    );
    check_duplicates(
        document
            .checksums
            .iter()
            .map(|checksum| checksum.id.as_str()),
        "$.checksums",
        "duplicate_checksum_id",
        &mut errors,
    );
    check_duplicates(
        document
            .manifest
            .sources
            .iter()
            .map(|source| source.id.as_str()),
        "$.manifest.sources",
        "duplicate_source_id",
        &mut errors,
    );

    let node_ids: BTreeSet<_> = document
        .content
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect();
    let opaque_ids: BTreeSet<_> = document
        .opaque
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();

    check_dangling_relations(&document.relations, &node_ids, &mut errors);
    check_missing_opaque_refs(document, &opaque_ids, &mut errors);

    for (index, checksum) in document.checksums.iter().enumerate() {
        check_checksum(checksum, index, &mut errors);
    }
    for (index, opaque) in document.opaque.iter().enumerate() {
        check_digest_format(
            &opaque.content_digest,
            &format!("$.opaque[{index}].content_digest"),
            &mut errors,
        );
    }

    let canonical_bytes_available = match to_canonical_bytes(document) {
        Ok(_) => true,
        Err(error) => {
            errors.push(VerificationError {
                code: "canonical_bytes_failed".to_owned(),
                path: "$".to_owned(),
                message: error.to_string(),
            });
            false
        }
    };

    let canonical_sha256_available = match sha256_canonical(document) {
        Ok(_) => true,
        Err(error) => {
            errors.push(VerificationError {
                code: "canonical_sha256_failed".to_owned(),
                path: "$".to_owned(),
                message: error.to_string(),
            });
            false
        }
    };

    warnings.extend(document.warnings.iter().map(|warning| VerificationWarning {
        code: warning.code.clone(),
        path: warning.path.clone(),
        message: warning.message.clone(),
    }));

    VerificationReport {
        passed: errors.is_empty(),
        errors,
        warnings,
        canonical_bytes_available,
        canonical_sha256_available,
    }
}

fn check_duplicates<'a>(
    ids: impl Iterator<Item = &'a str>,
    path: &str,
    code: &str,
    errors: &mut Vec<VerificationError>,
) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            errors.push(error(code, path, &format!("duplicate identifier `{id}`")));
        }
    }
}

fn check_dangling_relations(
    relations: &[Relation],
    node_ids: &BTreeSet<&str>,
    errors: &mut Vec<VerificationError>,
) {
    for (index, relation) in relations.iter().enumerate() {
        if !node_ids.contains(relation.source.as_str()) {
            errors.push(error(
                "dangling_relation",
                &format!("$.relations[{index}].source"),
                "relation source does not reference an existing content node",
            ));
        }
        if !node_ids.contains(relation.target.as_str()) {
            errors.push(error(
                "dangling_relation",
                &format!("$.relations[{index}].target"),
                "relation target does not reference an existing content node",
            ));
        }
    }
}

fn check_missing_opaque_refs(
    document: &CvnDocument,
    opaque_ids: &BTreeSet<&str>,
    errors: &mut Vec<VerificationError>,
) {
    for (index, asset) in document.assets.iter().enumerate() {
        if let Some(opaque_ref) = &asset.opaque_ref {
            if !opaque_ids.contains(opaque_ref.as_str()) {
                errors.push(error(
                    "missing_opaque_reference",
                    &format!("$.assets[{index}].opaque_ref"),
                    "asset opaque_ref does not reference an existing opaque entry",
                ));
            }
        }
    }

    for (node_index, node) in document.content.nodes.iter().enumerate() {
        for (ref_index, opaque_ref) in node.opaque_refs.iter().enumerate() {
            if !opaque_ids.contains(opaque_ref.as_str()) {
                errors.push(error(
                    "missing_opaque_reference",
                    &format!("$.content.nodes[{node_index}].opaque_refs[{ref_index}]"),
                    "content node opaque_refs entry does not reference an existing opaque entry",
                ));
            }
        }
    }

    for (index, entry) in document.opaque.iter().enumerate() {
        if entry.length == 0 {
            errors.push(error(
                "invalid_opaque_length",
                &format!("$.opaque[{index}].length"),
                "opaque entry length must be greater than zero",
            ));
        }
    }
}

fn check_checksum(checksum: &ChecksumEntry, index: usize, errors: &mut Vec<VerificationError>) {
    match checksum.algorithm {
        ChecksumAlgorithm::Sha256 => check_digest_format(
            &checksum.digest,
            &format!("$.checksums[{index}].digest"),
            errors,
        ),
    }

    if checksum.target.is_empty() {
        errors.push(error(
            "invalid_checksum_target",
            &format!("$.checksums[{index}].target"),
            "checksum target must not be empty",
        ));
    }
}

fn check_digest_format(digest: &str, path: &str, errors: &mut Vec<VerificationError>) {
    let valid = digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit());

    if !valid {
        errors.push(error(
            "invalid_checksum_digest",
            path,
            "digest must be 64 hexadecimal characters",
        ));
    }
}

fn error(code: &str, path: &str, message: &str) -> VerificationError {
    VerificationError {
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use cvn_core::{
        AssetEntry, AssetId, ChecksumId, ContentNode, DocumentId, OpaqueEntry, OpaqueId,
        PreservationMode, RelationId,
    };

    use super::*;

    #[test]
    fn empty_minimal_document_is_valid() {
        let report = verify_document(&CvnDocument::minimal(DocumentId::new("doc-1").unwrap()));

        assert!(report.passed);
        assert!(report.canonical_bytes_available);
        assert!(report.canonical_sha256_available);
    }

    #[test]
    fn duplicate_ids_are_detected() {
        let duplicate_id = cvn_core::NodeId::new("node-1").unwrap();
        let mut document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        document.content.nodes = vec![
            ContentNode {
                id: duplicate_id.clone(),
                kind: "paragraph".to_owned(),
                text: None,
                attributes: Default::default(),
                source_ref: None,
                opaque_refs: Vec::new(),
                children: Vec::new(),
            },
            ContentNode {
                id: duplicate_id,
                kind: "paragraph".to_owned(),
                text: None,
                attributes: Default::default(),
                source_ref: None,
                opaque_refs: Vec::new(),
                children: Vec::new(),
            },
        ];

        let report = verify_document(&document);

        assert!(!report.passed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.code == "duplicate_node_id"));
    }

    #[test]
    fn dangling_relation_is_detected() {
        let mut document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        document.relations.push(Relation {
            id: RelationId::new("rel-1").unwrap(),
            kind: "references".to_owned(),
            source: cvn_core::NodeId::new("missing-source").unwrap(),
            target: cvn_core::NodeId::new("missing-target").unwrap(),
            source_ref: None,
        });

        let report = verify_document(&document);

        assert!(!report.passed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.code == "dangling_relation"));
    }

    #[test]
    fn missing_opaque_reference_is_detected() {
        let mut document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        document.assets.push(AssetEntry {
            id: AssetId::new("asset-1").unwrap(),
            media_type: "application/octet-stream".to_owned(),
            original_name: None,
            source_ref: None,
            opaque_ref: Some(OpaqueId::new("opaque-missing").unwrap()),
            content_digest: None,
            length: None,
        });

        let report = verify_document(&document);

        assert!(!report.passed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.code == "missing_opaque_reference"));
    }

    #[test]
    fn missing_content_node_opaque_reference_is_detected() {
        let mut document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        document.content.nodes.push(ContentNode {
            id: cvn_core::NodeId::new("node-1").unwrap(),
            kind: "binary-placeholder".to_owned(),
            text: None,
            attributes: Default::default(),
            source_ref: None,
            opaque_refs: vec![OpaqueId::new("opaque-missing").unwrap()],
            children: Vec::new(),
        });

        let report = verify_document(&document);

        assert!(!report.passed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.code == "missing_opaque_reference"));
    }

    #[test]
    fn checksum_format_is_validated() {
        let mut document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        document.checksums.push(ChecksumEntry {
            id: ChecksumId::new("checksum-1").unwrap(),
            algorithm: ChecksumAlgorithm::Sha256,
            target: "$".to_owned(),
            digest: "not-hex".to_owned(),
        });

        let report = verify_document(&document);

        assert!(!report.passed);
        assert!(report
            .errors
            .iter()
            .any(|error| error.code == "invalid_checksum_digest"));
    }

    #[test]
    fn valid_opaque_entry_passes_digest_checks() {
        let mut document = CvnDocument::minimal(DocumentId::new("doc-1").unwrap());
        document.opaque.push(OpaqueEntry {
            id: OpaqueId::new("opaque-1").unwrap(),
            media_type: "application/octet-stream".to_owned(),
            original_name: None,
            source_ref: None,
            content_digest: "a".repeat(64),
            length: 1,
            preservation_mode: PreservationMode::PackageContentAddressed,
        });

        let report = verify_document(&document);

        assert!(report.passed);
    }
}
