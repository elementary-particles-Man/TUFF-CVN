use std::env;
use std::path::PathBuf;

use thiserror::Error;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("tcvn: {error}");
        std::process::exit(error.exit_code());
    }
}

fn run(args: Vec<String>) -> Result<(), CliError> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "import" => import_command(&args[1..]),
        "export" => export_command(&args[1..]),
        "verify" => verify_command(&args[1..]),
        "inspect" => inspect_command(&args[1..]),
        "diff" => Err(CliError::UnsupportedCommand("diff".to_owned())),
        command => Err(CliError::UnsupportedCommand(command.to_owned())),
    }
}

fn import_command(args: &[String]) -> Result<(), CliError> {
    if args.len() != 3 || args[1] != "-o" {
        return Err(CliError::Usage(
            "usage: tcvn import <input.docx> -o <output.cvn>".to_owned(),
        ));
    }

    let input = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[2]);
    let document = cvn_docx_import::import_docx_to_package(input, output)?;
    println!(
        "Imported DOCX as CVN preservation package: level=ExpandedOpcPartByteIdentity parts={}",
        document.opc.parts.len()
    );
    Ok(())
}

fn export_command(args: &[String]) -> Result<(), CliError> {
    if args.len() != 5 || args[1] != "--format" || args[2] != "docx" || args[3] != "-o" {
        return Err(CliError::Usage(
            "usage: tcvn export <input.cvn> --format docx -o <output.docx>".to_owned(),
        ));
    }

    let input = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[4]);
    let part_count = cvn_docx_export::export_package_to_docx(input, output)?;
    println!(
        "Exported DOCX from CVN preservation package: level=ExpandedOpcPartByteIdentity parts={part_count}"
    );
    Ok(())
}

fn verify_command(args: &[String]) -> Result<(), CliError> {
    if args.len() == 2 && args[1] == "--signatures" {
        let input = PathBuf::from(&args[0]);
        let integrity = cvn_verify::verify_canonical_package_integrity(&input)?;
        print_integrity_report(&integrity);
        if !integrity.passed {
            return Err(CliError::IntegrityFailed);
        }
        let report = cvn_verify::verify_opc_signatures(input)?;
        print_signature_report(&report);
        if report.unsupported {
            return Err(CliError::SignatureUnsupported);
        }
        if !report.passed {
            return Err(CliError::SignatureVerificationFailed);
        }
        return Ok(());
    }

    if args.len() == 1 {
        let input = PathBuf::from(&args[0]);
        let report = cvn_verify::verify_canonical_package_integrity(input)?;
        print_integrity_report(&report);
        if !report.passed {
            return Err(CliError::IntegrityFailed);
        }
        return Ok(());
    }

    if args.len() != 3 || args[1] != "--against" {
        return Err(CliError::Usage(
            "usage: tcvn verify <input.cvn> [--signatures] [--against <document.docx>]".to_owned(),
        ));
    }

    let input = PathBuf::from(&args[0]);
    let against = PathBuf::from(&args[2]);
    let integrity = cvn_verify::verify_canonical_package_integrity(&input)?;
    print_integrity_report(&integrity);
    if !integrity.passed {
        return Err(CliError::IntegrityFailed);
    }

    let report = cvn_verify::verify_expanded_opc_part_byte_identity(input, against)?;

    println!(
        "Verification ExpandedOpcPartByteIdentity: passed={} parts={}",
        report.passed, report.part_count
    );
    if !report.passed {
        println!("missing_parts={:?}", report.missing_parts);
        println!("unexpected_parts={:?}", report.unexpected_parts);
        println!("length_mismatches={:?}", report.length_mismatches);
        println!("digest_mismatches={:?}", report.digest_mismatches);
        println!("package_errors={:?}", report.package_errors);
        return Err(CliError::VerificationFailed);
    }

    Ok(())
}

fn inspect_command(args: &[String]) -> Result<(), CliError> {
    if args.len() < 2 {
        return Err(CliError::Usage(
            "usage: tcvn inspect <input.cvn> [--semantic] [--styles] [--numbering] [--stories] [--changes] [--mce]".to_owned(),
        ));
    }
    let flags = &args[1..];
    if flags.iter().any(|flag| {
        !matches!(
            flag.as_str(),
            "--semantic"
                | "--styles"
                | "--numbering"
                | "--stories"
                | "--changes"
                | "--mce"
                | "--signatures"
        )
    }) {
        return Err(CliError::Usage(
            "usage: tcvn inspect <input.cvn> [--semantic] [--styles] [--numbering] [--stories] [--changes] [--mce] [--signatures]"
                .to_owned(),
        ));
    }
    let input = PathBuf::from(&args[0]);
    let bytes = cvn_package::read_cvn_json_bytes(input)?;
    let cvn_json: cvn_core::CvnJson = serde_json::from_slice(&bytes)?;
    for flag in flags {
        match flag.as_str() {
            "--semantic" => println!(
                "{}",
                serde_json::to_string_pretty(&cvn_json.payload.semantic)?
            ),
            "--styles" => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&cvn_json.payload.semantic.styles)?
                )
            }
            "--numbering" => println!(
                "{}",
                serde_json::to_string_pretty(&cvn_json.payload.semantic.numbering)?
            ),
            "--stories" => println!(
                "{}",
                serde_json::to_string_pretty(&cvn_json.payload.semantic.stories)?
            ),
            "--changes" => println!(
                "{}",
                serde_json::to_string_pretty(&cvn_json.payload.track_changes)?
            ),
            "--mce" => println!("{}", serde_json::to_string_pretty(&cvn_json.payload.mce)?),
            "--signatures" => println!(
                "{}",
                serde_json::to_string_pretty(&cvn_json.payload.signatures)?
            ),
            _ => unreachable!("validated inspect flag"),
        }
    }
    Ok(())
}

fn print_signature_report(report: &cvn_verify::OpcSignatureVerificationReport) {
    println!(
        "Verification OpcXmlDigitalSignatures: passed={} signatures={}",
        report.passed, report.signatures
    );
    for signature in &report.projection.signatures {
        println!(
            "  signature_part={} cryptographic_validity={:?} certificate_trust={:?} signature_value={:?}",
            signature.signature_part_path,
            signature.verification.cryptographic_validity,
            signature.verification.certificate_trust,
            signature.verification.signature_value_status
        );
        for reference in &signature.verification.references {
            println!(
                "    reference uri={} status={:?} target={} expected={} actual={}",
                reference.uri,
                reference.status,
                reference.target_part_path.as_deref().unwrap_or("<none>"),
                reference.expected_digest,
                reference.actual_digest.as_deref().unwrap_or("<none>")
            );
        }
        for diagnostic in &signature.verification.diagnostics {
            println!(
                "    diagnostic code={} path={} message={}",
                diagnostic.code, diagnostic.path, diagnostic.message
            );
        }
    }
}

fn print_integrity_report(report: &cvn_package::CanonicalPackageIntegrityReport) {
    println!(
        "Verification CanonicalPackageIntegrity: passed={} root_expected={} root_actual={}",
        report.passed,
        report.root_expected.as_deref().unwrap_or("<none>"),
        report.root_actual.as_deref().unwrap_or("<none>")
    );
    for node in &report.node_results {
        println!(
            "  node={:?} passed={} expected={} actual={}",
            node.kind,
            node.passed,
            node.expected.as_deref().unwrap_or("<none>"),
            node.actual.as_deref().unwrap_or("<none>")
        );
    }
    for failure in report
        .object_failures
        .iter()
        .chain(report.canonicalization_failures.iter())
        .chain(report.package_failures.iter())
    {
        println!(
            "  failure code={} path={} message={}",
            failure.code, failure.path, failure.message
        );
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("unsupported command `{0}`")]
    UnsupportedCommand(String),
    #[error("DOCX import failed: {0}")]
    Import(#[from] cvn_docx_import::DocxImportError),
    #[error("DOCX export failed: {0}")]
    Export(#[from] cvn_docx_export::DocxExportError),
    #[error("verification failed: {0}")]
    Verify(#[from] cvn_verify::ExpandedOpcVerifyError),
    #[error("integrity verification failed: {0}")]
    Integrity(#[from] cvn_verify::CanonicalPackageIntegrityVerifyError),
    #[error("OPC XML signature verification failed: {0}")]
    Signature(#[from] cvn_verify::OpcSignatureVerifyError),
    #[error("package error: {0}")]
    Package(#[from] cvn_package::PackageError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("CanonicalPackageIntegrity failed")]
    IntegrityFailed,
    #[error("Expanded OPC Part Byte Identity failed")]
    VerificationFailed,
    #[error("OPC XML signature cryptographic verification failed")]
    SignatureVerificationFailed,
    #[error("OPC XML signature algorithm or transform unsupported")]
    SignatureUnsupported,
}

impl CliError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::UnsupportedCommand(_) => 2,
            Self::Import(_)
            | Self::Export(_)
            | Self::Verify(_)
            | Self::Integrity(_)
            | Self::Signature(_)
            | Self::Package(_)
            | Self::Json(_) => 3,
            Self::IntegrityFailed => 4,
            Self::VerificationFailed => 5,
            Self::SignatureVerificationFailed => 6,
            Self::SignatureUnsupported => 7,
        }
    }
}

fn print_help() {
    println!(
        "{project} — {expanded}

Convert multi-format data into reversible, verifiable, vendor-independent canonical JSON,
then regenerate supported formats from that canonical representation.

Usage:
  tcvn <command> [options]

Commands:
  tcvn import <input.docx> -o <output.cvn>
      Convert a DOCX ZIP into a CVN preservation package.

  tcvn export <input.cvn> --format docx -o <output.docx>
      Rebuild a DOCX ZIP from preserved raw OPC parts.

  tcvn verify <input.cvn>
      Verify CanonicalPackageIntegrity for a CVN package.

  tcvn verify <input.cvn> --signatures
      Verify OPC XML Digital Signatures cryptographically; signer trust remains unassessed.

  tcvn verify <input.cvn> --against <document.docx>
      Verify CanonicalPackageIntegrity and ExpandedOpcPartByteIdentity.

  tcvn inspect <input.cvn> [--semantic] [--styles] [--numbering] [--stories] [--changes] [--mce] [--signatures]
      Print read-only projections from cvn.json.

  tcvn diff <left.cvn> <right.cvn>
      Planned; not implemented yet.

Status:
  OPC raw-byte preservation package round trip is implemented for unedited DOCX preservation.
  DOCX semantic, style, and numbering projection import/inspect are implemented as read-only views.
  Semantic editing and projection-driven DOCX export are not implemented.",
        project = cvn_core::PROJECT_NAME,
        expanded = cvn_core::EXPANDED_NAME
    );
}
