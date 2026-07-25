use std::env;
use std::path::PathBuf;

use thiserror::Error;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("tcvn: {error}");
        std::process::exit(2);
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
    if args.len() != 3 || args[1] != "--against" {
        return Err(CliError::Usage(
            "usage: tcvn verify <input.cvn> --against <document.docx>".to_owned(),
        ));
    }

    let input = PathBuf::from(&args[0]);
    let against = PathBuf::from(&args[2]);
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
    #[error("Expanded OPC Part Byte Identity failed")]
    VerificationFailed,
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

  tcvn verify <input.cvn> --against <document.docx>
      Verify ExpandedOpcPartByteIdentity between a CVN package and DOCX.

  tcvn diff <left.cvn> <right.cvn>
      Planned; not implemented yet.

Status:
  OPC raw-byte preservation package round trip is implemented for unedited DOCX preservation.
  DOCX semantic conversion is not implemented.",
        project = cvn_core::PROJECT_NAME,
        expanded = cvn_core::EXPANDED_NAME
    );
}
