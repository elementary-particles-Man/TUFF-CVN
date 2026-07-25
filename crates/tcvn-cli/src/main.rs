use std::env;

fn main() {
    let wants_help = env::args()
        .nth(1)
        .map_or(true, |arg| arg == "-h" || arg == "--help");

    if wants_help {
        print_help();
        return;
    }

    eprintln!("tcvn: command handling is not implemented yet. Run `tcvn --help`.");
    std::process::exit(2);
}

fn print_help() {
    println!(
        "{project} — {expanded}

Convert multi-format data into reversible, verifiable, vendor-independent canonical JSON,
then regenerate supported formats from that canonical representation.

Usage:
  tcvn <command> [options]

Planned commands:
  tcvn import <input> -o <output.cvn>
  tcvn export <input.cvn> --format <format> -o <output>
  tcvn verify <input.cvn>
  tcvn diff <left.cvn> <right.cvn>

Status:
  Initial repository scaffold. Format conversion is not implemented yet.",
        project = cvn_core::PROJECT_NAME,
        expanded = cvn_core::EXPANDED_NAME
    );
}
