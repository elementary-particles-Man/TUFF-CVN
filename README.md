# TUFF-CVN

TUFF Canonical Verifiable Notation (TUFF-CVN) is an initial Rust workspace for converting multi-format data into reversible, verifiable, vendor-independent canonical JSON, then regenerating supported formats from that canonical representation.

日本語概要: TUFF-CVNは、複数形式のデータを可逆・検証可能な正本JSONへ変換し、正本JSONから各形式を再生成するための基盤です。

## Core concept

The project centers on a canonical JSON representation:

- import: source format -> canonical JSON
- export: canonical JSON -> target format
- verify: validate canonical JSON structure and integrity
- diff: compare canonical JSON documents

## Current status

Initial repository scaffold. The workspace builds and includes a CLI skeleton, but format conversion is not implemented yet.

## Initial target

The first target is a DOCX -> canonical JSON -> DOCX round trip.

## Workspace layout

- `crates/cvn-core` — shared domain types
- `crates/cvn-schema` — schema-related support
- `crates/cvn-canonical` — canonical JSON support
- `crates/cvn-package` — package/container support
- `crates/cvn-verify` — verification support
- `crates/cvn-docx-import` — DOCX import entry point
- `crates/cvn-docx-export` — DOCX export entry point
- `crates/tcvn-cli` — CLI binary
- `schemas/cvn-v1` — initial schema location
- `fixtures/docx` — DOCX fixtures location
- `docs` — format and round-trip notes

## CLI

The CLI binary is `tcvn`.

Planned commands:

- `tcvn import <input> -o <output.cvn>`
- `tcvn export <input.cvn> --format <format> -o <output>`
- `tcvn verify <input.cvn>`
- `tcvn diff <left.cvn> <right.cvn>`

## License

MIT
