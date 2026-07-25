# Round-trip Contract

The initial target remains DOCX to canonical JSON to DOCX, but DOCX conversion
is not implemented in this phase.

## Current equivalence scope

The implemented equivalence target is limited to:

- stable JSON structure for `CvnDocument`
- deterministic canonical bytes for the same typed value
- deterministic canonical bytes after deserialize and reserialize
- stable SHA-256 over canonical bytes

This phase does not claim byte-identical source regeneration or semantic
equivalence for any source document format.

## Deferred round-trip decisions

Future DOCX round-trip work must define:

- what document features are in scope
- how unsupported features are represented
- how opaque data is stored and recovered
- how verification reports loss, normalization, or regeneration differences
- which comparisons are byte-level, semantic, or structural

Unconfirmed/deferred:

- complete RFC 8785 compliance
- OOXML infoset preservation
- byte-identical DOCX regeneration
