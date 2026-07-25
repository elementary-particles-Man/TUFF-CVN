# Round-trip Contract

The initial target remains DOCX to canonical JSON to DOCX. P0-CVN-02 implements
an unedited DOCX preservation round trip based on raw OPC part bytes.

## Current equivalence scope

The implemented equivalence target is limited to:

- stable JSON structure for `CvnDocument`
- deterministic canonical bytes for the same typed value
- deterministic canonical bytes after deserialize and reserialize
- stable SHA-256 over canonical bytes
- Expanded OPC Part Byte Identity for unedited DOCX preservation packages

## Expanded OPC Part Byte Identity

Expanded OPC Part Byte Identity is the Level 1 preservation check for P0-CVN-02.
It verifies a source DOCX and reconstructed DOCX after ZIP expansion:

- part path sets are equal
- each part raw byte length is equal
- each part raw byte SHA-256 digest is equal
- no missing parts
- no unexpected parts

This is not ZIP physical byte identity. ZIP entry order is deterministic on
export, but original ZIP timestamps, compression parameters, central-directory
layout, and other container bytes are not claimed to match.

This is not XML C14N equivalence. XML parts are not canonicalized or
re-serialized for normal export; saved raw bytes are used as the payload.

This is not DOCX semantic equivalence. No OOXML semantic document model is
implemented in this phase.

## Deferred round-trip decisions

Future DOCX round-trip work must define:

- what document features are in scope
- how unsupported features are represented
- how opaque data is stored and recovered
- how verification reports loss, normalization, or regeneration differences
- which comparisons are byte-level, semantic, or structural
- how edited projections should update raw payloads
- how signatures and encrypted packages should be handled

Unconfirmed/deferred:

- complete RFC 8785 compliance
- OOXML infoset preservation
- byte-identical DOCX regeneration
- XMLDSig public-key verification
- XMLDSig re-signing
- encrypted Office document decryption
