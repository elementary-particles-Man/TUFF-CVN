# Round-trip Contract

The initial target remains DOCX to canonical JSON to DOCX. P0-CVN-02 implements
an unedited DOCX preservation round trip based on raw OPC part bytes.

## Current equivalence scope

The implemented equivalence target is limited to:

- stable JSON structure for `CvnDocument`
- deterministic canonical bytes for the same typed value
- deterministic canonical bytes after deserialize and reserialize
- stable SHA-256 over canonical bytes
- CanonicalPackageIntegrity for `.cvn` preservation packages
- Expanded OPC Part Byte Identity for unedited DOCX preservation packages

## CanonicalPackageIntegrity

CanonicalPackageIntegrity verifies the preservation package itself:

- RFC 8785 canonical payload digest
- OPC part map digest
- relationship projection digest
- content types projection digest
- semantic projection digest
- content-addressed object inventory digest
- root digest over the fixed integrity tree
- object filename digest, recorded digest, actual digest, and length

It detects `cvn.json` payload changes, part map changes, relationship changes,
content type projection changes, semantic projection changes, object blob changes, missing objects,
unexpected objects, invalid object names, and root digest tampering.

CanonicalPackageIntegrity and Expanded OPC Part Byte Identity are independent
verification levels. A package can pass one and fail the other; `tcvn verify`
reports them separately and does not hide either failure.

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

## Semantic projection scope

The semantic projection is read-only. It is generated during import from
preserved `word/document.xml` bytes and stored in `cvn.json`, but export still
uses preserved raw OPC part payloads. Semantic projection data is not an XML
serialization source in this phase.

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
- external CVN signing
