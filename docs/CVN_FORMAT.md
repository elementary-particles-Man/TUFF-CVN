# CVN Format

CVN is the canonical JSON representation for TUFF-CVN. The format is still
early and not stable.

## Root structure

The canonical package file `cvn.json` has two top-level areas:

- `payload`
- `integrity`

`payload` is the hash target. `integrity` stores the resulting manifest and root
digest. The root digest is never included in its own hash input.

The current payload root model is `CvnDocument`:

- `schema_version`
- `document_id`
- `manifest`
- `content`
- `styles`
- `relations`
- `permissions`
- `assets`
- `opaque`
- `opc`
- `semantic`
- `warnings`
- `checksums`

All root areas are present in canonical serialization. Empty arrays and empty
objects are valid for the initial minimal document.

## Stable IDs

IDs are externally supplied stable identifiers, not generated UUIDs. The current
typed IDs include `DocumentId`, `NodeId`, `AssetId`, `OpaqueId`, `RelationId`,
`ChecksumId`, and `SourceId`.

IDs serialize as JSON strings. They must be non-empty ASCII strings up to 128
bytes using letters, digits, `-`, `_`, `.`, or `:`.

## Source preservation

`SourceDescriptor`, `SourceFormat`, `SourcePartRef`, and `SourceByteRange`
provide vendor-neutral references back to source material. This phase does not
define DOCX-specific or OOXML-specific part names.

## Opaque data

`OpaqueEntry` preserves uninterpreted data by reference instead of discarding it.
It carries:

- `id`
- `media_type`
- `original_name`
- `source_ref`
- `content_digest`
- `length`
- `preservation_mode`

Opaque content can be represented as an external blob or as a package
content-addressed object. In the preservation package, raw bytes are stored
outside `cvn.json` under `objects/sha256/<lowercase-hex-digest>`. `cvn.json`
must not inline blob bytes as Base64.

## OPC preservation package

P0-CVN-02 introduces a directory-shaped `.cvn` preservation package:

- `cvn.json`
- `objects/sha256/<lowercase-hex-digest>`

The `opc` root area records OPC part metadata:

- original part path
- content type, when projected from `[Content_Types].xml`
- original uncompressed size
- raw-byte SHA-256 digest
- ZIP entry metadata for diagnostics

Multiple OPC part paths may reference the same content-addressed object. The
same digest is written once. If the same digest is ever observed with different
bytes, import or package writing fails hard.

Package object paths are derived only from validated lowercase SHA-256 digests;
path traversal is not allowed.

## Raw bytes and parsed projections

Raw bytes and parsed projections are separate:

- OPC part payloads are preserved as raw bytes in package objects.
- `[Content_Types].xml` is parsed into a read-only Default/Override projection.
- package-level and part-level `.rels` files are parsed into a read-only
  relationship projection.
- export does not regenerate XML from projections for unedited preservation.

Projection parsing rejects DOCTYPE and does not resolve external resources.
`TargetMode="External"` relationship targets are retained as inert original
strings. TUFF-CVN does not fetch, normalize, rewrite, or delete those URIs.

## Semantic projection

P0-CVN-04 adds a read-only semantic projection from `word/document.xml`.
The projection does not replace raw OPC preservation and is not used to
regenerate DOCX XML.

The `semantic` payload area records:

- `source_part`
- ordered blocks
- unsupported features

Supported block kinds are paragraphs and tables. Supported inline kinds are
text, tab, and line break. Tables preserve row/cell order and allow nested
tables. Paragraphs retain paragraph style IDs and available `w14:paraId`
source identifiers. Runs retain run style IDs and basic formatting flags:
bold, italic, underline, and strike.

`SemanticNodeId` is the CVN primary key for semantic nodes. It is separate from
source identifiers such as `w14:paraId`. When a source identifier exists, the
generated CVN ID is derived from document ID, source part, node kind, and source
identifier. When no source identifier exists, the ID is derived from document
ID, source part, XML structural path, node kind, and raw document digest. The
generated IDs are persisted in `cvn.json`.

Each semantic node includes a `SourceAnchor` with the source part and XML
structural path. Byte start may be recorded when available; end offsets are not
guessed.

Unknown or unsupported XML elements are not silently deleted. They are recorded
as `UnsupportedSemanticFeature` with feature code, source anchor, namespace URI,
local name, and handling. The raw bytes remain preserved in the OPC object.

## Warnings and checksums

Warnings are typed records with `code`, `severity`, `path`, `message`, and
optional `source_ref`.

Checksums are typed records with `id`, `algorithm`, `target`, and `digest`.
The implemented algorithm enum currently contains SHA-256.

## RFC 8785 canonicalization boundary

Current canonical serialization uses `serde_json_canonicalizer` for RFC 8785
JSON Canonicalization Scheme output:

- converts typed serde values through `serde_json::Value`
- sorts object keys by UTF-16 code unit order
- emits compact UTF-8 JSON with no unnecessary whitespace
- canonicalizes JSON number spellings according to the canonicalizer
- rejects integer magnitudes greater than `2^53`
- assumes duplicate keys are not generated by typed serde structures

UTF-16 key ordering matters. For example, U+10000 sorts before U+E000 under JCS,
even though scalar-value ordering would put U+E000 first.

The JCS safe integer boundary is `9007199254740992` (`2^53`). `9007199254740992`
is accepted; `9007199254740993` is rejected fail-closed. CVN core fields should
not introduce floating point values. Values that may exceed the JCS integer
range must be modeled as strings/newtypes instead of unchecked integers.

## Canonical payload and integrity manifest

Self-reference is avoided by separating the hash target from the result:

- `CanonicalPayloadView` contains the payload being hashed.
- `IntegrityManifest` stores the calculated tree.
- `canonical_payload` hashes only RFC 8785 bytes of `CanonicalPayloadView`.
- `integrity.root.digest` is not part of the root digest input.

Integrity leaf nodes use SHA-256 over `domain-prefix || RFC8785-bytes`:

- `canonical_payload`
- `part_map`
- `relations`
- `content_types`
- `semantic_projection`
- `objects`

The root digest uses fixed child order. Each child record is
`node-kind || 0x00 || digest-bytes`; the root hashes
`TUFF-CVN\0root\0 || child-records`.

Package writes use RFC 8785 canonical bytes for `cvn.json`, not pretty JSON.
Object bytes remain outside `cvn.json`.

Unconfirmed/deferred:

- OOXML infoset preservation
- byte-identical DOCX regeneration
- ZIP physical byte identity
- XML C14N equivalence
- DOCX semantic conversion
- external signing of CVN manifests
