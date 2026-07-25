# CVN v1 schemas

This directory is the placeholder location for CVN v1 schema artifacts.

The `cvn.json` root currently contains:

- `payload`
- `integrity`

The implemented Rust payload model currently defines these `CvnDocument` areas:

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

The current implementation is code-first. No standalone JSON Schema file is
published yet.

P0-CVN-02 adds OPC preservation metadata for unedited DOCX round trips. Raw part
bytes live outside `cvn.json` as content-addressed package objects. Parsed
`[Content_Types].xml` and `.rels` data are read-only projections and are not
used to regenerate XML payloads during normal export.

P0-CVN-03 adds `IntegrityManifest`:

- `version`
- `algorithm`
- `root.digest`
- `nodes[]`

The node kinds are:

- `canonical_payload`
- `part_map`
- `relations`
- `content_types`
- `semantic_projection`
- `style_projection`
- `numbering_projection`
- `objects`

The manifest is calculated from explicit hash-target projections. The
`root.digest` field is not included in its own calculation.

P0-CVN-04 adds the semantic projection model:

- `SemanticDocument`
- `SemanticBlock`
- `SemanticParagraph`
- `SemanticRun`
- `SemanticText`
- `SemanticTable`
- `SemanticTableRow`
- `SemanticTableCell`
- `SemanticInline`
- `SemanticNodeId`
- `SourceAnchor`
- `ParagraphPropertiesProjection`
- `RunPropertiesProjection`
- `UnsupportedSemanticFeature`

The semantic projection is read-only and does not replace raw OPC preservation.
Its integrity is checked by the `semantic_projection` leaf.

P0-CVN-05 adds read-only style and numbering projection models:

- `StyleRegistryProjection`
- `StyleDefinitionProjection`
- `StyleType`
- `StyleReference`
- `ResolvedStyleProjection`
- `StyleResolutionDiagnostic`
- `NumberingRegistryProjection`
- `AbstractNumberingProjection`
- `NumberingInstanceProjection`
- `NumberingLevelProjection`
- `NumberingReference`
- `NumberFormatProjection`
- `NumberingResolutionDiagnostic`

`SemanticDocument` may contain optional `styles` and `numbering` projections.
`SemanticParagraph` may contain a `NumberingReference` and resolved paragraph
style. `SemanticRun` may contain resolved run style. These projections are
read-only; raw `word/styles.xml` and `word/numbering.xml` remain preserved as OPC
objects and are not regenerated from projection data.

The integrity manifest version is now `cvn-integrity-v4-style-numbering`.
The `style_projection` and `numbering_projection` leaves hash deterministic
RFC 8785 projections independently from raw object hashes.

Non-supported or not-yet-claimed areas:

- DOCX conversion
- OOXML-specific part modeling
- OOXML infoset preservation
- byte-identical DOCX regeneration
- stable final CVN format
- ZIP physical byte identity
- XML C14N equivalence
- DOCX semantic conversion
- External URI resolution
