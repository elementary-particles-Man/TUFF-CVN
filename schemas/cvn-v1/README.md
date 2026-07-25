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
- `warnings`
- `checksums`

The current implementation is code-first. No standalone JSON Schema file is
published yet.

P0-CVN-02 adds OPC preservation metadata for unedited DOCX round trips. Raw part
bytes live outside `cvn.json` as content-addressed package objects. Parsed
`[Content_Types].xml` and `.rels` data are read-only projections and are not
used to regenerate XML payloads during normal export.

P0-CVN-03 adds `IntegrityManifest`:

- `algorithm`
- `root.digest`
- `nodes[]`

The node kinds are:

- `canonical_payload`
- `part_map`
- `relations`
- `content_types`
- `objects`

The manifest is calculated from explicit hash-target projections. The
`root.digest` field is not included in its own calculation.

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
