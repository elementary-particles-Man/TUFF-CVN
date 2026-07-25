# CVN v1 schemas

This directory is the placeholder location for CVN v1 schema artifacts.

The implemented Rust root model currently defines these `CvnDocument` areas:

- `schema_version`
- `document_id`
- `manifest`
- `content`
- `styles`
- `relations`
- `permissions`
- `assets`
- `opaque`
- `warnings`
- `checksums`

The current implementation is code-first. No standalone JSON Schema file is
published yet.

Non-supported or not-yet-claimed areas:

- complete RFC 8785 canonical JSON compliance
- DOCX conversion
- OOXML-specific part modeling
- OOXML infoset preservation
- byte-identical DOCX regeneration
- stable final CVN format
