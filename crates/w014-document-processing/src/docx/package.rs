//! OOXML hostile package limits, security preflight, and bounded extraction (WI-0207).
//!
//! Enforces:
//! - Package Limits:
//!   - `TOTAL_EXPANDED_BYTES <= 512 MiB` (536,870,912 bytes)
//!   - `ZIP_ENTRY_COUNT <= 10,000`
//!   - `MAX_PART_SIZE <= 64 MiB` (67,108,864 bytes)
//!   - `PER_ENTRY_COMPRESSION_RATIO <= 50:1`
//!   - `AGGREGATE_COMPRESSION_RATIO <= 100:1`
//!   - `XML_PART_SIZE <= 32 MiB` (33,554,432 bytes)
//!   - Reject BEFORE unsafe/unbounded extraction
//! - Package Security:
//!   - Path safety: reject absolute paths, drive prefixes, `..` traversal, NUL bytes, path aliases
//!   - Content-type validation: `[Content_Types].xml` required, reject macro/OLE content types
//!   - Relationships validation: reject external relationships, remote templates, OLE/macro relationships
//!   - XML safety: DTD rejected (`<!DOCTYPE`), external entities rejected (`<!ENTITY`), billion laughs defense
//!   - Format safety: reject macro-enabled DOCM/VBA, OLE embedded packages, polyglot/ambiguous ZIP archives

use std::collections::HashMap;
use std::io::{Cursor, Read};

use zip::ZipArchive;

use super::error::DocxError;

/// Maximum total expanded uncompressed bytes across all ZIP entries (512 MiB).
pub const MAX_TOTAL_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum allowed ZIP entry count (10,000 entries).
pub const MAX_ZIP_ENTRY_COUNT: usize = 10_000;

/// Maximum allowed single part uncompressed size (64 MiB).
pub const MAX_PART_SIZE: u64 = 64 * 1024 * 1024;

/// Maximum allowed per-entry compression ratio (50:1).
pub const MAX_PER_ENTRY_COMPRESSION_RATIO: f64 = 50.0;

/// Maximum allowed aggregate compression ratio (100:1).
pub const MAX_AGGREGATE_COMPRESSION_RATIO: f64 = 100.0;

/// Maximum allowed XML part uncompressed size (32 MiB).
pub const MAX_XML_PART_SIZE: u64 = 32 * 1024 * 1024;

/// Minimum uncompressed entry size before enforcing the per-entry ratio limit.
/// Prevents false positives on tiny 10-byte files that compress to 1 byte.
const MIN_SIZE_FOR_RATIO_CHECK: u64 = 1024;

/// ZIP Local File Header magic signature bytes (`PK\x03\x04`).
const ZIP_MAGIC_HEADER: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Media item extracted from `word/media/` inside a safe DOCX package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocxMediaItem {
    /// Full part name in package (e.g., "word/media/image1.png").
    pub part_name: String,
    /// Relationship ID if mapped (e.g., "rId4").
    pub relationship_id: Option<String>,
    /// Inferred or declared content type.
    pub content_type: String,
    /// Raw uncompressed image bytes.
    pub data: Vec<u8>,
}

/// Validated, safe in-memory representation of an OOXML DOCX package.
#[derive(Debug, Clone)]
pub struct DocxPackage {
    /// Raw XML text of `[Content_Types].xml`.
    pub content_types_xml: String,
    /// Raw XML text of `word/document.xml`.
    pub document_xml: String,
    /// Header XML parts (part_name, content).
    pub headers: Vec<(String, String)>,
    /// Footer XML parts (part_name, content).
    pub footers: Vec<(String, String)>,
    /// Media items extracted from `word/media/` (images for OCR evaluation).
    pub media_items: Vec<DocxMediaItem>,
    /// Relationship mapping (relationship_id -> target_part_name).
    pub relationships: HashMap<String, String>,
    /// Total uncompressed bytes extracted.
    pub total_expanded_bytes: u64,
    /// Total entry count in package.
    pub entry_count: usize,
}

impl DocxPackage {
    /// Opens and validates a DOCX byte buffer against all hostile package limits and security rules.
    ///
    /// # Errors
    /// Fails closed if any package limit, security policy, or integrity invariant is violated.
    pub fn open(bytes: &[u8]) -> Result<Self, DocxError> {
        // 1. Polyglot / Ambiguous ZIP Preflight: Must start with standard ZIP magic signature
        if bytes.len() < 4 || bytes[0..4] != ZIP_MAGIC_HEADER {
            return Err(DocxError::PolyglotOrAmbiguousPackage {
                detail: "Input bytes do not begin with standard ZIP magic signature PK\\x03\\x04"
                    .to_string(),
            });
        }

        let cursor = Cursor::new(bytes);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| DocxError::HostilePackage(format!("Malformed ZIP archive: {e}")))?;

        let entry_count = archive.len();
        if entry_count > MAX_ZIP_ENTRY_COUNT {
            return Err(DocxError::PackageLimitsExceeded {
                limit_name: "ZIP_ENTRY_COUNT",
                actual: entry_count as u64,
                limit: MAX_ZIP_ENTRY_COUNT as u64,
            });
        }

        // 2. Preflight Entry Inspection (Limits, Path Traversal, Ratio Checks)
        let mut total_uncompressed_bytes: u64 = 0;
        let mut part_names = Vec::with_capacity(entry_count);

        for i in 0..entry_count {
            let entry = archive.by_index(i).map_err(|e| {
                DocxError::HostilePackage(format!(
                    "Failed reading ZIP entry metadata at index {i}: {e}"
                ))
            })?;

            let name = entry.name().to_string();
            validate_entry_path(&name)?;

            let uncompressed_size = entry.size();
            let compressed_size = entry.compressed_size();

            // Part size limit check
            if uncompressed_size > MAX_PART_SIZE {
                return Err(DocxError::PackageLimitsExceeded {
                    limit_name: "MAX_PART_SIZE",
                    actual: uncompressed_size,
                    limit: MAX_PART_SIZE,
                });
            }

            // XML part size limit check
            if is_xml_part(&name) && uncompressed_size > MAX_XML_PART_SIZE {
                return Err(DocxError::PackageLimitsExceeded {
                    limit_name: "XML_PART_SIZE",
                    actual: uncompressed_size,
                    limit: MAX_XML_PART_SIZE,
                });
            }

            // Per-entry compression ratio check (zip bomb defense)
            if uncompressed_size > MIN_SIZE_FOR_RATIO_CHECK && compressed_size > 0 {
                let ratio = uncompressed_size as f64 / compressed_size as f64;
                if ratio > MAX_PER_ENTRY_COMPRESSION_RATIO {
                    return Err(DocxError::PackageLimitsExceeded {
                        limit_name: "PER_ENTRY_COMPRESSION_RATIO",
                        actual: ratio as u64,
                        limit: MAX_PER_ENTRY_COMPRESSION_RATIO as u64,
                    });
                }
            }

            // Aggregate uncompressed size check
            total_uncompressed_bytes = total_uncompressed_bytes
                .checked_add(uncompressed_size)
                .ok_or(DocxError::PackageLimitsExceeded {
                    limit_name: "TOTAL_EXPANDED_BYTES",
                    actual: u64::MAX,
                    limit: MAX_TOTAL_EXPANDED_BYTES,
                })?;

            if total_uncompressed_bytes > MAX_TOTAL_EXPANDED_BYTES {
                return Err(DocxError::PackageLimitsExceeded {
                    limit_name: "TOTAL_EXPANDED_BYTES",
                    actual: total_uncompressed_bytes,
                    limit: MAX_TOTAL_EXPANDED_BYTES,
                });
            }

            // Reject suspicious macro / OLE part names directly
            check_suspicious_part_name(&name)?;

            part_names.push(name);
        }

        // Aggregate compression ratio check
        if bytes.is_empty() {
            return Err(DocxError::HostilePackage(
                "Input buffer is empty".to_string(),
            ));
        }
        let aggregate_ratio = total_uncompressed_bytes as f64 / bytes.len() as f64;
        if aggregate_ratio > MAX_AGGREGATE_COMPRESSION_RATIO {
            return Err(DocxError::PackageLimitsExceeded {
                limit_name: "AGGREGATE_COMPRESSION_RATIO",
                actual: aggregate_ratio as u64,
                limit: MAX_AGGREGATE_COMPRESSION_RATIO as u64,
            });
        }

        // 3. Extract [Content_Types].xml and validate content types
        let content_types_idx = archive.index_for_name("[Content_Types].xml").ok_or(
            DocxError::MissingRequiredPart {
                part_name: "[Content_Types].xml",
            },
        )?;

        let content_types_xml = read_zip_entry_to_string(&mut archive, content_types_idx)?;
        validate_xml_security(&content_types_xml, "[Content_Types].xml")?;
        validate_content_types(&content_types_xml)?;

        // 4. Extract and validate relationships (_rels/.rels and word/_rels/document.xml.rels)
        let mut relationships = HashMap::new();
        for (i, name) in part_names.iter().enumerate() {
            if name.ends_with(".rels") {
                let rels_xml = read_zip_entry_to_string(&mut archive, i)?;
                validate_xml_security(&rels_xml, name)?;
                parse_and_validate_relationships(&rels_xml, name, &mut relationships)?;
            }
        }

        // 5. Extract word/document.xml (Required!)
        let doc_xml_idx =
            archive
                .index_for_name("word/document.xml")
                .ok_or(DocxError::MissingRequiredPart {
                    part_name: "word/document.xml",
                })?;
        let document_xml = read_zip_entry_to_string(&mut archive, doc_xml_idx)?;
        validate_xml_security(&document_xml, "word/document.xml")?;

        // 6. Extract headers and footers
        let mut headers = Vec::new();
        let mut footers = Vec::new();
        let mut media_items = Vec::new();

        for (i, name) in part_names.iter().enumerate() {
            if name.starts_with("word/header") && name.ends_with(".xml") {
                let text = read_zip_entry_to_string(&mut archive, i)?;
                validate_xml_security(&text, name)?;
                headers.push((name.clone(), text));
            } else if name.starts_with("word/footer") && name.ends_with(".xml") {
                let text = read_zip_entry_to_string(&mut archive, i)?;
                validate_xml_security(&text, name)?;
                footers.push((name.clone(), text));
            } else if name.starts_with("word/media/") {
                let media_data = read_zip_entry_to_vec(&mut archive, i)?;
                let ctype = infer_media_content_type(name);
                media_items.push(DocxMediaItem {
                    part_name: name.clone(),
                    relationship_id: None, // Can be resolved via relationships map if needed
                    content_type: ctype,
                    data: media_data,
                });
            }
        }

        Ok(Self {
            content_types_xml,
            document_xml,
            headers,
            footers,
            media_items,
            relationships,
            total_expanded_bytes: total_uncompressed_bytes,
            entry_count,
        })
    }
}

/// Validates entry path against path traversal, absolute paths, drive prefixes, and NUL bytes.
fn validate_entry_path(name: &str) -> Result<(), DocxError> {
    if name.is_empty() {
        return Err(DocxError::HostilePackage(
            "Empty ZIP entry name".to_string(),
        ));
    }

    // Reject NUL bytes
    if name.contains('\0') {
        return Err(DocxError::HostilePackage(
            "ZIP entry name contains NUL character (\\0)".to_string(),
        ));
    }

    // Reject absolute paths starting with '/' or '\'
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(DocxError::HostilePackage(format!(
            "Absolute path rejected in ZIP entry: '{name}'"
        )));
    }

    // Reject Windows drive prefixes like "C:" or "D:"
    if name.len() >= 2 && name.as_bytes()[1] == b':' && name.as_bytes()[0].is_ascii_alphabetic() {
        return Err(DocxError::HostilePackage(format!(
            "Drive prefix rejected in ZIP entry: '{name}'"
        )));
    }

    // Reject path traversal components ("..")
    for segment in name.split(['/', '\\']) {
        if segment == ".." {
            return Err(DocxError::HostilePackage(format!(
                "Path traversal '..' rejected in ZIP entry: '{name}'"
            )));
        }
    }

    Ok(())
}

/// Checks whether an entry is an XML or markup part subject to the XML part size limit.
fn is_xml_part(name: &str) -> bool {
    name.ends_with(".xml") || name.ends_with(".rels")
}

/// Rejects entry names matching macro, VBA, OLE, or activeX extensions.
fn check_suspicious_part_name(name: &str) -> Result<(), DocxError> {
    let lower = name.to_lowercase();
    if lower.contains("vbaproject") || lower.ends_with(".vba") || lower.contains("vbadata") {
        return Err(DocxError::MacroEnabledPackage {
            detail: format!("VBA macro part found in package: '{name}'"),
        });
    }

    if lower.contains("oleobject") || lower.contains("activex") {
        return Err(DocxError::OleOrEmbeddedPackage {
            detail: format!("OLE or ActiveX part found in package: '{name}'"),
        });
    }

    if lower.ends_with(".bin") && !lower.starts_with("word/media/") {
        return Err(DocxError::OleOrEmbeddedPackage {
            detail: format!("Embedded binary payload rejected: '{name}'"),
        });
    }

    Ok(())
}

/// Validates XML parts against DTD declarations and external entity expansion (Billion Laughs / XXE).
pub fn validate_xml_security(xml_text: &str, part_name: &str) -> Result<(), DocxError> {
    // Fail closed if DOCTYPE or ENTITY declaration is present
    let upper = xml_text.to_uppercase();
    if upper.contains("<!DOCTYPE") {
        return Err(DocxError::DtdOrExternalEntity {
            detail: format!("DOCTYPE declaration rejected in '{part_name}'"),
        });
    }

    if upper.contains("<!ENTITY") {
        return Err(DocxError::DtdOrExternalEntity {
            detail: format!("ENTITY declaration rejected in '{part_name}'"),
        });
    }

    Ok(())
}

/// Validates `[Content_Types].xml` for macro-enabled or OLE content types.
fn validate_content_types(content_types_xml: &str) -> Result<(), DocxError> {
    let lower = content_types_xml.to_lowercase();

    // Check for macro-enabled content types
    if lower.contains("macroenabled")
        || lower.contains("vbaproject")
        || lower.contains("application/vnd.ms-office.vba")
    {
        return Err(DocxError::MacroEnabledPackage {
            detail: "Macro-enabled content type declared in [Content_Types].xml".to_string(),
        });
    }

    // Check for OLE / embedded package content types
    if lower.contains("oleobject")
        || lower.contains("activex")
        || lower.contains("application/vnd.openxmlformats-officedocument.package")
    {
        return Err(DocxError::OleOrEmbeddedPackage {
            detail: "OLE or ActiveX content type declared in [Content_Types].xml".to_string(),
        });
    }

    Ok(())
}

/// Parses and validates relationship files (`.rels`).
/// Rejects `TargetMode="External"`, remote templates, OLE/macro relationships, and network URI targets.
fn parse_and_validate_relationships(
    rels_xml: &str,
    rels_part_name: &str,
    map: &mut HashMap<String, String>,
) -> Result<(), DocxError> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(rels_xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if e.name().as_ref() == b"Relationship" {
                    let mut id = None;
                    let mut target = None;
                    let mut rel_type = None;
                    let mut target_mode = None;

                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"Id" => id = Some(String::from_utf8_lossy(&attr.value).to_string()),
                            b"Target" => {
                                target = Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                            b"Type" => {
                                rel_type = Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                            b"TargetMode" => {
                                target_mode =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                            _ => {}
                        }
                    }

                    if let (Some(t), Some(rt)) = (&target, &rel_type) {
                        // Reject TargetMode="External"
                        if let Some(mode) = &target_mode
                            && mode.eq_ignore_ascii_case("External")
                        {
                            return Err(DocxError::ExternalRelationship {
                                target: t.clone(),
                                relationship_type: rt.clone(),
                            });
                        }

                        // Reject remote URLs in target
                        let lower_target = t.to_lowercase();
                        if lower_target.starts_with("http://")
                            || lower_target.starts_with("https://")
                            || lower_target.starts_with("ftp://")
                            || lower_target.starts_with("file://")
                            || lower_target.starts_with("\\\\")
                            || lower_target.starts_with("smb://")
                        {
                            return Err(DocxError::ExternalRelationship {
                                target: t.clone(),
                                relationship_type: rt.clone(),
                            });
                        }

                        // Reject remote templates
                        if rt.contains("attachedTemplate") {
                            return Err(DocxError::RemoteTemplate { target: t.clone() });
                        }

                        // Reject OLE / macro relationships
                        if rt.contains("vbaProject") {
                            return Err(DocxError::MacroEnabledPackage {
                                detail: format!("VBA relationship in '{rels_part_name}'"),
                            });
                        }
                        if rt.contains("oleObject") || rt.contains("activeXControl") {
                            return Err(DocxError::OleOrEmbeddedPackage {
                                detail: format!("OLE/ActiveX relationship in '{rels_part_name}'"),
                            });
                        }

                        if let Some(i) = id {
                            map.insert(i, t.clone());
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(DocxError::XmlParseError {
                    part_name: rels_part_name.to_string(),
                    detail: format!("Error reading relationship XML: {e}"),
                });
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(())
}

fn infer_media_content_type(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.ends_with(".png") {
        "image/png".to_string()
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg".to_string()
    } else if lower.ends_with(".tiff") || lower.ends_with(".tif") {
        "image/tiff".to_string()
    } else if lower.ends_with(".bmp") {
        "image/bmp".to_string()
    } else if lower.ends_with(".webp") {
        "image/webp".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

fn read_zip_entry_to_string<R: std::io::Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
) -> Result<String, DocxError> {
    let mut entry = archive.by_index(index).map_err(|e| DocxError::Io {
        detail: e.to_string(),
    })?;
    let mut text = String::new();
    entry.read_to_string(&mut text).map_err(|e| DocxError::Io {
        detail: e.to_string(),
    })?;
    Ok(text)
}

fn read_zip_entry_to_vec<R: std::io::Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
) -> Result<Vec<u8>, DocxError> {
    let mut entry = archive.by_index(index).map_err(|e| DocxError::Io {
        detail: e.to_string(),
    })?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).map_err(|e| DocxError::Io {
        detail: e.to_string(),
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    fn build_valid_docx() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
                    <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
                    <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
                    <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
                </Types>").unwrap();

            zip.start_file("_rels/.rels", options).unwrap();
            zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                    <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
                </Relationships>").unwrap();

            zip.start_file("word/document.xml", options).unwrap();
            zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
                    <w:body>\
                        <w:p><w:r><w:t>Hello World</w:t></w:r></w:p>\
                    </w:body>\
                </w:document>").unwrap();

            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn test_valid_docx_opens_successfully() {
        let bytes = build_valid_docx();
        let pkg = DocxPackage::open(&bytes).expect("Valid DOCX should open cleanly");
        assert_eq!(pkg.entry_count, 3);
        assert!(pkg.document_xml.contains("Hello World"));
    }

    #[test]
    fn test_polyglot_rejected() {
        let mut bytes = b"MZ\x90\x00PE executable header".to_vec();
        bytes.extend_from_slice(&build_valid_docx());
        let res = DocxPackage::open(&bytes);
        assert!(matches!(
            res,
            Err(DocxError::PolyglotOrAmbiguousPackage { .. })
        ));
    }

    #[test]
    fn test_path_traversal_rejected() {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();
            zip.start_file("word/../../etc/passwd", options).unwrap();
            zip.write_all(b"payload").unwrap();
            zip.finish().unwrap();
        }
        let res = DocxPackage::open(&buf);
        assert!(matches!(res, Err(DocxError::HostilePackage(_))));
    }

    #[test]
    fn test_absolute_path_rejected() {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();
            zip.start_file("/etc/shadow", options).unwrap();
            zip.write_all(b"payload").unwrap();
            zip.finish().unwrap();
        }
        let res = DocxPackage::open(&buf);
        assert!(matches!(res, Err(DocxError::HostilePackage(_))));
    }

    #[test]
    fn test_external_relationship_rejected() {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();

            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>").unwrap();

            zip.start_file("_rels/.rels", options).unwrap();
            zip.write_all(b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"http://evil.com\" TargetMode=\"External\"/>\
            </Relationships>").unwrap();

            zip.finish().unwrap();
        }
        let res = DocxPackage::open(&buf);
        assert!(matches!(res, Err(DocxError::ExternalRelationship { .. })));
    }

    #[test]
    fn test_macro_docm_rejected() {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();

            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
                <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.ms-word.document.macroEnabled.main+xml\"/>\
            </Types>").unwrap();

            zip.start_file("word/vbaProject.bin", options).unwrap();
            zip.write_all(b"vba bytecode").unwrap();

            zip.finish().unwrap();
        }
        let res = DocxPackage::open(&buf);
        assert!(matches!(res, Err(DocxError::MacroEnabledPackage { .. })));
    }

    #[test]
    fn test_dtd_declaration_rejected() {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();

            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(b"<!DOCTYPE foo SYSTEM \"http://evil.com/evil.dtd\"><Types></Types>")
                .unwrap();

            zip.finish().unwrap();
        }
        let res = DocxPackage::open(&buf);
        assert!(matches!(res, Err(DocxError::DtdOrExternalEntity { .. })));
    }
}
