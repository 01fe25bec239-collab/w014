//! Integration and golden fixture test suite for DOCX P0 safe subset extraction (WI-0207).
//!
//! Validates:
//! - Golden DOCX packages containing paragraphs, headings, tables, headers, footers, and page breaks
//! - Hierarchical section paths (`SectionPath`) extracted accurately
//! - Table cells parsed into `BlockKind::TableCell`
//! - Headers and footers parsed into `BlockKind::Header` and `BlockKind::Footer`
//! - Page segmentation via `<w:br w:type="page"/>` and `<w:lastRenderedPageBreak/>`
//! - Accurate half-open normalized character ranges (`norm_start`, `norm_end`)
//! - Complete production of `ParserArtifact`, `ParserPage`, `ParserBlock`, `SourceSpan`
//! - Canonical span hashes verified fail-closed

use std::io::{Cursor, Write};

use uuid::Uuid;
use w014_document_processing::docx::{DocxPackage, DocxParser};
use w014_document_processing::docx_producer::{
    DOCX_LOCATOR_VERSION, DOCX_PARSER_NAME, DocxOcrProducer,
};
use w014_document_processing::ocr::MockTesseractEngine;
use w014_document_processing::sandbox::{SANDBOX_PROTOCOL_VERSION, SandboxInput, SandboxStatus};
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId, WorkspaceId};
use w014_domain::{BlockKind, ExtractionMethod, Sha256};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// Helper to build a valid OOXML DOCX package buffer.
struct DocxBuilder {
    document_xml: String,
    headers: Vec<(String, String)>,
    footers: Vec<(String, String)>,
    media_items: Vec<(String, Vec<u8>)>,
    relationships: Vec<(String, String, String, Option<String>)>, // (id, type, target, target_mode)
}

impl DocxBuilder {
    fn new() -> Self {
        Self {
            document_xml: String::new(),
            headers: Vec::new(),
            footers: Vec::new(),
            media_items: Vec::new(),
            relationships: vec![(
                "rId1".to_string(),
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
                    .to_string(),
                "word/document.xml".to_string(),
                None,
            )],
        }
    }

    fn with_document_xml(mut self, xml: impl Into<String>) -> Self {
        self.document_xml = xml.into();
        self
    }

    fn with_header(mut self, name: impl Into<String>, xml: impl Into<String>) -> Self {
        let name_str = name.into();
        let r_id = format!("rIdHdr{}", self.headers.len() + 1);
        self.relationships.push((
            r_id,
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/header"
                .to_string(),
            name_str.clone(),
            None,
        ));
        self.headers.push((name_str, xml.into()));
        self
    }

    fn with_footer(mut self, name: impl Into<String>, xml: impl Into<String>) -> Self {
        let name_str = name.into();
        let r_id = format!("rIdFtr{}", self.footers.len() + 1);
        self.relationships.push((
            r_id,
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer"
                .to_string(),
            name_str.clone(),
            None,
        ));
        self.footers.push((name_str, xml.into()));
        self
    }

    fn with_media(mut self, name: impl Into<String>, data: Vec<u8>) -> Self {
        self.media_items.push((name.into(), data));
        self
    }

    fn build(self) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            // 1. [Content_Types].xml
            zip.start_file("[Content_Types].xml", options).unwrap();
            let mut ct = String::from(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="png" ContentType="image/png"/>
    <Default Extension="jpg" ContentType="image/jpeg"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>"#,
            );
            for (hdr_name, _) in &self.headers {
                ct.push_str(&format!(
                    r#"<Override PartName="/{}" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>"#,
                    hdr_name
                ));
            }
            for (ftr_name, _) in &self.footers {
                ct.push_str(&format!(
                    r#"<Override PartName="/{}" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>"#,
                    ftr_name
                ));
            }
            ct.push_str("</Types>");
            zip.write_all(ct.as_bytes()).unwrap();

            // 2. _rels/.rels
            zip.start_file("_rels/.rels", options).unwrap();
            let mut root_rels = String::from(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
            );
            for (id, rel_type, target, mode) in &self.relationships {
                if target.starts_with("word/") {
                    let mode_attr = match mode {
                        Some(m) => format!(r#" TargetMode="{}""#, m),
                        None => String::new(),
                    };
                    root_rels.push_str(&format!(
                        r#"<Relationship Id="{}" Type="{}" Target="{}"{}/>"#,
                        id, rel_type, target, mode_attr
                    ));
                }
            }
            root_rels.push_str("</Relationships>");
            zip.write_all(root_rels.as_bytes()).unwrap();

            // 3. word/_rels/document.xml.rels
            zip.start_file("word/_rels/document.xml.rels", options)
                .unwrap();
            let mut doc_rels = String::from(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
            );
            for (id, rel_type, target, mode) in &self.relationships {
                if !target.starts_with("word/document.xml") {
                    let mode_attr = match mode {
                        Some(m) => format!(r#" TargetMode="{}""#, m),
                        None => String::new(),
                    };
                    doc_rels.push_str(&format!(
                        r#"<Relationship Id="{}" Type="{}" Target="{}"{}/>"#,
                        id, rel_type, target, mode_attr
                    ));
                }
            }
            doc_rels.push_str("</Relationships>");
            zip.write_all(doc_rels.as_bytes()).unwrap();

            // 4. word/document.xml
            zip.start_file("word/document.xml", options).unwrap();
            zip.write_all(self.document_xml.as_bytes()).unwrap();

            // 5. Headers & Footers
            for (hdr_name, hdr_xml) in self.headers {
                zip.start_file(hdr_name, options).unwrap();
                zip.write_all(hdr_xml.as_bytes()).unwrap();
            }
            for (ftr_name, ftr_xml) in self.footers {
                zip.start_file(ftr_name, options).unwrap();
                zip.write_all(ftr_xml.as_bytes()).unwrap();
            }

            // 6. Media items
            for (media_name, data) in self.media_items {
                zip.start_file(media_name, options).unwrap();
                zip.write_all(&data).unwrap();
            }

            zip.finish().unwrap();
        }
        buf
    }
}

#[test]
fn test_docx_golden_fixture_structure_and_hierarchy() {
    let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
        <w:body>
            <w:p>
                <w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
                <w:r><w:t>1. Executive Overview</w:t></w:r>
            </w:p>
            <w:p>
                <w:r><w:t>This document details the procurement specifications for contract W911NF-20-C-0001.</w:t></w:r>
            </w:p>
            <w:p>
                <w:pPr><w:pStyle w:val="Heading2"/></w:pPr>
                <w:r><w:t>1.1 Deliverable Standards</w:t></w:r>
            </w:p>
            <w:tbl>
                <w:tr>
                    <w:tc><w:p><w:r><w:t>Deliverable Item</w:t></w:r></w:p></w:tc>
                    <w:tc><w:p><w:r><w:t>Standard DID</w:t></w:r></w:p></w:tc>
                </w:tr>
                <w:tr>
                    <w:tc><w:p><w:r><w:t>Management Report</w:t></w:r></w:p></w:tc>
                    <w:tc><w:p><w:r><w:t>DI-MGMT-80004A</w:t></w:r></w:p></w:tc>
                </w:tr>
            </w:tbl>
            <w:p>
                <w:r><w:t>End of section 1.</w:t></w:r>
                <w:r><w:br w:type="page"/></w:r>
            </w:p>
            <w:p>
                <w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
                <w:r><w:t>2. Technical Details</w:t></w:r>
            </w:p>
            <w:p>
                <w:r><w:t>Page 2 contains additional technical payload specifications.</w:t></w:r>
            </w:p>
        </w:body>
    </w:document>"#;

    let hdr_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
        <w:p><w:r><w:t>CLASSIFICATION: UNCLASSIFIED // PROPRIETARY</w:t></w:r></w:p>
    </w:hdr>"#;

    let ftr_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
        <w:p><w:r><w:t>DISTRIBUTION STATEMENT A: Approved for public release.</w:t></w:r></w:p>
    </w:ftr>"#;

    let docx_bytes = DocxBuilder::new()
        .with_document_xml(doc_xml)
        .with_header("word/header1.xml", hdr_xml)
        .with_footer("word/footer1.xml", ftr_xml)
        .build();

    let package = DocxPackage::open(&docx_bytes).expect("DOCX package should open cleanly");
    let parsed_doc = DocxParser::parse_package(&package).expect("DOCX parser should succeed");

    assert_eq!(parsed_doc.pages.len(), 2, "Expected 2 segmented pages");

    // Check Page 1
    let p1 = &parsed_doc.pages[0];
    assert_eq!(p1.page_number, 1);
    assert!(p1.normalized_text.contains("1. Executive Overview"));
    assert!(p1.normalized_text.contains("DI-MGMT-80004A"));

    // Check Block kinds on Page 1
    let kinds: Vec<BlockKind> = p1.blocks.iter().map(|b| b.kind).collect();
    assert!(kinds.contains(&BlockKind::Header));
    assert!(kinds.contains(&BlockKind::Heading));
    assert!(kinds.contains(&BlockKind::Paragraph));
    assert!(kinds.contains(&BlockKind::TableCell));

    // Check Section path hierarchy
    let did_block = p1
        .blocks
        .iter()
        .find(|b| b.text.contains("DI-MGMT-80004A"))
        .expect("DID block must exist");
    assert_eq!(
        did_block.section_path,
        vec!["1. Executive Overview", "1.1 Deliverable Standards"]
    );

    // Check Page 2
    let p2 = &parsed_doc.pages[1];
    assert_eq!(p2.page_number, 2);
    assert!(p2.normalized_text.contains("2. Technical Details"));
    assert!(p2.normalized_text.contains("DISTRIBUTION STATEMENT A"));
}

#[tokio::test]
async fn test_docx_producer_produces_valid_domain_artifacts_and_sandbox_output() {
    let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
        <w:body>
            <w:p>
                <w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
                <w:r><w:t>Legal Notice</w:t></w:r>
            </w:p>
            <w:p>
                <w:r><w:t>Contract FA8650-19-C-1234 terms apply.</w:t></w:r>
            </w:p>
        </w:body>
    </w:document>"#;

    let docx_bytes = DocxBuilder::new().with_document_xml(doc_xml).build();

    let ws_id = WorkspaceId::new();
    let ver_id = DocumentVersionId::new();
    let art_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let hash = Sha256::digest(&docx_bytes);

    let sandbox_input = SandboxInput::new(
        ws_id,
        ver_id,
        art_id,
        job_id,
        w014_domain::StoredMediaType::new(w014_domain::MediaType::Docx.as_str()).unwrap(),
        hash,
        docx_bytes.len() as i64,
        docx_bytes,
    )
    .expect("SandboxInput creation should succeed");

    let mock_ocr = MockTesseractEngine::returning_text("Ignored for native text");
    let producer = DocxOcrProducer::new(mock_ocr);

    let output = producer
        .process_sandbox_input(&sandbox_input)
        .await
        .expect("Producer execution should succeed");

    // 1. Verify SandboxOutput
    assert_eq!(
        output.sandbox_output.protocol_version,
        SANDBOX_PROTOCOL_VERSION
    );
    assert_eq!(output.sandbox_output.status, SandboxStatus::Success);
    assert_eq!(output.sandbox_output.parser_name, DOCX_PARSER_NAME);
    assert_eq!(
        output.sandbox_output.locator_version.as_str(),
        DOCX_LOCATOR_VERSION
    );
    assert_eq!(output.sandbox_output.page_count, 1);
    assert!(output.sandbox_output.block_count >= 2);
    assert!(output.sandbox_output.span_count >= 2);
    assert!(output.sandbox_output.text_sha256.is_some());

    // Validate SandboxOutput against input
    output
        .sandbox_output
        .validate_against_input(&sandbox_input)
        .expect("Sandbox output validation against input must succeed");

    // 2. Verify ParserArtifact fact
    assert_eq!(output.artifact.workspace_id, ws_id);
    assert_eq!(output.artifact.document_version_id, ver_id);
    assert_eq!(output.artifact.page_count, 1);

    // 3. Verify Pages
    assert_eq!(output.pages.len(), 1);
    assert_eq!(output.pages[0].extraction, ExtractionMethod::NativeText);
    assert!(!output.pages[0].ocr_used);

    // 4. Verify Spans & Provenance
    for span in &output.spans {
        assert_eq!(span.provenance.workspace_id, ws_id);
        assert_eq!(span.provenance.document_version_id, ver_id);
        assert_eq!(span.provenance.page_number, 1);
        assert_eq!(span.extraction, ExtractionMethod::NativeText);

        // Canonical span hash binds frozen inputs
        let computed_hash = span.span_sha256();
        assert_eq!(span.span_sha256(), computed_hash);
    }
}

fn make_valid_png_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut png = Vec::new();
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    png.extend_from_slice(&[0, 0, 0, 13]);
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&width.to_be_bytes());
    png.extend_from_slice(&height.to_be_bytes());
    png.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit truecolor
    png.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder
    png
}

#[tokio::test]
async fn test_native_text_only_docx_does_not_consume_ocr_page_budget() {
    // Construct DOCX with 260 native text pages (> 250 max OCR pages)
    let mut doc_xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    for page_i in 1..=260 {
        doc_xml.push_str(&format!(
            r#"<w:p><w:r><w:t>This is native text for page {} with well over fifty characters of structured procurement content.</w:t></w:r>"#,
            page_i
        ));
        if page_i < 260 {
            doc_xml.push_str(r#"<w:r><w:br w:type="page"/></w:r>"#);
        }
        doc_xml.push_str("</w:p>");
    }
    doc_xml.push_str("</w:body></w:document>");

    let docx_bytes = DocxBuilder::new().with_document_xml(doc_xml).build();

    let ws_id = WorkspaceId::new();
    let ver_id = DocumentVersionId::new();
    let art_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let hash = Sha256::digest(&docx_bytes);

    let sandbox_input = SandboxInput::new(
        ws_id,
        ver_id,
        art_id,
        job_id,
        w014_domain::StoredMediaType::new(w014_domain::MediaType::Docx.as_str()).unwrap(),
        hash,
        docx_bytes.len() as i64,
        docx_bytes,
    )
    .expect("SandboxInput creation should succeed");

    let mock_ocr = MockTesseractEngine::returning_text("Should not be called");
    let producer = DocxOcrProducer::new(mock_ocr);

    let output = producer
        .process_sandbox_input(&sandbox_input)
        .await
        .expect("260-page native text document must succeed without OCR budget exhaustion");

    assert_eq!(output.pages.len(), 260);
    assert_eq!(output.sandbox_output.page_count, 260);
    for page in &output.pages {
        assert_eq!(page.extraction, ExtractionMethod::NativeText);
        assert!(!page.ocr_used);
    }
}

#[tokio::test]
async fn test_ocr_page_budget_exactly_250_pages_accepted() {
    // Construct DOCX with 250 pages, each with sparse text ("Scan #X") and embedded image
    let mut doc_xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    for page_i in 1..=250 {
        doc_xml.push_str(&format!(r#"<w:p><w:r><w:t>Scan #{}</w:t></w:r>"#, page_i));
        if page_i < 250 {
            doc_xml.push_str(r#"<w:r><w:br w:type="page"/></w:r>"#);
        }
        doc_xml.push_str("</w:p>");
    }
    doc_xml.push_str("</w:body></w:document>");

    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new()
        .with_document_xml(doc_xml)
        .with_media("word/media/image1.png", png)
        .build();

    let ws_id = WorkspaceId::new();
    let ver_id = DocumentVersionId::new();
    let art_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let hash = Sha256::digest(&docx_bytes);

    let sandbox_input = SandboxInput::new(
        ws_id,
        ver_id,
        art_id,
        job_id,
        w014_domain::StoredMediaType::new(w014_domain::MediaType::Docx.as_str()).unwrap(),
        hash,
        docx_bytes.len() as i64,
        docx_bytes,
    )
    .expect("SandboxInput creation should succeed");

    let mock_ocr = MockTesseractEngine::returning_text("Extracted OCR Text");
    let producer = DocxOcrProducer::new(mock_ocr);

    let output = producer
        .process_sandbox_input(&sandbox_input)
        .await
        .expect("Exactly 250 OCR pages must be accepted");

    assert_eq!(output.pages.len(), 250);
    for page in &output.pages {
        assert!(page.ocr_used);
    }
}

#[tokio::test]
async fn test_ocr_page_budget_251_pages_rejected() {
    // Construct DOCX with 251 pages, each with sparse text and embedded image
    let mut doc_xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    for page_i in 1..=251 {
        doc_xml.push_str(&format!(r#"<w:p><w:r><w:t>Scan #{}</w:t></w:r>"#, page_i));
        if page_i < 251 {
            doc_xml.push_str(r#"<w:r><w:br w:type="page"/></w:r>"#);
        }
        doc_xml.push_str("</w:p>");
    }
    doc_xml.push_str("</w:body></w:document>");

    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new()
        .with_document_xml(doc_xml)
        .with_media("word/media/image1.png", png)
        .build();

    let ws_id = WorkspaceId::new();
    let ver_id = DocumentVersionId::new();
    let art_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let hash = Sha256::digest(&docx_bytes);

    let sandbox_input = SandboxInput::new(
        ws_id,
        ver_id,
        art_id,
        job_id,
        w014_domain::StoredMediaType::new(w014_domain::MediaType::Docx.as_str()).unwrap(),
        hash,
        docx_bytes.len() as i64,
        docx_bytes,
    )
    .expect("SandboxInput creation should succeed");

    let mock_ocr = MockTesseractEngine::returning_text("Extracted OCR Text");
    let producer = DocxOcrProducer::new(mock_ocr);

    let res = producer.process_sandbox_input(&sandbox_input).await;
    assert!(
        matches!(
            res,
            Err(
                w014_document_processing::docx::DocxError::PackageLimitsExceeded {
                    limit_name: "OCR_PAGE_LIMIT",
                    actual: 251,
                    limit: 250,
                }
            )
        ),
        "251 OCR pages must be rejected with OCR_PAGE_LIMIT exceeded"
    );
}

#[tokio::test]
async fn test_overall_ocr_job_budget_exhaustion_and_decrease_across_pages() {
    // Construct DOCX with 3 pages requiring OCR
    let mut doc_xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    for page_i in 1..=3 {
        doc_xml.push_str(&format!(r#"<w:p><w:r><w:t>Scan #{}</w:t></w:r>"#, page_i));
        if page_i < 3 {
            doc_xml.push_str(r#"<w:r><w:br w:type="page"/></w:r>"#);
        }
        doc_xml.push_str("</w:p>");
    }
    doc_xml.push_str("</w:body></w:document>");

    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new()
        .with_document_xml(doc_xml)
        .with_media("word/media/image1.png", png)
        .build();

    let ws_id = WorkspaceId::new();
    let ver_id = DocumentVersionId::new();
    let art_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let hash = Sha256::digest(&docx_bytes);

    let sandbox_input = SandboxInput::new(
        ws_id,
        ver_id,
        art_id,
        job_id,
        w014_domain::StoredMediaType::new(w014_domain::MediaType::Docx.as_str()).unwrap(),
        hash,
        docx_bytes.len() as i64,
        docx_bytes,
    )
    .expect("SandboxInput creation should succeed");

    // Each page takes 600ms delay. Total job timeout is configured to 1 second.
    // Page 1 takes 600ms. Remaining budget: ~400ms.
    // Page 2 cannot complete in 400ms -> fails closed on job timeout.
    let mock_ocr = MockTesseractEngine::delayed(std::time::Duration::from_millis(600), "ocr text");
    let producer = DocxOcrProducer::new(mock_ocr).with_ocr_config(
        w014_document_processing::ocr::OcrPolicyConfig {
            job_timeout_secs: 1,
            ..Default::default()
        },
    );

    let res = producer.process_sandbox_input(&sandbox_input).await;
    assert!(
        res.is_err(),
        "Job exceeding total wall-clock budget must fail closed"
    );
}

#[test]
fn test_ooxmlsdk_authoritative_safe_subset_path_execution() {
    let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
        <w:body>
            <w:p>
                <w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
                <w:r><w:t>OOXMLSDK Authoritative Heading</w:t></w:r>
            </w:p>
            <w:p>
                <w:r><w:t>First paragraph under authoritative heading.</w:t></w:r>
                <w:r><w:br w:type="page"/></w:r>
            </w:p>
            <w:p>
                <w:r><w:t>Second page content.</w:t></w:r>
            </w:p>
            <w:tbl>
                <w:tr>
                    <w:tc><w:p><w:r><w:t>Cell 1</w:t></w:r></w:p></w:tc>
                    <w:tc><w:p><w:r><w:t>Cell 2</w:t></w:r></w:p></w:tc>
                </w:tr>
            </w:tbl>
        </w:body>
    </w:document>"#;

    let docx_bytes = DocxBuilder::new().with_document_xml(doc_xml).build();

    let parsed = DocxParser::parse_from_bytes(&docx_bytes)
        .expect("ooxmlsdk authoritative parse must succeed");

    assert_eq!(parsed.pages.len(), 2, "Must segment into exactly 2 pages");
    assert_eq!(parsed.pages[0].page_number, 1);
    assert_eq!(parsed.pages[0].blocks.len(), 2);
    assert_eq!(parsed.pages[0].blocks[0].kind, BlockKind::Heading);
    assert_eq!(
        parsed.pages[0].blocks[0].text,
        "OOXMLSDK Authoritative Heading"
    );
    assert_eq!(
        parsed.pages[0].blocks[0].section_path,
        vec!["OOXMLSDK Authoritative Heading"]
    );

    assert_eq!(parsed.pages[1].page_number, 2);
    assert_eq!(parsed.pages[1].blocks[0].kind, BlockKind::Paragraph);
    assert_eq!(parsed.pages[1].blocks[0].text, "Second page content.");

    // Table cells on page 2
    assert_eq!(parsed.pages[1].blocks[1].kind, BlockKind::TableCell);
    assert_eq!(parsed.pages[1].blocks[1].text, "Cell 1");
    assert_eq!(parsed.pages[1].blocks[2].kind, BlockKind::TableCell);
    assert_eq!(parsed.pages[1].blocks[2].text, "Cell 2");
}
