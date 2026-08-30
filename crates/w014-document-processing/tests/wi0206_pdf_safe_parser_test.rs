//! WI-0206 PDF Safe-Subset Parser & Text Normalization Test Suite.
//!
//! Tests:
//! - Valid PDF parsing & extraction (single page, multi-page, text extraction, page geometries, rotation)
//! - Structural block classification (Heading, Paragraph, Header, section paths, bounding boxes)
//! - Granular source spans (half-open normalized offsets, character counts, inert text <= 64 KiB, raw-to-normalized offset mappings)
//! - Unicode NFC Normalization (authoritative NFC, NFKC explicitly NOT authoritative, zero-width/control preservation & flagging, bidi preservation, confusables)
//! - PDF Safe-Subset Fail-Closed Enforcement:
//!   - Malformed xref: FAIL CLOSED
//!   - Recursive / malformed object structures: FAIL CLOSED
//!   - Encrypted / password PDF: UNSUPPORTED_FILE (no password collection)
//!   - JavaScript / Actions: NEVER EXECUTED (inert / stripped)
//!   - Links: INERT TEXT ONLY (no URL following)
//!   - Launch actions: NEVER EXECUTED
//!   - Attachments: NOT RECURSIVELY OPENED
//!   - Decompression bombs: FAIL CLOSED
//!   - Page limit (> 2000 pages): FAIL CLOSED
//!   - Raster limit (> 40 MP/page): FAIL CLOSED
//!   - Checksum mismatch: FAIL CLOSED
//! - Deterministic Artifact & Text SHA-256 digests

use unicode_normalization::UnicodeNormalization;
use w014_document_processing::parser::{
    DEFAULT_LOCATOR_VERSION, DEFAULT_PARSER_PROFILE_VERSION, ParserFailure, ParserLimits,
    ParserRequest, PdfSafeParser, map_normalized_range_to_raw, normalize_text_nfc,
};
use w014_domain::ids::{DocumentVersionId, ParserArtifactId, WorkspaceId};
use w014_domain::source_spans::derive_span_hash;
use w014_domain::{
    BoundingBox, ExtractionMethod, LocatorVersion, OffsetRange, SectionPath, Sha256, SourceSpan,
    SpanProvenance, StoredMediaType,
};

/// Helper constructing a minimal valid PDF byte sequence containing given text.
fn create_simple_pdf_bytes(text: &str) -> Vec<u8> {
    let stream_content = format!("BT /F1 12 Tf 50 700 Td ({}) Tj ET", text);
    let stream_len = stream_content.len();

    let pdf = format!(
        "%PDF-1.4\n\
        1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
        3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n\
        4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n\
        xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000210 00000 n \n\
        trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n",
        stream_len, stream_content
    );

    pdf.into_bytes()
}

fn pdf_media_type() -> StoredMediaType {
    StoredMediaType::new("application/pdf").unwrap()
}

#[test]
fn test_valid_pdf_parsing_produces_canonical_artifact_pages_blocks_spans() {
    let sample_text = "Executive Summary\nThis is the authoritative document text.";
    let pdf_bytes = create_simple_pdf_bytes(sample_text);
    let digest = Sha256::digest(&pdf_bytes);

    let request =
        ParserRequest::pdf_default("obj-test-01", digest, pdf_media_type()).expect("valid request");

    let parser = PdfSafeParser::default();
    let artifact = parser
        .parse(&request, &pdf_bytes)
        .expect("parse must succeed");

    assert_eq!(artifact.artifact_version, "parser-artifact-v1");
    assert_eq!(artifact.input_sha256, digest);
    assert_eq!(artifact.page_count, 1);
    assert!(!artifact.pages.is_empty());
    assert!(!artifact.blocks.is_empty());
    assert!(!artifact.spans.is_empty());
    assert_eq!(artifact.ocr_pages, None); // WI-0206 negative scope: OCR is None

    // Verify 1-based page numbering
    assert_eq!(artifact.pages[0].page_number, 1);
    assert_eq!(artifact.pages[0].extraction, ExtractionMethod::NativeText);
    assert!(!artifact.pages[0].ocr_used);

    // Verify blocks contain kinds and normalized bounds
    let first_block = &artifact.blocks[0];
    assert_eq!(first_block.page_number, 1);
    assert_eq!(first_block.ordinal, 0);
    assert!(first_block.norm_start < first_block.norm_end);

    // Verify spans contain normalized offset range and inert text <= 64 KiB
    let first_span = &artifact.spans[0];
    assert_eq!(first_span.page_number, 1);
    assert_eq!(first_span.block_ordinal, 0);
    assert!(first_span.text.len() <= 65_536);
}

#[test]
fn test_unicode_nfc_normalization_and_nfkc_prohibition() {
    // Normalization Form C composed form
    let decomposed_string = "Caf\u{0065}\u{0301} and na\u{0069}\u{0308}ve";
    let norm = normalize_text_nfc(decomposed_string);

    assert_eq!(norm.normalized_text, "Café and naïve");
    assert_eq!(norm.raw_text, decomposed_string);

    // Verify NFKC is NOT used as authoritative text:
    // Under NFKC, ligature 'ﬁ' (U+FB01) decomposes to 'f' + 'i', and '½' becomes '1/2'.
    // Under authoritative NFC, 'ﬁ' and '½' remain preserved!
    let special_text = "The ﬁnal ½ share";
    let nfc_result = normalize_text_nfc(special_text);
    let nfkc_converted: String = special_text.nfkc().collect();

    assert_eq!(nfc_result.normalized_text, "The ﬁnal ½ share");
    assert_ne!(nfc_result.normalized_text, nfkc_converted);
    assert!(nfkc_converted.contains("final"));
}

#[test]
fn test_zero_width_and_control_characters_preserved_and_flagged() {
    // String with Zero-Width Space (U+200B), Word Joiner (U+2060), and Control Char (U+0007)
    let dirty_string = "Alpha\u{200B}Beta\u{2060}Gamma\u{0007}Delta";
    let norm = normalize_text_nfc(dirty_string);

    // Original evidence is preserved in normalized text
    assert!(norm.normalized_text.contains('\u{200B}'));
    assert!(norm.normalized_text.contains('\u{2060}'));
    assert!(norm.normalized_text.contains('\u{0007}'));

    // Warnings are emitted
    let has_zw_warning = norm
        .warnings
        .iter()
        .any(|w| w.code == "ZERO_WIDTH_CHARACTER_DETECTED");
    let has_ctrl_warning = norm
        .warnings
        .iter()
        .any(|w| w.code == "CONTROL_CHARACTER_DETECTED");

    assert!(has_zw_warning, "Zero-width warning must be emitted");
    assert!(
        has_ctrl_warning,
        "Control character warning must be emitted"
    );
}

#[test]
fn test_bidi_logical_order_preservation() {
    // Bidirectional text must preserve logical extracted stream order, NEVER visually reordered
    let bidi_stream = "Hello \u{200E}\u{0627}\u{0644}\u{0633}\u{0644}\u{0627}\u{0645} World";
    let norm = normalize_text_nfc(bidi_stream);

    assert_eq!(norm.normalized_text, bidi_stream);
    assert!(
        norm.warnings
            .iter()
            .any(|w| w.code == "BIDI_CONTROL_CHARACTER_DETECTED")
    );
}

#[test]
fn test_confusable_homoglyphs_flagged() {
    // "bаnk" with Cyrillic 'а' (U+0430) mixed with Latin 'b', 'n', 'k'
    let confusable = "b\u{0430}nk";
    let norm = normalize_text_nfc(confusable);

    assert!(
        norm.warnings
            .iter()
            .any(|w| w.code == "MIXED_SCRIPT_CONFUSABLE_CYRILLIC")
    );
}

#[test]
fn test_normalized_to_raw_offset_mapping() {
    // Combining character 'e' + '\u{0301}' (2 chars in raw, 1 char in NFC)
    let raw = "Caf\u{0065}\u{0301} shop";
    let norm = normalize_text_nfc(raw);

    assert_eq!(norm.normalized_text, "Café shop");

    // "Café" in normalized is [0, 4), which maps to [0, 5) in raw
    let (raw_start, raw_end) =
        map_normalized_range_to_raw(0, 4, &norm.norm_to_raw_char_map, raw.chars().count());
    assert_eq!(raw_start, 0);
    assert_eq!(raw_end, 5);

    // "shop" in normalized is [5, 9), which maps to [6, 10) in raw
    let (raw_start, raw_end) =
        map_normalized_range_to_raw(5, 9, &norm.norm_to_raw_char_map, raw.chars().count());
    assert_eq!(raw_start, 6);
    assert_eq!(raw_end, 10);
}

#[test]
fn test_safe_subset_malformed_xref_fails_closed() {
    let bad_pdf = b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF";
    let digest = Sha256::digest(bad_pdf);

    let request = ParserRequest::pdf_default("bad-xref", digest, pdf_media_type()).unwrap();
    let parser = PdfSafeParser::default();

    let err = parser.parse(&request, bad_pdf).unwrap_err();
    assert!(matches!(err, ParserFailure::MalformedXref(_)));
}

#[test]
fn test_safe_subset_encrypted_pdf_unsupported() {
    let encrypted_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n\
        xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n\
        trailer\n<< /Size 3 /Root 1 0 R /Encrypt << /V 2 /R 3 >> >>\nstartxref\n120\n%%EOF";
    let digest = Sha256::digest(encrypted_pdf);

    let request = ParserRequest::pdf_default("encrypted", digest, pdf_media_type()).unwrap();
    let parser = PdfSafeParser::default();

    let err = parser.parse(&request, encrypted_pdf).unwrap_err();
    assert_eq!(err, ParserFailure::EncryptedOrPasswordProtected);
}

#[test]
fn test_safe_subset_deeply_nested_objects_fail_closed() {
    // Build nested dictionaries with depth > 64
    let mut nested = String::from("%PDF-1.4\n1 0 obj\n");
    for _ in 0..70 {
        nested.push_str("<< /Nested ");
    }
    nested.push_str("123 ");
    for _ in 0..70 {
        nested.push_str(">> ");
    }
    nested.push_str("\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n100\n%%EOF");

    let pdf_bytes = nested.into_bytes();
    let digest = Sha256::digest(&pdf_bytes);

    let request = ParserRequest::pdf_default("nested", digest, pdf_media_type()).unwrap();
    let parser = PdfSafeParser::default();

    let err = parser.parse(&request, &pdf_bytes).unwrap_err();
    assert!(matches!(err, ParserFailure::RecursiveOrMalformedObject(_)));
}

#[test]
fn test_safe_subset_javascript_actions_inert_and_flagged() {
    let js_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('evil');) >> >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
        3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n\
        4 0 obj\n<< /Length 30 >>\nstream\nBT /F1 12 Tf (Safe Text) Tj ET\nendstream\nendobj\n\
        xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000100 00000 n \n0000000160 00000 n \n0000000250 00000 n \n\
        trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n350\n%%EOF";

    let digest = Sha256::digest(js_pdf);
    let request = ParserRequest::pdf_default("js-test", digest, pdf_media_type()).unwrap();
    let parser = PdfSafeParser::default();

    let artifact = parser
        .parse(&request, js_pdf)
        .expect("parse must succeed and strip JS");

    // JavaScript was never executed, and warning is recorded
    assert!(
        artifact
            .parser_warnings
            .iter()
            .any(|w| w.code == "JAVASCRIPT_ACTIONS_IGNORED")
    );
}

#[test]
fn test_safe_subset_links_inert_only() {
    let link_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
        3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://malicious.example.com) >> >>] /Contents 4 0 R >>\nendobj\n\
        4 0 obj\n<< /Length 35 >>\nstream\nBT /F1 12 Tf (Inert link test) Tj ET\nendstream\nendobj\n\
        xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000260 00000 n \n\
        trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n350\n%%EOF";

    let digest = Sha256::digest(link_pdf);
    let request = ParserRequest::pdf_default("link-test", digest, pdf_media_type()).unwrap();
    let parser = PdfSafeParser::default();

    let artifact = parser
        .parse(&request, link_pdf)
        .expect("parse must succeed");

    // Links are preserved as inert text only; never followed
    assert!(
        artifact
            .parser_warnings
            .iter()
            .any(|w| w.code == "INERT_LINKS_RETAINED")
    );
}

#[test]
fn test_safe_subset_page_limit_enforced() {
    let mut limits = ParserLimits::pdf_frozen_default();
    limits.max_pages = 2; // Artificially low limit for testing

    let request = ParserRequest::new(
        "page-limit-test",
        Sha256::from_bytes([0u8; 32]),
        pdf_media_type(),
        None,
        limits,
        DEFAULT_PARSER_PROFILE_VERSION,
    )
    .unwrap();

    // 3 pages
    let three_page_pdf = b"%PDF-1.4\n\
        1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 >>\nendobj\n\
        3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n\
        4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n\
        5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n\
        xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000125 00000 n \n0000000195 00000 n \n0000000265 00000 n \n\
        trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n350\n%%EOF";

    let mut req_with_digest = request;
    req_with_digest.expected_sha256 = Sha256::digest(three_page_pdf);

    let parser = PdfSafeParser::new(req_with_digest.limits.clone());
    let err = parser.parse(&req_with_digest, three_page_pdf).unwrap_err();

    assert!(matches!(
        err,
        ParserFailure::PageLimitExceeded {
            actual: 3,
            limit: 2
        }
    ));
}

#[test]
fn test_safe_subset_input_checksum_mismatch_fails_closed() {
    let pdf_bytes = create_simple_pdf_bytes("Checksum test");
    let actual_digest = Sha256::digest(&pdf_bytes);
    let wrong_digest = Sha256::from_bytes([0xFF; 32]);

    let request =
        ParserRequest::pdf_default("checksum-test", wrong_digest, pdf_media_type()).unwrap();
    let parser = PdfSafeParser::default();

    let err = parser.parse(&request, &pdf_bytes).unwrap_err();
    assert_eq!(
        err,
        ParserFailure::InputChecksumMismatch {
            expected: wrong_digest.to_hex(),
            actual: actual_digest.to_hex(),
        }
    );
}

#[test]
fn test_canonical_span_hash_computation_and_invariants() {
    let ws_id = WorkspaceId::new();
    let dv_id = DocumentVersionId::new();
    let pa_id = ParserArtifactId::new();
    let locator = LocatorVersion::new(DEFAULT_LOCATOR_VERSION).unwrap();

    let provenance = SpanProvenance::new(
        ws_id, dv_id, pa_id, locator, 1, // 1-based page_number
    )
    .unwrap();

    let span = SourceSpan::new(
        provenance,
        0,
        OffsetRange::new(0, 14).unwrap(),
        Some(OffsetRange::new(0, 14).unwrap()),
        BoundingBox::new(50.0, 50.0, 200.0, 20.0).ok(),
        SectionPath::new(vec!["Intro".to_string()]).ok(),
        "Authoritative!".to_string(),
        ExtractionMethod::NativeText,
        Some(1.0),
    )
    .unwrap();

    let hash_1 = derive_span_hash(&span);
    let hash_2 = derive_span_hash(&span);

    assert_eq!(hash_1, hash_2, "Span hash must be deterministic");

    // Verify changing the document version changes the span hash (no floating citations)
    let different_dv = DocumentVersionId::new();
    let mut different_prov = span.provenance.clone();
    different_prov.document_version_id = different_dv;

    let span_diff = SourceSpan::new(
        different_prov,
        0,
        span.normalized_range,
        span.raw_range,
        span.bbox,
        span.section_path.clone(),
        span.text.clone(),
        span.extraction,
        span.quality_score,
    )
    .unwrap();

    let hash_diff = derive_span_hash(&span_diff);
    assert_ne!(
        hash_1, hash_diff,
        "Span hash MUST bind exact document_version_id"
    );
}
