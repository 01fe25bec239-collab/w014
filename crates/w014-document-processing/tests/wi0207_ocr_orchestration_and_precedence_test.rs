//! Test suite for OCR orchestration, resource limits, native precedence, and conflict policy (WI-0207).
//!
//! Validates:
//! - Tesseract Rust orchestration (zero Python components)
//! - OCR triggered strictly when scanned/low-text policy is met (< 50 chars native text on page with images)
//! - OCR skipped when native text is dense
//! - Native text preserved separately (never silently overwritten)
//! - Edit distance ratio > 5% triggers ReviewIntegritySignal::EditDistanceExceeded
//! - Critical token mismatch (contract number, legend, revision, DID) triggers ReviewIntegritySignal::CriticalTokenMismatch
//! - Resource limits: 250 pages, 15s/page, 30m job, 40 MP raster, 300 DPI
//! - Full provenance preserved for OCR spans (`raw_range = None`, `extraction = ExtractionMethod::Ocr`)
//! - Fail closed on error: NO GUESS, NO AI FALLBACK

use std::time::Duration;

use w014_document_processing::ocr::{
    CriticalTokenType, MAX_JOB_WALL_CLOCK_SECS, MAX_OCR_PAGES, MAX_PAGE_DURATION_SECS,
    MAX_RASTER_PIXELS, MockTesseractEngine, OcrEngine, OcrError, OcrPolicyConfig,
    ProcessTesseractEngine, ReviewIntegritySignal, SpanProvenanceFactory, TARGET_DPI,
    evaluate_native_vs_ocr, inspect_and_validate_raster,
};
use w014_domain::ids::{DocumentVersionId, ParserArtifactId, WorkspaceId};
use w014_domain::{ExtractionMethod, LocatorVersion, OffsetRange};

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

#[test]
fn test_ocr_resource_limits_constants() {
    assert_eq!(MAX_OCR_PAGES, 250);
    assert_eq!(MAX_PAGE_DURATION_SECS, 15);
    assert_eq!(MAX_RASTER_PIXELS, 40_000_000);
    assert_eq!(TARGET_DPI, 300);
}

#[test]
fn test_raster_within_40mp_allowed() {
    // 6000 x 6000 = 36 MP <= 40 MP
    let img = make_valid_png_bytes(6000, 6000);
    let res = inspect_and_validate_raster(&img);
    assert!(res.is_ok());
    let dims = res.unwrap();
    assert_eq!(dims.total_pixels, 36_000_000);
}

#[test]
fn test_raster_exceeding_40mp_rejected() {
    // 7000 x 6000 = 42 MP > 40 MP
    let img = make_valid_png_bytes(7000, 6000);
    let res = inspect_and_validate_raster(&img);
    assert!(
        matches!(res, Err(OcrError::RasterExceeded { pixels, limit }) if pixels == 42_000_000 && limit == 40_000_000)
    );
}

#[test]
fn test_ocr_policy_skips_dense_native_text() {
    let config = OcrPolicyConfig::default();
    let dense_text =
        "This is a comprehensive paragraph with well over fifty characters of structured text.";
    assert!(!config.should_trigger_ocr(dense_text.len(), false));
    assert!(!config.should_trigger_ocr(dense_text.len(), true));
}

#[test]
fn test_ocr_policy_triggers_on_low_text_with_images() {
    let config = OcrPolicyConfig::default();
    let sparse_text = "Scan #1";
    assert!(!config.should_trigger_ocr(sparse_text.len(), false)); // no images -> don't trigger
    assert!(config.should_trigger_ocr(sparse_text.len(), true)); // images + low text -> trigger!
}

#[test]
fn test_edit_distance_calculation_and_threshold_signal() {
    let native = "Agreement between Party A and Party B for services.";
    // Slight typo (< 5%)
    let close_ocr = "Agreement between Party A and Party B for serviecs.";
    let res_close = evaluate_native_vs_ocr(native, Some(close_ocr), 1, Some(0.95));
    assert!(
        !res_close
            .signals
            .iter()
            .any(|s| matches!(s, ReviewIntegritySignal::EditDistanceExceeded { .. })),
        "Edit distance below 5% should not trigger signal"
    );

    // Heavy alteration (> 5%)
    let drifted_ocr = "Agreement between Party X and Party Z for goods.";
    let res_drifted = evaluate_native_vs_ocr(native, Some(drifted_ocr), 1, Some(0.95));
    assert!(
        res_drifted
            .signals
            .iter()
            .any(|s| matches!(s, ReviewIntegritySignal::EditDistanceExceeded { .. })),
        "Edit distance above 5% must trigger signal"
    );
}

#[test]
fn test_critical_tokens_mismatch_signals_review() {
    let native = "Contract FA8650-19-C-1234 Revision Rev-B DISTRIBUTION STATEMENT A";
    let ocr = "Contract FA8650-19-C-9999 Revision Rev-C DISTRIBUTION STATEMENT B";

    let res = evaluate_native_vs_ocr(native, Some(ocr), 1, Some(0.9));
    assert!(res.requires_review);

    let contract_mismatch = res.signals.iter().any(|s| {
        matches!(
            s,
            ReviewIntegritySignal::CriticalTokenMismatch {
                token_type: CriticalTokenType::ContractNumber,
                ..
            }
        )
    });
    let rev_mismatch = res.signals.iter().any(|s| {
        matches!(
            s,
            ReviewIntegritySignal::CriticalTokenMismatch {
                token_type: CriticalTokenType::Revision,
                ..
            }
        )
    });
    let legend_mismatch = res.signals.iter().any(|s| {
        matches!(
            s,
            ReviewIntegritySignal::CriticalTokenMismatch {
                token_type: CriticalTokenType::LegendField,
                ..
            }
        )
    });

    assert!(
        contract_mismatch,
        "Contract number mismatch must be flagged"
    );
    assert!(rev_mismatch, "Revision mismatch must be flagged");
    assert!(legend_mismatch, "Legend field mismatch must be flagged");
}

#[test]
fn test_critical_token_missing_in_ocr_signals_review() {
    let native = "Governing document: DI-MGMT-80004A standard.";
    let ocr = "Governing document: standard deliverable.";

    let res = evaluate_native_vs_ocr(native, Some(ocr), 1, Some(0.85));
    assert!(res.requires_review);

    let did_mismatch = res.signals.iter().any(|s| {
        matches!(
            s,
            ReviewIntegritySignal::CriticalTokenMismatch {
                token_type: CriticalTokenType::DataIdOrDid,
                ..
            }
        )
    });
    assert!(did_mismatch, "Missing DID in OCR must be flagged");
}

#[test]
fn test_ocr_job_and_page_limits_ceiling_enforced() {
    let default_config = OcrPolicyConfig::default();
    assert_eq!(default_config.job_timeout_secs, MAX_JOB_WALL_CLOCK_SECS);
    assert_eq!(default_config.page_timeout_secs, MAX_PAGE_DURATION_SECS);
    assert_eq!(default_config.max_pages, MAX_OCR_PAGES);
    assert_eq!(default_config.effective_job_timeout_secs(), 1800);
    assert_eq!(default_config.effective_page_timeout_secs(), 15);
    assert_eq!(default_config.effective_max_pages(), 250);

    // Over-configured values MUST be bounded by frozen constants
    let over_config = OcrPolicyConfig {
        max_pages: 9999,
        page_timeout_secs: 9999,
        job_timeout_secs: 9999,
        max_raster_pixels: 999_999_999,
        target_dpi: 1200,
        low_text_threshold: 50,
    };
    assert_eq!(over_config.effective_max_pages(), 250);
    assert_eq!(over_config.effective_page_timeout_secs(), 15);
    assert_eq!(over_config.effective_job_timeout_secs(), 1800);
    assert_eq!(over_config.effective_max_raster_pixels(), 40_000_000);
    assert_eq!(over_config.effective_target_dpi(), 300);
}

#[cfg(unix)]
#[tokio::test]
async fn test_process_tesseract_timeout_kills_and_reaps_child() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let mut temp_script = tempfile::NamedTempFile::new().unwrap();
    write!(temp_script, "#!/bin/sh\nsleep 60\n").unwrap();
    let script_path = temp_script.path().to_path_buf();

    let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script_path, perms).unwrap();

    let engine = ProcessTesseractEngine::new(&script_path).with_config(OcrPolicyConfig {
        page_timeout_secs: 1,
        ..Default::default()
    });

    let img = make_valid_png_bytes(100, 100);
    let start = std::time::Instant::now();
    let res = engine
        .ocr_image_with_timeout(&img, "image/png", Duration::from_millis(200))
        .await;

    assert!(
        start.elapsed() < Duration::from_secs(5),
        "Subprocess execution must terminate promptly on timeout"
    );
    assert!(
        matches!(res, Err(OcrError::Timeout { .. })),
        "Subprocess timeout must fail closed with OcrError::Timeout"
    );
}

#[tokio::test]
async fn test_mock_tesseract_delayed_execution_bounded_by_max_duration() {
    let mock = MockTesseractEngine::delayed(Duration::from_millis(500), "delayed text");
    let img = make_valid_png_bytes(100, 100);

    // Call with 50ms ceiling < 500ms mock delay -> must time out
    let res = mock
        .ocr_image_with_timeout(&img, "image/png", Duration::from_millis(50))
        .await;
    assert!(matches!(res, Err(OcrError::Timeout { .. })));

    // Call with 1000ms ceiling > 500ms mock delay -> must succeed
    let res_ok = mock
        .ocr_image_with_timeout(&img, "image/png", Duration::from_millis(1000))
        .await;
    assert!(res_ok.is_ok());
    assert_eq!(res_ok.unwrap().raw_text, "delayed text");
}

#[test]
fn test_ocr_provenance_full_fidelity_and_canonical_hash() {
    let ws_id = WorkspaceId::new();
    let doc_ver_id = DocumentVersionId::new();
    let artifact_id = ParserArtifactId::new();
    let loc_ver = LocatorVersion::new("w014-docx-p0-v1").unwrap();

    let factory = SpanProvenanceFactory::new(ws_id, doc_ver_id, artifact_id, loc_ver);

    // OCR span: raw_range is strictly None, extraction is ExtractionMethod::Ocr
    let ocr_span = factory
        .build_ocr_span(
            1,
            0,
            OffsetRange::new(0, 15).unwrap(),
            None,
            "OCR parsed text",
            Some(0.85),
        )
        .unwrap();

    assert_eq!(ocr_span.extraction, ExtractionMethod::Ocr);
    assert_eq!(ocr_span.raw_range, None);
    assert_eq!(ocr_span.provenance.page_number, 1);
    assert_eq!(ocr_span.quality_score, Some(0.85));

    // Native span: raw_range may exist, extraction is ExtractionMethod::NativeText
    let native_span = factory
        .build_native_span(
            1,
            1,
            OffsetRange::new(0, 18).unwrap(),
            Some(OffsetRange::new(100, 118).unwrap()),
            Some(vec!["Section 1".to_string()]),
            "Native parsed text",
        )
        .unwrap();

    assert_eq!(native_span.extraction, ExtractionMethod::NativeText);
    assert_eq!(
        native_span.raw_range,
        Some(OffsetRange::new(100, 118).unwrap())
    );
    assert_eq!(native_span.quality_score, Some(1.0));
}

#[tokio::test]
async fn test_mock_tesseract_timeout_fails_closed() {
    let mock = MockTesseractEngine::timing_out();
    let img = make_valid_png_bytes(100, 100);
    let res = mock.ocr_image(&img, "image/png").await;
    assert!(matches!(res, Err(OcrError::Timeout { .. })));
}

#[tokio::test]
async fn test_mock_tesseract_crash_fails_closed() {
    let mock = MockTesseractEngine::crashing("Tesseract memory allocation fault");
    let img = make_valid_png_bytes(100, 100);
    let res = mock.ocr_image(&img, "image/png").await;
    assert!(matches!(res, Err(OcrError::EngineCrash { .. })));
}
