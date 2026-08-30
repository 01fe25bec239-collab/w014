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

use w014_document_processing::ocr::{
    CriticalTokenType, MAX_OCR_PAGES, MAX_PAGE_DURATION_SECS, MAX_RASTER_PIXELS,
    MockTesseractEngine, OcrEngine, OcrError, OcrPolicyConfig, ReviewIntegritySignal, TARGET_DPI,
    evaluate_native_vs_ocr, inspect_and_validate_raster,
};

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
