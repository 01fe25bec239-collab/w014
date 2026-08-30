//! Rust-controlled OCR fallback, Tesseract orchestration, and conflict policy (WI-0207).

pub mod config;
pub mod error;
pub mod image_inspector;
pub mod precedence;
pub mod provenance;
pub mod tesseract;

pub use config::{
    LOW_TEXT_CHAR_THRESHOLD, MAX_JOB_WALL_CLOCK_SECS, MAX_NATIVE_OCR_EDIT_DISTANCE_RATIO,
    MAX_OCR_PAGES, MAX_PAGE_DURATION_SECS, MAX_RASTER_PIXELS, OcrPolicyConfig, TARGET_DPI,
};
pub use error::OcrError;
pub use image_inspector::{ImageDimensions, inspect_and_validate_raster};
pub use precedence::{
    ConflictEvaluationResult, CriticalToken, CriticalTokenType, ReviewIntegritySignal,
    evaluate_native_vs_ocr, extract_critical_tokens, levenshtein_distance,
};
pub use provenance::SpanProvenanceFactory;
pub use tesseract::{
    MockOcrBehavior, MockTesseractEngine, OcrEngine, OcrPageOutput, ProcessTesseractEngine,
};
