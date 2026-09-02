//! Canonical PDF Parser and Safe Subset Engine (WI-0206).
//!
//! Provides:
//! - Typed request contracts (`ParserRequest`, `ParserLimits`)
//! - Canonical in-memory artifact data models (`ParserArtifactData`, `ParsedPageData`, `ParsedBlockData`, `ParsedSpanData`)
//! - Fail-closed error taxonomy (`ParserFailure`)
//! - Unicode NFC text normalization with original evidence preservation & offset mapping
//! - Safe PDF subset parser engine (`PdfSafeParser`)
//! - PDFium bindings over version-pinned PDFium (`pdfium_backend`)

pub mod artifact;
pub mod failure;
pub mod normalization;
pub mod pdf_parser;
pub mod pdfium_backend;
pub mod request;

pub use artifact::{
    PageGeometry, ParsedBlockData, ParsedPageData, ParsedSpanData, ParserArtifactData,
    ParserQualityMetrics, ParserWarning,
};
pub use failure::ParserFailure;
pub use normalization::{
    NormalizationResult, TextWarning, map_normalized_range_to_raw, normalize_text_nfc,
};
pub use pdf_parser::PdfSafeParser;
pub use pdfium_backend::{
    PINNED_PDFIUM_BUILD, PINNED_PDFIUM_MAJOR, PINNED_PDFIUM_VERSION_STR, get_authoritative_pdfium,
    get_pdfium, lock_pdfium, pdfium_version_info, verify_pdfium_library_identity,
    verify_pdfium_library_identity_with_expected,
};
pub use request::{
    DEFAULT_LOCATOR_VERSION, DEFAULT_PARSER_PROFILE_VERSION, DEFAULT_TEXT_NORMALIZATION_VERSION,
    PDF_MAX_PAGES, PDF_MAX_RASTER_MP_PER_PAGE, PDF_MAX_RECURSION_DEPTH,
    PDF_MAX_STREAM_DECOMPRESSED_BYTES, PDF_MAX_TOTAL_DECOMPRESSED_BYTES, ParserLimits,
    ParserRequest,
};
