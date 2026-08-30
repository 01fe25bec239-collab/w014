//! OCR error taxonomy (WI-0207).

use thiserror::Error;

/// Fail-closed error taxonomy for OCR operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OcrError {
    #[error("OCR page count limit exceeded: actual {actual}, maximum allowed {limit}")]
    PageLimitExceeded { actual: u32, limit: u32 },

    #[error("OCR page processing timed out after {elapsed_secs}s (limit {limit_secs}s)")]
    Timeout { elapsed_secs: u64, limit_secs: u64 },

    #[error("Image raster pixel count {pixels} exceeds maximum limit {limit} (40 Megapixels)")]
    RasterExceeded { pixels: u64, limit: u64 },

    #[error("Tesseract engine crashed or terminated with error: {detail}")]
    EngineCrash { detail: String },

    #[error("OCR execution failed ({code}): {detail}")]
    ExecutionFailed { code: String, detail: String },

    #[error("I/O error during OCR execution: {detail}")]
    Io { detail: String },

    #[error("Review integrity signal required: {0}")]
    ReviewSignalRequired(String),
}

impl OcrError {
    /// Returns machine-readable failure code for audit and sandbox results.
    #[must_use]
    pub const fn failure_code(&self) -> &'static str {
        match self {
            Self::PageLimitExceeded { .. } => "OCR_PAGE_LIMIT_EXCEEDED",
            Self::Timeout { .. } => "OCR_TIMEOUT",
            Self::RasterExceeded { .. } => "OCR_RASTER_LIMIT_EXCEEDED",
            Self::EngineCrash { .. } => "OCR_ENGINE_CRASH",
            Self::ExecutionFailed { .. } => "OCR_EXECUTION_FAILED",
            Self::Io { .. } => "OCR_IO_ERROR",
            Self::ReviewSignalRequired(_) => "OCR_REVIEW_SIGNAL_REQUIRED",
        }
    }
}
