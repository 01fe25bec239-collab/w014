//! Typed parser failure domain for safe PDF subset processing (WI-0206).
//!
//! Fails closed on any security, malformation, or resource ceiling violation:
//! - Malformed xref: FAIL CLOSED
//! - Recursive / cyclic objects: FAIL CLOSED
//! - Encrypted / password PDF: UNSUPPORTED_FILE (no password collection)
//! - Decompression bomb: FAIL CLOSED
//! - Oversized native decode: FAIL CLOSED
//! - Raster limit exceeded (> 40 MP/page): FAIL CLOSED
//! - Page limit exceeded (> 2000 pages): FAIL CLOSED
//! - Corrupted / malformed streams: FAIL CLOSED

use serde::{Deserialize, Serialize};

use crate::sandbox::output::SandboxStatus;

/// Typed parser execution failure domain.
#[derive(Debug, Clone, PartialEq, thiserror::Error, Serialize, Deserialize)]
pub enum ParserFailure {
    /// PDF cross-reference table or stream is corrupt / invalid.
    #[error("Malformed PDF cross-reference table or stream: {0}")]
    MalformedXref(String),

    /// PDF contains recursive object references or exceeds maximum nesting depth.
    #[error("Recursive or malformed PDF object structure: {0}")]
    RecursiveOrMalformedObject(String),

    /// PDF is encrypted or requires a password (unsupported safe subset).
    #[error("Encrypted or password-protected PDF is unsupported")]
    EncryptedOrPasswordProtected,

    /// Stream decompression exceeded safety threshold (decompression bomb defense).
    #[error("Decompression bomb detected or decompression limit exceeded: {0}")]
    DecompressionBomb(String),

    /// Native decode size exceeded memory ceiling.
    #[error("Oversized native decode exceeds memory ceiling: {0}")]
    OversizedNativeDecode(String),

    /// Page count exceeds the frozen maximum (<= 2000 pages).
    #[error("Page count {actual} exceeds maximum page limit {limit}")]
    PageLimitExceeded { actual: u32, limit: u32 },

    /// Page raster resolution exceeds the frozen ceiling (<= 40 MP/page).
    #[error("Page raster resolution {actual_mp:.2} MP exceeds limit {limit_mp:.2} MP")]
    RasterLimitExceeded { actual_mp: f64, limit_mp: f64 },

    /// PDF uses unsupported features or incompatible PDF profile.
    #[error("Unsupported PDF feature or profile: {0}")]
    UnsupportedFeature(String),

    /// PDF file structure or content is corrupted.
    #[error("Corrupted PDF document: {0}")]
    CorruptedFile(String),

    /// Input byte checksum did not match declared digest.
    #[error("Input SHA-256 checksum mismatch: expected {expected}, actual {actual}")]
    InputChecksumMismatch { expected: String, actual: String },

    /// I/O error during parser execution.
    #[error("I/O error during parse: {0}")]
    Io(String),

    /// Authoritative PDFium backend is unavailable or not found.
    #[error("Authoritative PDFium backend is unavailable: {0}")]
    PdfiumUnavailable(String),

    /// Authoritative PDFium backend failed to bind or load dynamic library.
    #[error("Authoritative PDFium backend bind failure: {0}")]
    PdfiumBindFailure(String),

    /// Authoritative PDFium backend identity or version could not be verified.
    #[error("Authoritative PDFium identity or version unverifiable: {0}")]
    PdfiumUnverified(String),

    /// PDFium native page text extraction error.
    #[error("PDFium native page text extraction error: {0}")]
    PageTextExtractionFailed(String),

    /// Internal parser execution error.
    #[error("Internal parser failure: {0}")]
    Internal(String),
}

impl ParserFailure {
    /// Maps typed failure to the closed `SandboxStatus` domain.
    #[must_use]
    pub const fn status(&self) -> SandboxStatus {
        match self {
            Self::EncryptedOrPasswordProtected | Self::UnsupportedFeature(_) => {
                SandboxStatus::Unsupported
            }
            Self::MalformedXref(_) | Self::CorruptedFile(_) => SandboxStatus::Corrupted,
            Self::RecursiveOrMalformedObject(_)
            | Self::DecompressionBomb(_)
            | Self::OversizedNativeDecode(_)
            | Self::PageLimitExceeded { .. }
            | Self::RasterLimitExceeded { .. }
            | Self::InputChecksumMismatch { .. }
            | Self::Io(_)
            | Self::PdfiumUnavailable(_)
            | Self::PdfiumBindFailure(_)
            | Self::PdfiumUnverified(_)
            | Self::PageTextExtractionFailed(_)
            | Self::Internal(_) => SandboxStatus::Failed,
        }
    }

    /// Machine-readable failure code string.
    #[must_use]
    pub const fn failure_code(&self) -> &'static str {
        match self {
            Self::MalformedXref(_) => "MALFORMED_XREF",
            Self::RecursiveOrMalformedObject(_) => "RECURSIVE_OBJECT_STRUCTURE",
            Self::EncryptedOrPasswordProtected => "UNSUPPORTED_ENCRYPTED_PDF",
            Self::DecompressionBomb(_) => "DECOMPRESSION_BOMB_DETECTED",
            Self::OversizedNativeDecode(_) => "OVERSIZED_NATIVE_DECODE",
            Self::PageLimitExceeded { .. } => "PAGE_LIMIT_EXCEEDED",
            Self::RasterLimitExceeded { .. } => "RASTER_LIMIT_EXCEEDED",
            Self::UnsupportedFeature(_) => "UNSUPPORTED_PDF_FEATURE",
            Self::CorruptedFile(_) => "CORRUPTED_PDF",
            Self::InputChecksumMismatch { .. } => "INPUT_CHECKSUM_MISMATCH",
            Self::Io(_) => "PARSER_IO_ERROR",
            Self::PdfiumUnavailable(_) => "PDFIUM_UNAVAILABLE",
            Self::PdfiumBindFailure(_) => "PDFIUM_BIND_FAILURE",
            Self::PdfiumUnverified(_) => "PDFIUM_UNVERIFIED",
            Self::PageTextExtractionFailed(_) => "PAGE_TEXT_EXTRACTION_ERROR",
            Self::Internal(_) => "PARSER_INTERNAL_ERROR",
        }
    }

    /// Diagnostic detail message (safe metadata, no hostile payload reflection).
    #[must_use]
    pub fn detail(&self) -> String {
        self.to_string()
    }
}
