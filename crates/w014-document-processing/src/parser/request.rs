//! Typed parser request and bounded limit configurations (WI-0206).
//!
//! Preserves frozen typed request semantics:
//! - Object reference
//! - Expected content SHA-256 digest
//! - Declared MIME media type
//! - Optional document class hint
//! - Hard frozen execution and format bounds (pages <= 2000, raster <= 40 MP/page)
//! - Parser profile version

use serde::{Deserialize, Serialize};
use w014_domain::limits::MAX_PAGE_NUMBER;
use w014_domain::{Sha256, StoredMediaType};

/// Maximum allowed pages in a PDF safe subset document (frozen bound: 2000).
pub const PDF_MAX_PAGES: u32 = 2000;

/// Maximum allowed raster megapixels per page (frozen bound: 40 MP).
pub const PDF_MAX_RASTER_MP_PER_PAGE: f64 = 40.0;

/// Maximum allowed single stream decompressed size (100 MiB).
pub const PDF_MAX_STREAM_DECOMPRESSED_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum allowed total document decompressed size (1 GiB).
pub const PDF_MAX_TOTAL_DECOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;

/// Maximum object recursion / dictionary nesting depth (64).
pub const PDF_MAX_RECURSION_DEPTH: u32 = 64;

/// Canonical default parser profile version.
pub const DEFAULT_PARSER_PROFILE_VERSION: &str = "pdf-safe-v1";

/// Canonical default text normalization version.
pub const DEFAULT_TEXT_NORMALIZATION_VERSION: &str = "nfc-v1";

/// Canonical default span locator version.
pub const DEFAULT_LOCATOR_VERSION: &str = "w014-locator-v1";

/// Hard frozen execution and content limits for document parser execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserLimits {
    /// Maximum allowed pages in document (must be <= 2000).
    pub max_pages: u32,
    /// Maximum allowed raster megapixels per page (must be <= 40.0).
    pub max_raster_mp_per_page: f64,
    /// Maximum single stream decompressed size in bytes.
    pub max_stream_decompressed_bytes: u64,
    /// Maximum total decompressed size in bytes.
    pub max_total_decompressed_bytes: u64,
    /// Maximum object recursion depth.
    pub max_recursion_depth: u32,
    /// Maximum structural blocks allowed per document.
    pub max_blocks: u32,
    /// Maximum source spans allowed per document.
    pub max_spans: u32,
    /// Maximum bytes per single span text (frozen <= 64 KiB).
    pub max_span_text_bytes: usize,
    /// Maximum execution duration in milliseconds (frozen <= 600,000 ms).
    pub max_execution_duration_ms: u64,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self::pdf_frozen_default()
    }
}

impl ParserLimits {
    /// Frozen standard bounds conforming to WI-0206 PDF safe subset rules.
    #[must_use]
    pub const fn pdf_frozen_default() -> Self {
        Self {
            max_pages: PDF_MAX_PAGES,
            max_raster_mp_per_page: PDF_MAX_RASTER_MP_PER_PAGE,
            max_stream_decompressed_bytes: PDF_MAX_STREAM_DECOMPRESSED_BYTES,
            max_total_decompressed_bytes: PDF_MAX_TOTAL_DECOMPRESSED_BYTES,
            max_recursion_depth: PDF_MAX_RECURSION_DEPTH,
            max_blocks: 500_000,
            max_spans: 1_000_000,
            max_span_text_bytes: 65_536,
            max_execution_duration_ms: 600_000,
        }
    }

    /// Validates internal bounds.
    ///
    /// # Errors
    /// Returns error if any ceiling violates the frozen system maxima.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_pages == 0 || self.max_pages > MAX_PAGE_NUMBER {
            return Err(format!(
                "max_pages {} outside allowable range 1..={MAX_PAGE_NUMBER}",
                self.max_pages
            ));
        }
        if self.max_pages > PDF_MAX_PAGES {
            return Err(format!(
                "max_pages {} exceeds frozen PDF ceiling {PDF_MAX_PAGES}",
                self.max_pages
            ));
        }
        if !self.max_raster_mp_per_page.is_finite() || self.max_raster_mp_per_page <= 0.0 {
            return Err("max_raster_mp_per_page must be positive and finite".to_string());
        }
        if self.max_raster_mp_per_page > PDF_MAX_RASTER_MP_PER_PAGE {
            return Err(format!(
                "max_raster_mp_per_page {} exceeds frozen ceiling {PDF_MAX_RASTER_MP_PER_PAGE}",
                self.max_raster_mp_per_page
            ));
        }
        if self.max_span_text_bytes > 65_536 {
            return Err(format!(
                "max_span_text_bytes {} exceeds frozen 64 KiB ceiling",
                self.max_span_text_bytes
            ));
        }
        Ok(())
    }
}

/// Typed request specifying exact parameters for document parser execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParserRequest {
    /// Object storage identifier or reference.
    pub object_ref: String,
    /// Authoritative expected content SHA-256 digest.
    pub expected_sha256: Sha256,
    /// Declared MIME media type.
    pub declared_media_type: StoredMediaType,
    /// Optional document classification hint.
    pub document_class_hint: Option<String>,
    /// Execution and format limits.
    pub limits: ParserLimits,
    /// Parser profile version.
    pub parser_profile_version: String,
}

impl ParserRequest {
    /// Creates a new validated `ParserRequest`.
    ///
    /// # Errors
    /// Returns error if bounds or fields are invalid.
    pub fn new(
        object_ref: impl Into<String>,
        expected_sha256: Sha256,
        declared_media_type: StoredMediaType,
        document_class_hint: Option<String>,
        limits: ParserLimits,
        parser_profile_version: impl Into<String>,
    ) -> Result<Self, String> {
        let obj = object_ref.into();
        if obj.trim().is_empty() {
            return Err("object_ref must be non-empty".to_string());
        }
        let profile = parser_profile_version.into();
        if profile.trim().is_empty() {
            return Err("parser_profile_version must be non-empty".to_string());
        }
        limits.validate()?;
        Ok(Self {
            object_ref: obj,
            expected_sha256,
            declared_media_type,
            document_class_hint,
            limits,
            parser_profile_version: profile,
        })
    }

    /// Creates a standard PDF parser request with frozen default limits.
    pub fn pdf_default(
        object_ref: impl Into<String>,
        expected_sha256: Sha256,
        declared_media_type: StoredMediaType,
    ) -> Result<Self, String> {
        Self::new(
            object_ref,
            expected_sha256,
            declared_media_type,
            None,
            ParserLimits::pdf_frozen_default(),
            DEFAULT_PARSER_PROFILE_VERSION,
        )
    }
}
