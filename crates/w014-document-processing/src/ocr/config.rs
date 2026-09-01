//! OCR resource limits, timeouts, and execution policy configuration (WI-0207).

use serde::{Deserialize, Serialize};

/// Maximum total OCR pages allowed per job (250 pages).
pub const MAX_OCR_PAGES: u32 = 250;

/// Maximum allowed execution duration per page (15 seconds).
pub const MAX_PAGE_DURATION_SECS: u64 = 15;

/// Maximum allowed total OCR job wall clock duration (30 minutes = 1,800 seconds).
pub const MAX_JOB_WALL_CLOCK_SECS: u64 = 1800;

/// Maximum allowed image raster pixels per page (40 Megapixels = 40,000,000 pixels).
pub const MAX_RASTER_PIXELS: u64 = 40_000_000;

/// Target rendering DPI for OCR rasterization (<= 300 DPI).
pub const TARGET_DPI: u32 = 300;

/// Character count threshold below which a page containing images is treated as scanned/low-text.
pub const LOW_TEXT_CHAR_THRESHOLD: usize = 50;

/// Maximum edit distance percentage allowed between normalized native text and OCR text (5% = 0.05).
pub const MAX_NATIVE_OCR_EDIT_DISTANCE_RATIO: f64 = 0.05;

/// Frozen OCR execution policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcrPolicyConfig {
    /// Maximum pages allowed for OCR.
    pub max_pages: u32,
    /// Timeout in seconds per page.
    pub page_timeout_secs: u64,
    /// Overall job timeout in seconds.
    pub job_timeout_secs: u64,
    /// Maximum allowed raster pixels.
    pub max_raster_pixels: u64,
    /// Target rendering DPI.
    pub target_dpi: u32,
    /// Minimum characters required before skipping OCR.
    pub low_text_threshold: usize,
}

impl Default for OcrPolicyConfig {
    fn default() -> Self {
        Self {
            max_pages: MAX_OCR_PAGES,
            page_timeout_secs: MAX_PAGE_DURATION_SECS,
            job_timeout_secs: MAX_JOB_WALL_CLOCK_SECS,
            max_raster_pixels: MAX_RASTER_PIXELS,
            target_dpi: TARGET_DPI,
            low_text_threshold: LOW_TEXT_CHAR_THRESHOLD,
        }
    }
}

impl OcrPolicyConfig {
    /// Returns the effective page count limit, bounded by `MAX_OCR_PAGES` (<= 250).
    #[must_use]
    pub const fn effective_max_pages(&self) -> u32 {
        if self.max_pages > MAX_OCR_PAGES {
            MAX_OCR_PAGES
        } else {
            self.max_pages
        }
    }

    /// Returns the effective per-page timeout in seconds, bounded by `MAX_PAGE_DURATION_SECS` (<= 15s).
    #[must_use]
    pub const fn effective_page_timeout_secs(&self) -> u64 {
        if self.page_timeout_secs > MAX_PAGE_DURATION_SECS {
            MAX_PAGE_DURATION_SECS
        } else {
            self.page_timeout_secs
        }
    }

    /// Returns the effective total job timeout in seconds, bounded by `MAX_JOB_WALL_CLOCK_SECS` (<= 1800s).
    #[must_use]
    pub const fn effective_job_timeout_secs(&self) -> u64 {
        if self.job_timeout_secs > MAX_JOB_WALL_CLOCK_SECS {
            MAX_JOB_WALL_CLOCK_SECS
        } else {
            self.job_timeout_secs
        }
    }

    /// Returns the effective max raster pixels, bounded by `MAX_RASTER_PIXELS` (<= 40 MP).
    #[must_use]
    pub const fn effective_max_raster_pixels(&self) -> u64 {
        if self.max_raster_pixels > MAX_RASTER_PIXELS {
            MAX_RASTER_PIXELS
        } else {
            self.max_raster_pixels
        }
    }

    /// Returns the effective target DPI, bounded by `TARGET_DPI` (<= 300).
    #[must_use]
    pub const fn effective_target_dpi(&self) -> u32 {
        if self.target_dpi > TARGET_DPI {
            TARGET_DPI
        } else {
            self.target_dpi
        }
    }

    /// Checks whether OCR should be triggered for a page given native text and image presence.
    #[must_use]
    pub fn should_trigger_ocr(&self, native_text_len: usize, has_images: bool) -> bool {
        // Trigger OCR if the page has embedded images and sparse native text (< 50 chars)
        has_images && native_text_len < self.low_text_threshold
    }
}
