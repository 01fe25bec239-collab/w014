//! Rust-controlled Tesseract OCR orchestration (WI-0207).
//!
//! Enforces:
//! - Engine: Tesseract orchestrated directly by Rust (zero Python components)
//! - Hard per-page timeout: <= 15 seconds, shared as ONE wall-clock deadline
//!   per OCR page across every image/media invocation on that page
//! - Hard per-job timeout: <= 30 minutes
//! - Hard page ceiling: <= 250 pages
//! - Raster limit: <= 40 Megapixels per image
//! - Target DPI: <= 300 DPI
//! - Fail closed on error/timeout/crash: NO GUESS, NO AI FALLBACK
//!
//! Shared page-deadline contract (WI0207 D2):
//! Callers establish ONE `page_deadline = page_start + effective_page_timeout`
//! per OCR page and pass `min(remaining_page_budget, remaining_job_budget)`
//! as `max_duration` to EVERY child OCR operation on that page. The deadline
//! MUST NOT reset between media operations. This engine additionally bounds
//! the effective timeout by the configured page limit and terminates + reaps
//! the child on timeout.

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use super::config::{MAX_PAGE_DURATION_SECS, OcrPolicyConfig, TARGET_DPI};
use super::error::OcrError;
use super::image_inspector::inspect_and_validate_raster;
use crate::normalization::normalize_nfc;

/// Computes the maximum duration a child OCR operation may receive.
///
/// Returns `min(remaining_page_budget, remaining_job_budget,
/// configured_page_limit)` so that multiple images on the same page share
/// ONE page deadline and no invocation can reset the page clock.
#[must_use]
pub fn child_ocr_budget(
    remaining_page: Duration,
    remaining_job: Duration,
    configured_page_limit: Duration,
) -> Duration {
    remaining_page.min(remaining_job).min(configured_page_limit)
}

/// Output resulting from single image OCR extraction.
#[derive(Debug, Clone, PartialEq)]
pub struct OcrPageOutput {
    /// Raw unnormalized text produced by OCR engine.
    pub raw_text: String,
    /// Unicode NFC normalized text.
    pub normalized_text: String,
    /// Optional confidence score in 0.0..=1.0.
    pub confidence: Option<f64>,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
}

/// Abstract interface for OCR engines.
#[async_trait]
pub trait OcrEngine: Send + Sync {
    /// Performs OCR extraction on the provided image bytes with default page timeout.
    ///
    /// # Errors
    /// Fails closed if raster limits are exceeded, timeout occurs, or the engine crashes.
    async fn ocr_image(&self, image_bytes: &[u8], format: &str) -> Result<OcrPageOutput, OcrError> {
        self.ocr_image_with_timeout(
            image_bytes,
            format,
            Duration::from_secs(MAX_PAGE_DURATION_SECS),
        )
        .await
    }

    /// Performs OCR extraction on the provided image bytes with an explicit maximum duration ceiling.
    ///
    /// The effective timeout is bounded by `min(configured_page_timeout, max_duration, MAX_PAGE_DURATION_SECS)`.
    ///
    /// # Errors
    /// Fails closed if raster limits are exceeded, timeout occurs, or the engine crashes.
    async fn ocr_image_with_timeout(
        &self,
        image_bytes: &[u8],
        format: &str,
        max_duration: Duration,
    ) -> Result<OcrPageOutput, OcrError>;
}

/// Production Rust process runner executing the `tesseract` command-line tool.
#[derive(Debug, Clone)]
pub struct ProcessTesseractEngine {
    /// Path to the tesseract executable (default: "tesseract").
    pub binary_path: PathBuf,
    /// OCR policy configuration.
    pub config: OcrPolicyConfig,
}

impl Default for ProcessTesseractEngine {
    fn default() -> Self {
        Self {
            binary_path: PathBuf::from("tesseract"),
            config: OcrPolicyConfig::default(),
        }
    }
}

impl ProcessTesseractEngine {
    /// Creates a new `ProcessTesseractEngine` with custom binary path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
            config: OcrPolicyConfig::default(),
        }
    }

    /// Customizes OCR policy configuration.
    #[must_use]
    pub fn with_config(mut self, config: OcrPolicyConfig) -> Self {
        self.config = config;
        self
    }
}

#[async_trait]
impl OcrEngine for ProcessTesseractEngine {
    async fn ocr_image(&self, image_bytes: &[u8], format: &str) -> Result<OcrPageOutput, OcrError> {
        let default_limit = Duration::from_secs(self.config.effective_page_timeout_secs());
        self.ocr_image_with_timeout(image_bytes, format, default_limit)
            .await
    }

    async fn ocr_image_with_timeout(
        &self,
        image_bytes: &[u8],
        _format: &str,
        max_duration: Duration,
    ) -> Result<OcrPageOutput, OcrError> {
        let start = Instant::now();

        // 1. Inspect image header and enforce <= 40 MP raster limit BEFORE invoking engine
        let dims = inspect_and_validate_raster(image_bytes)?;
        tracing::debug!(
            "Validated image raster for OCR: {}x{} ({} pixels)",
            dims.width,
            dims.height,
            dims.total_pixels
        );

        // 2. Write image bytes to secure isolated tempfile
        let mut temp_file = tempfile::Builder::new()
            .prefix("w014_ocr_")
            .tempfile()
            .map_err(|e| OcrError::Io {
                detail: format!("Failed to create temporary image file: {e}"),
            })?;

        temp_file.write_all(image_bytes).map_err(|e| OcrError::Io {
            detail: format!("Failed to write image data to tempfile: {e}"),
        })?;
        let temp_path = temp_file.path().to_path_buf();

        // 3. Build sanitized command: `tesseract <temp_path> stdout -l eng --dpi 300`
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg(&temp_path)
            .arg("stdout")
            .arg("-l")
            .arg("eng")
            .arg("--dpi")
            .arg(TARGET_DPI.to_string());

        cmd.env_clear();
        // Allow basic environment paths
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        if let Ok(tessdata) = std::env::var("TESSDATA_PREFIX") {
            cmd.env("TESSDATA_PREFIX", tessdata);
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        // 4. Calculate effective timeout: bounded by configured page timeout (<= 15s) and max_duration.
        //    Callers pass min(remaining_page_budget, remaining_job_budget) as
        //    max_duration so the shared page deadline is honored per image.
        let configured_page_limit = Duration::from_secs(self.config.effective_page_timeout_secs());
        let effective_timeout = configured_page_limit.min(max_duration);

        if effective_timeout.is_zero() {
            drop(temp_file);
            return Err(OcrError::Timeout {
                elapsed_secs: 0,
                limit_secs: 0,
            });
        }

        let mut child = cmd.spawn().map_err(|e| OcrError::EngineCrash {
            detail: format!(
                "Failed to spawn Tesseract process '{:?}': {e}",
                self.binary_path
            ),
        })?;

        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();

        let read_and_wait = async {
            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();

            if let Some(ref mut out) = stdout {
                let _ = out.read_to_end(&mut stdout_buf).await;
            }
            if let Some(ref mut err) = stderr {
                let _ = err.read_to_end(&mut stderr_buf).await;
            }

            let status = child.wait().await;
            (status, stdout_buf, stderr_buf)
        };

        let wait_result = tokio::time::timeout(effective_timeout, read_and_wait).await;

        // Clean up tempfile
        drop(temp_file);

        let (status_res, stdout_bytes, stderr_bytes) = match wait_result {
            Ok(tuple) => tuple,
            Err(_) => {
                // Timeout fired: explicitly terminate the child process and reap it
                let _ = child.start_kill();
                let _ = child.wait().await;

                let elapsed = start.elapsed().as_secs();
                return Err(OcrError::Timeout {
                    elapsed_secs: elapsed,
                    limit_secs: effective_timeout.as_secs(),
                });
            }
        };

        let status = status_res.map_err(|e| OcrError::EngineCrash {
            detail: format!("Error waiting on Tesseract process: {e}"),
        })?;

        let stderr_str = String::from_utf8_lossy(&stderr_bytes).to_string();

        if !status.success() {
            return Err(OcrError::EngineCrash {
                detail: format!(
                    "Tesseract exited with non-zero code {:?}: {stderr_str}",
                    status.code()
                ),
            });
        }

        let raw_text = String::from_utf8_lossy(&stdout_bytes).to_string();
        let normalized_text = normalize_nfc(&raw_text);
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(OcrPageOutput {
            raw_text,
            normalized_text,
            confidence: Some(0.85), // Base estimated confidence when TSV details are omitted
            duration_ms,
        })
    }
}

/// Deterministic mock OCR engine for testing without external Tesseract binary.
#[derive(Debug, Clone)]
pub struct MockTesseractEngine {
    /// Canned text output or error behavior.
    pub behavior: MockOcrBehavior,
}

/// Behavior modes for `MockTesseractEngine`.
#[derive(Debug, Clone)]
pub enum MockOcrBehavior {
    /// Always succeed returning the given text.
    Success(String),
    /// Simulate timeout.
    Timeout,
    /// Simulate engine crash.
    Crash(String),
    /// Echoes embedded image length and hex snippet as text.
    Echo,
    /// Simulate processing with artificial sleep delay.
    Delay(Duration, String),
}

impl Default for MockTesseractEngine {
    fn default() -> Self {
        Self {
            behavior: MockOcrBehavior::Echo,
        }
    }
}

impl MockTesseractEngine {
    /// Creates a mock returning the fixed text.
    #[must_use]
    pub fn returning_text(text: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            behavior: MockOcrBehavior::Success(text.into()),
        })
    }

    /// Creates a mock that simulates timeout.
    #[must_use]
    pub fn timing_out() -> Arc<Self> {
        Arc::new(Self {
            behavior: MockOcrBehavior::Timeout,
        })
    }

    /// Creates a mock that simulates engine crash.
    #[must_use]
    pub fn crashing(msg: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            behavior: MockOcrBehavior::Crash(msg.into()),
        })
    }

    /// Creates a mock that simulates processing delay.
    #[must_use]
    pub fn delayed(duration: Duration, text: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            behavior: MockOcrBehavior::Delay(duration, text.into()),
        })
    }
}

#[async_trait]
impl OcrEngine for MockTesseractEngine {
    async fn ocr_image(&self, image_bytes: &[u8], format: &str) -> Result<OcrPageOutput, OcrError> {
        self.ocr_image_with_timeout(
            image_bytes,
            format,
            Duration::from_secs(MAX_PAGE_DURATION_SECS),
        )
        .await
    }

    async fn ocr_image_with_timeout(
        &self,
        image_bytes: &[u8],
        _format: &str,
        max_duration: Duration,
    ) -> Result<OcrPageOutput, OcrError> {
        // Enforce raster validation even in mock engine
        let _ = inspect_and_validate_raster(image_bytes)?;

        if max_duration.is_zero() {
            return Err(OcrError::Timeout {
                elapsed_secs: 0,
                limit_secs: 0,
            });
        }

        match &self.behavior {
            MockOcrBehavior::Success(text) => {
                let norm = normalize_nfc(text);
                Ok(OcrPageOutput {
                    raw_text: text.clone(),
                    normalized_text: norm,
                    confidence: Some(0.95),
                    duration_ms: 10,
                })
            }
            MockOcrBehavior::Timeout => Err(OcrError::Timeout {
                elapsed_secs: 16,
                limit_secs: 15,
            }),
            MockOcrBehavior::Crash(msg) => Err(OcrError::EngineCrash {
                detail: msg.clone(),
            }),
            MockOcrBehavior::Echo => {
                let echo_text = format!(
                    "OCR extracted text from {} bytes of image data",
                    image_bytes.len()
                );
                let norm = normalize_nfc(&echo_text);
                Ok(OcrPageOutput {
                    raw_text: echo_text,
                    normalized_text: norm,
                    confidence: Some(0.90),
                    duration_ms: 5,
                })
            }
            MockOcrBehavior::Delay(duration, text) => {
                if *duration > max_duration {
                    tokio::time::sleep(max_duration).await;
                    Err(OcrError::Timeout {
                        elapsed_secs: max_duration.as_secs(),
                        limit_secs: max_duration.as_secs(),
                    })
                } else {
                    tokio::time::sleep(*duration).await;
                    let norm = normalize_nfc(text);
                    Ok(OcrPageOutput {
                        raw_text: text.clone(),
                        normalized_text: norm,
                        confidence: Some(0.95),
                        duration_ms: duration.as_millis() as u64,
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_child_ocr_budget_is_min_of_remaining_budgets() {
        // Required example shape: page starts t=0 with 15s; image 1 consumes
        // 8s; image 2 must see at most ~7s while the job still has budget.
        let budget = child_ocr_budget(
            Duration::from_secs(7),
            Duration::from_secs(1700),
            Duration::from_secs(15),
        );
        assert_eq!(budget, Duration::from_secs(7));

        // Job budget is the binding constraint.
        let budget = child_ocr_budget(
            Duration::from_secs(15),
            Duration::from_millis(400),
            Duration::from_secs(15),
        );
        assert_eq!(budget, Duration::from_millis(400));

        // Exhausted page budget yields zero (caller fails closed before spawn).
        let budget = child_ocr_budget(
            Duration::ZERO,
            Duration::from_secs(100),
            Duration::from_secs(15),
        );
        assert!(budget.is_zero());

        // Configured page limit caps even generous remaining budgets.
        let budget = child_ocr_budget(
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(15),
        );
        assert_eq!(budget, Duration::from_secs(15));
    }
}
