//! High-level DOCX safe-subset and OCR pipeline producer (WI-0207).
//!
//! Orchestrates:
//! 1. Hostile package limits & security preflight (`DocxPackage::open`)
//! 2. Safe subset hierarchy extraction (`DocxParser::parse_package`)
//! 3. Scanned / low-text OCR fallback via Rust-controlled Tesseract orchestration
//! 4. Native text precedence and conflict policy evaluation (`evaluate_native_vs_ocr`)
//! 5. Production of domain entities (`ParserArtifact`, `ParserPage`, `ParserBlock`, `SourceSpan`)
//! 6. Typed, bounded `SandboxOutput` generation

use std::sync::Arc;
use std::time::Instant;

use w014_domain::ids::ParserArtifactId;
use w014_domain::{
    BlockKind, ExtractionMethod, LocatorVersion, OffsetRange, ParserArtifact, ParserBlock,
    ParserPage, Rotation, Sha256, SourceSpan,
};

use crate::docx::{DocxError, DocxPackage, DocxParser};
use crate::ocr::{
    ConflictEvaluationResult, MAX_OCR_PAGES, OcrEngine, OcrError, OcrPolicyConfig,
    SpanProvenanceFactory, evaluate_native_vs_ocr,
};
use crate::sandbox::{SANDBOX_PROTOCOL_VERSION, SandboxInput, SandboxOutput, SandboxStatus};

/// Canonical locator version used by the DOCX P0 safe subset parser.
pub const DOCX_LOCATOR_VERSION: &str = "w014-docx-p0-v1";

/// Canonical parser name for the DOCX P0 parser engine.
pub const DOCX_PARSER_NAME: &str = "w014-docx-safe-parser";

/// Canonical parser version.
pub const DOCX_PARSER_VERSION: &str = "0.1.0";

/// Result produced by full DOCX / OCR parsing.
#[derive(Debug, Clone, PartialEq)]
pub struct DocxParseOutput {
    /// Sandbox output envelope.
    pub sandbox_output: SandboxOutput,
    /// Root parser artifact fact.
    pub artifact: ParserArtifact,
    /// Ordered page facts.
    pub pages: Vec<ParserPage>,
    /// Ordered block facts across all pages.
    pub blocks: Vec<ParserBlock>,
    /// Ordered citable source span facts.
    pub spans: Vec<SourceSpan>,
    /// Per-page conflict evaluation results (if OCR executed).
    pub conflict_results: Vec<ConflictEvaluationResult>,
}

/// DOCX / OCR parsing producer engine.
pub struct DocxOcrProducer {
    ocr_engine: Arc<dyn OcrEngine>,
    ocr_config: OcrPolicyConfig,
    locator_version: LocatorVersion,
}

impl DocxOcrProducer {
    /// Creates a new producer with the specified OCR engine backend.
    #[must_use]
    pub fn new(ocr_engine: Arc<dyn OcrEngine>) -> Self {
        Self {
            ocr_engine,
            ocr_config: OcrPolicyConfig::default(),
            locator_version: LocatorVersion::new(DOCX_LOCATOR_VERSION)
                .expect("Valid static locator version"),
        }
    }

    /// Sets custom OCR policy configuration.
    #[must_use]
    pub fn with_ocr_config(mut self, config: OcrPolicyConfig) -> Self {
        self.ocr_config = config;
        self
    }

    /// Executes complete DOCX parsing pipeline on scoped `SandboxInput`.
    ///
    /// # Errors
    /// Fails closed if hostile package limits are violated, format is unsupported/corrupted,
    /// or OCR exhausts resources.
    pub async fn process_sandbox_input(
        &self,
        input: &SandboxInput,
    ) -> Result<DocxParseOutput, DocxError> {
        let start_time = Instant::now();

        // 1. Hostile package limits & security preflight
        let package = DocxPackage::open(&input.bytes)?;

        // 2. Safe subset hierarchy extraction
        let parsed_doc = DocxParser::parse_package(&package)?;

        // 3. Page count limit check
        if parsed_doc.pages.len() > MAX_OCR_PAGES as usize {
            return Err(DocxError::PackageLimitsExceeded {
                limit_name: "OCR_PAGE_LIMIT",
                actual: parsed_doc.pages.len() as u64,
                limit: MAX_OCR_PAGES as u64,
            });
        }

        // 4. Build domain entities and execute OCR fallback where policy dictates
        let artifact_id = ParserArtifactId::new();
        let artifact = ParserArtifact::new(
            input.workspace_id,
            input.document_version_id,
            Some(input.job_id),
            DOCX_PARSER_NAME,
            DOCX_PARSER_VERSION,
            self.locator_version.clone(),
        )
        .map_err(|e| DocxError::Internal {
            detail: e.to_string(),
        })?;

        let prov_factory = SpanProvenanceFactory::new(
            input.workspace_id,
            input.document_version_id,
            artifact_id,
            self.locator_version.clone(),
        );

        let mut domain_pages = Vec::with_capacity(parsed_doc.pages.len());
        let mut domain_blocks = Vec::new();
        let mut domain_spans = Vec::new();
        let mut conflict_results = Vec::new();

        let mut global_span_sequence: u32 = 0;
        let mut total_full_text = String::new();

        for parsed_page in parsed_doc.pages {
            let page_num = parsed_page.page_number;
            let native_text = parsed_page.normalized_text.clone();

            let mut page_text = native_text.clone();
            let mut extraction = ExtractionMethod::NativeText;
            let mut ocr_used = false;
            let mut quality_score = Some(1.0);

            // Check if OCR should run for this page under frozen policy
            if self
                .ocr_config
                .should_trigger_ocr(native_text.len(), parsed_page.has_embedded_images)
                && !parsed_page.media_items.is_empty()
            {
                // OCR fallback execution on page images
                let mut ocr_texts = Vec::new();
                for media in &parsed_page.media_items {
                    let ocr_res = self
                        .ocr_engine
                        .ocr_image(&media.data, &media.content_type)
                        .await
                        .map_err(|ocr_err| match ocr_err {
                            OcrError::PageLimitExceeded { actual, limit } => {
                                DocxError::PackageLimitsExceeded {
                                    limit_name: "OCR_PAGES",
                                    actual: actual as u64,
                                    limit: limit as u64,
                                }
                            }
                            OcrError::RasterExceeded { pixels, limit } => {
                                DocxError::PackageLimitsExceeded {
                                    limit_name: "OCR_RASTER_PIXELS",
                                    actual: pixels,
                                    limit,
                                }
                            }
                            OcrError::Timeout {
                                elapsed_secs,
                                limit_secs,
                            } => DocxError::Io {
                                detail: format!(
                                    "OCR timed out after {elapsed_secs}s (limit {limit_secs}s)"
                                ),
                            },
                            other => DocxError::Io {
                                detail: format!("OCR engine failure: {other}"),
                            },
                        })?;
                    ocr_texts.push(ocr_res.normalized_text);
                }

                let combined_ocr = ocr_texts.join("\n");
                let conflict_eval =
                    evaluate_native_vs_ocr(&native_text, Some(&combined_ocr), page_num, Some(0.85));

                conflict_results.push(conflict_eval);

                ocr_used = true;
                if native_text.is_empty() {
                    // Page has no native text; provisional OCR text is adopted
                    page_text = combined_ocr;
                    extraction = ExtractionMethod::Ocr;
                    quality_score = Some(0.85);
                } else {
                    // Native text is preserved; extraction is Mixed
                    extraction = ExtractionMethod::Mixed;
                    quality_score = Some(0.95);
                }
            }

            let domain_page = ParserPage::new(
                &artifact,
                page_num,
                page_text.clone(),
                extraction,
                ocr_used,
                quality_score,
                None, // Docx has no explicit point dimensions
                None,
                Rotation::Deg0,
            )
            .map_err(|e| DocxError::Internal {
                detail: e.to_string(),
            })?;

            // Build block facts
            if parsed_page.blocks.is_empty() && !page_text.is_empty() {
                // Synthesize block for OCR-derived or unblocked page text
                let block = ParserBlock::new(
                    &domain_page,
                    0,
                    BlockKind::Paragraph,
                    0,
                    page_text.len() as u32,
                    None,
                    Vec::new(),
                    page_text.clone(),
                    quality_score,
                )
                .map_err(|e| DocxError::Internal {
                    detail: e.to_string(),
                })?;

                let span = if ocr_used && extraction == ExtractionMethod::Ocr {
                    prov_factory
                        .build_ocr_span(
                            page_num,
                            global_span_sequence,
                            OffsetRange::new(0, page_text.len() as u32).map_err(|e| {
                                DocxError::Internal {
                                    detail: e.to_string(),
                                }
                            })?,
                            None,
                            page_text.clone(),
                            quality_score,
                        )
                        .map_err(|e| DocxError::Internal {
                            detail: e.to_string(),
                        })?
                } else {
                    prov_factory
                        .build_native_span(
                            page_num,
                            global_span_sequence,
                            OffsetRange::new(0, page_text.len() as u32).map_err(|e| {
                                DocxError::Internal {
                                    detail: e.to_string(),
                                }
                            })?,
                            None,
                            None,
                            page_text.clone(),
                        )
                        .map_err(|e| DocxError::Internal {
                            detail: e.to_string(),
                        })?
                };

                global_span_sequence += 1;
                domain_blocks.push(block);
                domain_spans.push(span);
            } else {
                for b in parsed_page.blocks {
                    let block = ParserBlock::new(
                        &domain_page,
                        b.ordinal,
                        b.kind,
                        b.norm_start,
                        b.norm_end,
                        None,
                        b.section_path.clone(),
                        b.text.clone(),
                        b.confidence,
                    )
                    .map_err(|e| DocxError::Internal {
                        detail: e.to_string(),
                    })?;

                    let span = prov_factory
                        .build_native_span(
                            page_num,
                            global_span_sequence,
                            OffsetRange::new(b.norm_start, b.norm_end).map_err(|e| {
                                DocxError::Internal {
                                    detail: e.to_string(),
                                }
                            })?,
                            None,
                            if b.section_path.is_empty() {
                                None
                            } else {
                                Some(b.section_path)
                            },
                            b.text,
                        )
                        .map_err(|e| DocxError::Internal {
                            detail: e.to_string(),
                        })?;

                    global_span_sequence += 1;
                    domain_blocks.push(block);
                    domain_spans.push(span);
                }
            }

            if !total_full_text.is_empty() && !page_text.is_empty() {
                total_full_text.push_str("\n\n");
            }
            total_full_text.push_str(&page_text);
            domain_pages.push(domain_page);
        }

        let execution_duration_ms = start_time.elapsed().as_millis() as u64;
        let text_sha256 = if total_full_text.is_empty() {
            None
        } else {
            Some(Sha256::digest(total_full_text.as_bytes()))
        };

        // Complete the ParserArtifact
        let completed_artifact = artifact
            .complete(
                chrono::Utc::now(),
                domain_pages.len() as i32,
                domain_blocks.len() as i32,
                domain_spans.len() as i32,
                Some(execution_duration_ms as i64),
            )
            .map_err(|e| DocxError::Internal {
                detail: e.to_string(),
            })?;

        // Construct SandboxOutput envelope
        let sandbox_output = SandboxOutput {
            protocol_version: SANDBOX_PROTOCOL_VERSION.to_string(),
            document_version_id: input.document_version_id,
            object_artifact_id: input.object_artifact_id,
            input_sha256: input.content_sha256,
            status: SandboxStatus::Success,
            parser_name: DOCX_PARSER_NAME.to_string(),
            parser_version: DOCX_PARSER_VERSION.to_string(),
            locator_version: self.locator_version.clone(),
            page_count: domain_pages.len() as i32,
            block_count: domain_blocks.len() as i32,
            span_count: domain_spans.len() as i32,
            text_sha256,
            execution_duration_ms,
            failure_code: None,
            failure_detail: None,
            parsed_artifact: None,
        };

        Ok(DocxParseOutput {
            sandbox_output,
            artifact: completed_artifact,
            pages: domain_pages,
            blocks: domain_blocks,
            spans: domain_spans,
            conflict_results,
        })
    }
}
