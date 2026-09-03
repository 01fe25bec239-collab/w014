//! Deterministic tests for shared OCR page wall-clock deadline (WI0207 D2).
//!
//! Frozen semantics under test:
//! - ONE `page_start` + ONE `page_deadline = page_start + effective_page_timeout`
//!   per OCR page; every image/media OCR operation on that page shares the SAME
//!   deadline and the clock MUST NOT reset between media operations.
//! - Each child operation receives at most
//!   `min(remaining_page_budget, remaining_job_budget)`.
//! - Page/job exhaustion fails closed; no later OCR operation continues.
//! - 250-page ceiling counts OCR-submitted pages only.
//! - Timed-out Tesseract children are terminated + reaped (no orphans).
//!
//! All timing tests use small deterministic test-only bounds (1-2s page/job,
//! 100-800ms simulated OCR delays) so no test sleeps for a real 15 seconds.

use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use uuid::Uuid;
use w014_document_processing::docx_producer::DocxOcrProducer;
use w014_document_processing::ocr::{
    MockTesseractEngine, OcrEngine, OcrError, OcrPageOutput, OcrPolicyConfig,
    ProcessTesseractEngine, inspect_and_validate_raster,
};
use w014_document_processing::sandbox::SandboxInput;
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId, WorkspaceId};
use w014_domain::{MediaType, Sha256, StoredMediaType};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_valid_png_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut png = Vec::new();
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    png.extend_from_slice(&[0, 0, 0, 13]);
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&width.to_be_bytes());
    png.extend_from_slice(&height.to_be_bytes());
    png.extend_from_slice(&[8, 2, 0, 0, 0]);
    png.extend_from_slice(&[0, 0, 0, 0]);
    png
}

struct DocxBuilder {
    document_xml: String,
    media_items: Vec<(String, Vec<u8>)>,
}

impl DocxBuilder {
    fn new(document_xml: impl Into<String>) -> Self {
        Self {
            document_xml: document_xml.into(),
            media_items: Vec::new(),
        }
    }

    fn with_media(mut self, name: impl Into<String>, data: Vec<u8>) -> Self {
        self.media_items.push((name.into(), data));
        self
    }

    fn build(self) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(
                b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
                    <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
                    <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
                    <Default Extension=\"png\" ContentType=\"image/png\"/>\
                    <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
                </Types>",
            )
            .unwrap();

            zip.start_file("_rels/.rels", options).unwrap();
            zip.write_all(
                b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                    <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
                </Relationships>",
            )
            .unwrap();

            zip.start_file("word/document.xml", options).unwrap();
            zip.write_all(self.document_xml.as_bytes()).unwrap();

            zip.start_file("word/_rels/document.xml.rels", options)
                .unwrap();
            zip.write_all(
                b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                </Relationships>",
            )
            .unwrap();

            for (media_name, data) in self.media_items {
                zip.start_file(media_name, options).unwrap();
                zip.write_all(&data).unwrap();
            }

            zip.finish().unwrap();
        }
        buf
    }
}

fn sandbox_input_for(docx_bytes: Vec<u8>) -> SandboxInput {
    let ws_id = WorkspaceId::new();
    let ver_id = DocumentVersionId::new();
    let art_id = ObjectArtifactId::new();
    let job_id = Uuid::new_v4();
    let hash = Sha256::digest(&docx_bytes);
    let len = docx_bytes.len() as i64;
    SandboxInput::new(
        ws_id,
        ver_id,
        art_id,
        job_id,
        StoredMediaType::new(MediaType::Docx.as_str()).unwrap(),
        hash,
        len,
        docx_bytes,
    )
    .expect("SandboxInput creation should succeed")
}

fn single_scanned_page_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Scan #1</w:t></w:r></w:p></w:body></w:document>"#.to_string()
}

fn multi_scanned_page_xml(pages: u32) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    for page_i in 1..=pages {
        xml.push_str(&format!(r#"<w:p><w:r><w:t>Scan #{page_i}</w:t></w:r>"#));
        if page_i < pages {
            xml.push_str(r#"<w:r><w:br w:type="page"/></w:r>"#);
        }
        xml.push_str("</w:p>");
    }
    xml.push_str("</w:body></w:document>");
    xml
}

fn dense_native_page_xml(pages: u32) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    for page_i in 1..=pages {
        xml.push_str(&format!(
            r#"<w:p><w:r><w:t>Dense native procurement text for page {page_i} with well over fifty characters of structured content.</w:t></w:r>"#
        ));
        if page_i < pages {
            xml.push_str(r#"<w:r><w:br w:type="page"/></w:r>"#);
        }
        xml.push_str("</w:p>");
    }
    xml.push_str("</w:body></w:document>");
    xml
}

/// Recording engine: records every `max_duration` child budget it receives and
/// simulates a fixed processing delay. Proves the second image cannot receive
/// a fresh page clock.
#[derive(Debug)]
struct RecordingBudgetEngine {
    delay: Duration,
    text: String,
    seen_budgets: Arc<Mutex<Vec<Duration>>>,
}

impl RecordingBudgetEngine {
    fn new(delay: Duration, text: impl Into<String>, seen: Arc<Mutex<Vec<Duration>>>) -> Arc<Self> {
        Arc::new(Self {
            delay,
            text: text.into(),
            seen_budgets: seen,
        })
    }
}

#[async_trait]
impl OcrEngine for RecordingBudgetEngine {
    async fn ocr_image_with_timeout(
        &self,
        image_bytes: &[u8],
        _format: &str,
        max_duration: Duration,
    ) -> Result<OcrPageOutput, OcrError> {
        let _ = inspect_and_validate_raster(image_bytes)?;
        if max_duration.is_zero() {
            return Err(OcrError::Timeout {
                elapsed_secs: 0,
                limit_secs: 0,
            });
        }
        self.seen_budgets.lock().unwrap().push(max_duration);
        if self.delay > max_duration {
            tokio::time::sleep(max_duration).await;
            return Err(OcrError::Timeout {
                elapsed_secs: max_duration.as_secs(),
                limit_secs: max_duration.as_secs(),
            });
        }
        tokio::time::sleep(self.delay).await;
        Ok(OcrPageOutput {
            raw_text: self.text.clone(),
            normalized_text: self.text.clone(),
            confidence: Some(0.95),
            duration_ms: self.delay.as_millis() as u64,
        })
    }
}

// ---------------------------------------------------------------------------
// Deadline arithmetic is covered by unit tests on `child_ocr_budget` in
// `src/ocr/tesseract.rs` (no sleeps). The integration tests below prove the
// producer honors ONE shared page deadline end to end with small
// deterministic bounds.

// ---------------------------------------------------------------------------
// Producer integration tests (small deterministic bounds)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_one_image_within_page_budget_pass() {
    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new(single_scanned_page_xml())
        .with_media("word/media/image1.png", png)
        .build();
    let input = sandbox_input_for(docx_bytes);

    let mock = MockTesseractEngine::delayed(Duration::from_millis(100), "single image ocr");
    let producer = DocxOcrProducer::new(mock).with_ocr_config(OcrPolicyConfig {
        page_timeout_secs: 2,
        job_timeout_secs: 30,
        ..Default::default()
    });

    let out = producer
        .process_sandbox_input(&input)
        .await
        .expect("ONE_IMAGE_WITHIN_PAGE_BUDGET must PASS");
    assert_eq!(out.pages.len(), 1);
    assert!(out.pages[0].ocr_used);
}

#[tokio::test]
async fn test_multiple_images_share_single_page_deadline() {
    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new(single_scanned_page_xml())
        .with_media("word/media/image1.png", png.clone())
        .with_media("word/media/image2.png", png)
        .build();
    let input = sandbox_input_for(docx_bytes);

    let seen: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
    let engine = RecordingBudgetEngine::new(
        Duration::from_millis(300),
        "shared budget ocr",
        Arc::clone(&seen),
    );
    let producer = DocxOcrProducer::new(engine).with_ocr_config(OcrPolicyConfig {
        page_timeout_secs: 2,
        job_timeout_secs: 60,
        ..Default::default()
    });

    let start = Instant::now();
    let out = producer
        .process_sandbox_input(&input)
        .await
        .expect("MULTIPLE_IMAGES_SHARED_PAGE_BUDGET must PASS when total fits");
    let total = start.elapsed();
    assert_eq!(out.pages.len(), 1);
    assert!(out.pages[0].ocr_used);
    // Total page OCR wall clock must remain within the page budget.
    assert!(
        total < Duration::from_secs(2),
        "TOTAL PAGE OCR WALL CLOCK must stay <= page budget, elapsed={total:?}"
    );

    let budgets = seen.lock().unwrap().clone();
    assert_eq!(
        budgets.len(),
        2,
        "both media items on the same page must be submitted"
    );
    assert!(
        budgets[1] < budgets[0],
        "second image must receive a reduced budget sharing the SAME page deadline, got {budgets:?}"
    );
    assert!(
        budgets[1] <= Duration::from_millis(1900),
        "second image must NOT receive a fresh full page budget, got {budgets:?}"
    );
}

#[tokio::test]
async fn test_second_or_later_image_cannot_reset_page_clock() {
    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new(single_scanned_page_xml())
        .with_media("word/media/image1.png", png.clone())
        .with_media("word/media/image2.png", png)
        .build();
    let input = sandbox_input_for(docx_bytes);

    let seen: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
    // Each image needs 600ms; page budget is only 1s. With a per-image reset
    // both would succeed (1.2s total with fresh clocks). With the shared
    // deadline the second image has only ~400ms left and must fail closed.
    let engine = RecordingBudgetEngine::new(
        Duration::from_millis(600),
        "should not fit twice",
        Arc::clone(&seen),
    );
    let producer = DocxOcrProducer::new(engine).with_ocr_config(OcrPolicyConfig {
        page_timeout_secs: 1,
        job_timeout_secs: 60,
        ..Default::default()
    });

    let res = producer.process_sandbox_input(&input).await;
    assert!(
        res.is_err(),
        "SECOND_OR_LATER_IMAGE_CANNOT_RESET_PAGE_CLOCK: second image with a fresh 15s clock would succeed, shared budget must FAIL CLOSED"
    );
    let budgets = seen.lock().unwrap().clone();
    assert!(
        !budgets.is_empty(),
        "at least the first image must have been attempted"
    );
    if budgets.len() >= 2 {
        assert!(
            budgets[1] < Duration::from_secs(1),
            "second image budget must be reduced by first image consumption, got {budgets:?}"
        );
        assert!(
            budgets[1] < Duration::from_millis(600),
            "second image budget must be insufficient for another full delay, got {budgets:?}"
        );
    }
    // If the producer failed closed before invoking the engine a second time,
    // a single recorded budget also proves no reset occurred.
}

#[tokio::test]
async fn test_page_timeout_fails_closed() {
    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new(single_scanned_page_xml())
        .with_media("word/media/image1.png", png)
        .build();
    let input = sandbox_input_for(docx_bytes);

    // Single image needs 1500ms but the page budget is 1s.
    let mock = MockTesseractEngine::delayed(Duration::from_millis(1500), "too slow");
    let producer = DocxOcrProducer::new(mock).with_ocr_config(OcrPolicyConfig {
        page_timeout_secs: 1,
        job_timeout_secs: 60,
        ..Default::default()
    });

    let start = Instant::now();
    let res = producer.process_sandbox_input(&input).await;
    let elapsed = start.elapsed();
    assert!(res.is_err(), "PAGE_TIMEOUT must FAIL CLOSED");
    assert!(
        elapsed < Duration::from_secs(5),
        "page timeout must return promptly, elapsed={elapsed:?}"
    );
}

#[tokio::test]
async fn test_job_timeout_fails_closed() {
    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new(multi_scanned_page_xml(2))
        .with_media("word/media/image1.png", png)
        .build();
    let input = sandbox_input_for(docx_bytes);

    // Each page needs 700ms; the whole-job budget is 1s, so the second page
    // has only ~300ms left and must fail closed on the job deadline.
    let mock = MockTesseractEngine::delayed(Duration::from_millis(700), "ocr text");
    let producer = DocxOcrProducer::new(mock).with_ocr_config(OcrPolicyConfig {
        page_timeout_secs: 15,
        job_timeout_secs: 1,
        ..Default::default()
    });

    let res = producer.process_sandbox_input(&input).await;
    assert!(res.is_err(), "JOB_TIMEOUT must FAIL CLOSED");
}

// ---------------------------------------------------------------------------
// Page-count semantics: OCR-submitted pages only
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ocr_page_count_only_ocr_pages() {
    // Two scanned pages but the OCR ceiling is 1: the second submission must
    // be rejected. This proves the counter tracks OCR-submitted pages.
    let png = make_valid_png_bytes(100, 100);
    let docx_bytes = DocxBuilder::new(multi_scanned_page_xml(2))
        .with_media("word/media/image1.png", png)
        .build();
    let input = sandbox_input_for(docx_bytes);

    let mock = MockTesseractEngine::returning_text("ocr text");
    let producer = DocxOcrProducer::new(mock).with_ocr_config(OcrPolicyConfig {
        max_pages: 1,
        ..Default::default()
    });

    let res = producer.process_sandbox_input(&input).await;
    assert!(
        matches!(
            res,
            Err(
                w014_document_processing::docx::DocxError::PackageLimitsExceeded {
                    limit_name: "OCR_PAGE_LIMIT",
                    actual: 2,
                    limit: 1,
                }
            )
        ),
        "OCR_PAGE_COUNT_ONLY_OCR_PAGES: second OCR-submitted page must be rejected"
    );
}

#[tokio::test]
async fn test_native_only_pages_not_charged_to_250() {
    // Five dense native pages with a ceiling of 1 OCR page must still pass
    // because native-only pages are never submitted to OCR.
    let docx_bytes = DocxBuilder::new(dense_native_page_xml(5)).build();
    let input = sandbox_input_for(docx_bytes);

    let mock = MockTesseractEngine::returning_text("must not be called");
    let producer = DocxOcrProducer::new(mock).with_ocr_config(OcrPolicyConfig {
        max_pages: 1,
        ..Default::default()
    });

    let out = producer
        .process_sandbox_input(&input)
        .await
        .expect("NATIVE_ONLY_PAGES_NOT_CHARGED_TO_250 must PASS");
    assert_eq!(out.pages.len(), 5);
    for page in &out.pages {
        assert!(!page.ocr_used);
    }
}

// ---------------------------------------------------------------------------
// Fail-closed child process safety: terminated + reaped, no orphan
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn test_timed_out_child_terminated_and_reaped() {
    use std::os::unix::fs::PermissionsExt;

    // Slow process: sleeps 60s so the OCR timeout must kill it.
    let mut slow_script = tempfile::NamedTempFile::new().unwrap();
    writeln!(slow_script, "#!/bin/sh\nsleep 60").unwrap();
    let slow_path = slow_script.path().to_path_buf();
    let mut perms = std::fs::metadata(&slow_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&slow_path, perms).unwrap();

    let engine = ProcessTesseractEngine::new(&slow_path).with_config(OcrPolicyConfig {
        page_timeout_secs: 1,
        ..Default::default()
    });
    let img = make_valid_png_bytes(100, 100);

    let start = Instant::now();
    let res = engine
        .ocr_image_with_timeout(&img, "image/png", Duration::from_millis(200))
        .await;
    let first_elapsed = start.elapsed();
    assert!(
        matches!(res, Err(OcrError::Timeout { .. })),
        "TIMED_OUT_CHILD must FAIL CLOSED with Timeout"
    );
    assert!(
        first_elapsed < Duration::from_secs(5),
        "TIMED_OUT_TESSERACT_CHILD must be TERMINATED promptly, elapsed={first_elapsed:?}"
    );

    // A second timeout against the same slow binary must also return promptly:
    // a leaked/zombie child would accumulate and delay subsequent operations.
    let start = Instant::now();
    let res2 = engine
        .ocr_image_with_timeout(&img, "image/png", Duration::from_millis(200))
        .await;
    let second_elapsed = start.elapsed();
    assert!(
        matches!(res2, Err(OcrError::Timeout { .. })),
        "second timeout must also fail closed"
    );
    assert!(
        second_elapsed < Duration::from_secs(5),
        "TIMED_OUT_TESSERACT_CHILD must be REAPED (no zombie/orphan accumulation), elapsed={second_elapsed:?}"
    );

    // The engine must remain usable after timeouts: a fast child proves no
    // orphan process blocks later OCR operations.
    let mut fast_script = tempfile::NamedTempFile::new().unwrap();
    writeln!(fast_script, "#!/bin/sh\necho hello").unwrap();
    let fast_path = fast_script.path().to_path_buf();
    let mut perms = std::fs::metadata(&fast_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fast_path, perms).unwrap();

    let fast_engine = ProcessTesseractEngine::new(&fast_path).with_config(OcrPolicyConfig {
        page_timeout_secs: 5,
        ..Default::default()
    });
    let fast_res = fast_engine
        .ocr_image_with_timeout(&img, "image/png", Duration::from_secs(5))
        .await;
    assert!(
        fast_res.is_ok(),
        "ORPHAN_PROCESS_AFTER_TIMEOUT must be ABSENT: fast OCR after timeouts must succeed"
    );
}
