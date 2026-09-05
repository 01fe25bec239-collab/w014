//! Foundation production parser sandbox image runtime proof (WI0205).
//!
//! Distinguishes STATIC_IMAGE_CONTRACT (deterministic, no Docker required)
//! from ACTUAL_DOCKER_RUNTIME (live `ProcessSandboxRunner` execution through
//! the authoritative `w014-parser-sandbox:local` image).
//!
//! Ordinary environments without Docker skip runtime tests with a diagnostic.
//! The A3 acceptance run sets `W014_REQUIRE_PRODUCTION_IMAGE_RUNTIME=1`, which
//! turns any skip into a hard failure (never a claimed PASS from a skip).

use uuid::Uuid;
use w014_document_processing::sandbox::{
    DEFAULT_OCI_IMAGE, ProcessSandboxRunner, SANDBOX_PROTOCOL_VERSION, SandboxInput, SandboxRunner,
    SandboxSecurityProfile, SandboxStatus,
};
use w014_domain::Sha256;
use w014_domain::StoredMediaType;
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId, WorkspaceId};
use w014_worker::{DEFAULT_PARSER_SANDBOX_BIN, create_default_sandbox_runner};

const PRODUCTION_IMAGE: &str = "w014-parser-sandbox:local";
const DOCX_MEDIA: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const PDF_MEDIA: &str = "application/pdf";

static MINIMAL_DOCX: &[u8] = include_bytes!("fixtures/minimal-hello.docx");

// Deterministic OCR-requiring DOCX: one page, zero native <w:t> text
// (native_text_len 0 < LOW_TEXT_CHAR_THRESHOLD 50), two embedded PNG
// raster images on that single page carrying sentinel text
// "W014 OCR RUNTIME ALPHA" / "W014 OCR RUNTIME BETA".
static OCR_DOCX: &[u8] = include_bytes!("fixtures/ocr-runtime-two-image-sentinels.docx");

fn runtime_required() -> bool {
    std::env::var("W014_REQUIRE_PRODUCTION_IMAGE_RUNTIME").is_ok()
}

fn docker_available() -> bool {
    ProcessSandboxRunner::platform_default_wrapper().is_some()
}

fn production_image_present() -> bool {
    std::process::Command::new("docker")
        .args(["image", "inspect", PRODUCTION_IMAGE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns true when the caller must execute live runtime (not skip).
fn require_live_runtime(test_name: &str) -> bool {
    if docker_available() && production_image_present() {
        return true;
    }
    let reason = if !docker_available() {
        "approved docker backend absent"
    } else {
        "production image w014-parser-sandbox:local absent"
    };
    if runtime_required() {
        panic!(
            "W014_REQUIRE_PRODUCTION_IMAGE_RUNTIME=1 but live runtime unavailable for {test_name}: {reason}"
        );
    }
    eprintln!(
        "SKIP {test_name}: {reason} (set W014_REQUIRE_PRODUCTION_IMAGE_RUNTIME=1 to enforce)"
    );
    false
}

fn sample_pdf_bytes(text: &str) -> Vec<u8> {
    let stream_content = format!("BT /F1 12 Tf 50 700 Td ({text}) Tj ET");
    let stream_len = stream_content.len();
    format!(
        "%PDF-1.4\n\
        1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
        2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
        3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n\
        4 0 obj\n<< /Length {stream_len} >>\nstream\n{stream_content}\nendstream\nendobj\n\
        xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000210 00000 n \n\
        trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n"
    )
    .into_bytes()
}

fn sample_input(media: &str, bytes: Vec<u8>) -> SandboxInput {
    SandboxInput::new(
        WorkspaceId::new(),
        DocumentVersionId::new(),
        ObjectArtifactId::new(),
        Uuid::new_v4(),
        StoredMediaType::new(media).unwrap(),
        Sha256::digest(&bytes),
        bytes.len() as i64,
        bytes,
    )
    .expect("valid sandbox input")
}

// ---------------------------------------------------------------------------
// STATIC_IMAGE_CONTRACT: deterministic, no Docker required.
// ---------------------------------------------------------------------------

#[test]
fn test_production_image_static_contract() {
    assert_eq!(
        DEFAULT_OCI_IMAGE, PRODUCTION_IMAGE,
        "D3 default OCI image must be exactly w014-parser-sandbox:local"
    );
    assert_eq!(
        DEFAULT_PARSER_SANDBOX_BIN, "w014-parser-sandbox",
        "worker default binary must be w014-parser-sandbox"
    );

    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dockerfile = manifest.join("parser-sandbox/Dockerfile");
    let build_sh = manifest.join("parser-sandbox/build-image.sh");
    assert!(
        dockerfile.is_file(),
        "Dockerfile must exist: {}",
        dockerfile.display()
    );
    assert!(
        build_sh.is_file(),
        "build-image.sh must exist: {}",
        build_sh.display()
    );

    let df = std::fs::read_to_string(&dockerfile).expect("read Dockerfile");
    // Real binary from locked repository source.
    assert!(
        df.contains("cargo build"),
        "Dockerfile must compile the real binary"
    );
    assert!(
        df.contains("--locked"),
        "Dockerfile must use Cargo --locked"
    );
    assert!(
        df.contains("-p w014-document-processing"),
        "Dockerfile must build w014-document-processing"
    );
    assert!(
        df.contains("--bin w014-parser-sandbox"),
        "Dockerfile must build --bin w014-parser-sandbox"
    );
    // Authoritative PDFium pin preserved.
    assert!(df.contains("7881"), "Dockerfile must pin PDFium build 7881");
    assert!(
        df.contains("6252fce3da45e7f0dc5b27f4d4e1a1456ca3f7734cdb04f927967df772127478"),
        "Dockerfile must verify the authoritative Linux/arm64 PDFium SHA-256"
    );
    assert!(
        df.contains("sha256sum -c"),
        "Dockerfile must fail on PDFium hash mismatch"
    );
    // Tesseract runtime.
    assert!(
        df.contains("tesseract-ocr"),
        "Dockerfile must package Tesseract"
    );
    assert!(
        df.contains("tesseract-ocr-eng"),
        "Dockerfile must package English tessdata"
    );
    // Bounded context: never `COPY . .` as an instruction, never bakes credentials.
    let has_copy_dot = df.lines().any(|line| {
        let t = line.trim_start();
        t.starts_with("COPY . .") || t.starts_with("COPY .,")
    });
    assert!(!has_copy_dot, "production Dockerfile must not use COPY . .");
    for secret in [
        ".env",
        "PRIVATE KEY",
        "AWS_SECRET",
        "DATABASE_URL",
        "docker.sock",
    ] {
        let leaked = df.lines().any(|line| {
            let t = line.trim_start();
            !t.starts_with('#') && line.contains(secret)
        });
        assert!(!leaked, "Dockerfile must not reference '{secret}'");
    }
    // Invocation compatibility: no ENTRYPOINT instruction rewriting the D3 command.
    let has_entrypoint = df.lines().any(|line| {
        let t = line.trim_start();
        !t.starts_with('#') && t.starts_with("ENTRYPOINT")
    });
    assert!(
        !has_entrypoint,
        "Dockerfile must not set ENTRYPOINT (D3 runs `image w014-parser-sandbox`)"
    );
    // No Python parser runtime in the final image definition.
    assert!(
        !df.contains("python-docx"),
        "Dockerfile must not introduce python-docx"
    );
    assert!(
        !df.contains("LibreOffice"),
        "Dockerfile must not introduce LibreOffice"
    );

    let sh = std::fs::read_to_string(&build_sh).expect("read build-image.sh");
    assert!(
        sh.contains("w014-parser-sandbox:local"),
        "build script must tag w014-parser-sandbox:local"
    );
    assert!(
        sh.contains("Dockerfile"),
        "build script must use the exact Dockerfile"
    );
}

// ---------------------------------------------------------------------------
// ACTUAL_DOCKER_RUNTIME via the authoritative ProcessSandboxRunner.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_production_image_pdf_real_docker_runtime() {
    if !require_live_runtime("pdf_real_docker_runtime") {
        return;
    }
    let pdf = sample_pdf_bytes("Executive Summary production image");
    let input = sample_input(PDF_MEDIA, pdf);
    let profile = SandboxSecurityProfile::frozen_default();
    // Production factory: default binary + platform docker wrapper + default image.
    let runner = create_default_sandbox_runner();

    let output = runner
        .run(&profile, &input)
        .await
        .expect("real PDF must execute inside the authoritative sandbox");
    assert_eq!(output.protocol_version, SANDBOX_PROTOCOL_VERSION);
    assert_eq!(output.status, SandboxStatus::Success);
    assert!(
        output.parser_name.contains("pdfium"),
        "PDF must use authoritative PDFium path, got '{}'",
        output.parser_name
    );
    assert!(output.page_count >= 1);
    assert!(output.parsed_artifact.is_some());
    output
        .validate_against_input(&input)
        .expect("protocol must validate");
}

#[tokio::test]
async fn test_production_image_docx_real_docker_runtime() {
    if !require_live_runtime("docx_real_docker_runtime") {
        return;
    }
    let input = sample_input(DOCX_MEDIA, MINIMAL_DOCX.to_vec());
    let profile = SandboxSecurityProfile::frozen_default();
    let runner = create_default_sandbox_runner();

    let output = runner
        .run(&profile, &input)
        .await
        .expect("real DOCX must execute inside the authoritative sandbox");
    assert_eq!(output.protocol_version, SANDBOX_PROTOCOL_VERSION);
    assert_eq!(output.status, SandboxStatus::Success);
    assert_eq!(
        output.parser_name, "w014-docx-safe-parser",
        "DOCX must use authoritative ooxmlsdk producer path"
    );
    output
        .validate_against_input(&input)
        .expect("protocol must validate");
}

#[tokio::test]
async fn test_production_image_docx_ocr_real_tesseract_runtime() {
    // Final OCR production-runtime evidence (W2 BLOCKED_D2_FINAL_IMAGE_OCR_RUNTIME_EVIDENCE).
    //
    // Path under proof:
    //   OCR-requiring DOCX -> create_default_sandbox_runner()
    //   -> ProcessSandboxRunner -> authoritative hardened Docker policy
    //   -> w014-parser-sandbox:local -> real w014-parser-sandbox
    //   -> DocxOcrProducer<ProcessTesseractEngine> -> real Tesseract.
    //
    // Fixture construction (verified by inspection, see
    // fixtures/ocr-runtime-two-image-sentinels.docx):
    //   - structurally valid DOCX / OOXML ZIP package,
    //   - word/document.xml contains zero <w:t> elements, so native text is
    //     EMPTY (length 0 < LOW_TEXT_CHAR_THRESHOLD 50),
    //   - word/media/image1.png + word/media/image2.png are valid PNG
    //     rasters (1600x500 each) on the single OCR page,
    //   - rasters carry deterministic high-contrast sentinel text
    //     "W014 OCR RUNTIME ALPHA" / "W014 OCR RUNTIME BETA", confirmed
    //     readable by the image's own Tesseract 5.3.0 as a supplemental
    //     fixture diagnostic.
    //
    // Combined OCR-necessity reasoning (no product change to expose ocr_used):
    //   fixture native text is empty, so a Success with non-empty
    //   text_sha256 plus non-zero block/span counts cannot come from native
    //   DOCX text and necessarily traversed the accepted D2 OCR fallback.
    //   The accepted parser binary binds this DOCX media path to
    //   DocxOcrProducer with the real ProcessTesseractEngine, and D2
    //   in-process tests prove the shared page-deadline semantics of that
    //   path. SandboxOutput exposes no full-text field for DOCX
    //   (parsed_artifact is None by product design), so the exact
    //   deterministic text_sha256 digest of the combined sentinel OCR text
    //   is asserted as the strongest observable proof.
    if !require_live_runtime("docx_ocr_real_tesseract_runtime") {
        return;
    }
    let input = sample_input(DOCX_MEDIA, OCR_DOCX.to_vec());
    let profile = SandboxSecurityProfile::frozen_default();
    // Exact real production runner: default binary + platform docker
    // wrapper + default w014-parser-sandbox:local image.
    let runner = create_default_sandbox_runner();

    let output = runner
        .run(&profile, &input)
        .await
        .expect("OCR DOCX must execute inside the authoritative sandbox");
    assert_eq!(output.protocol_version, SANDBOX_PROTOCOL_VERSION);
    assert_eq!(output.status, SandboxStatus::Success);
    assert_eq!(
        output.parser_name, "w014-docx-safe-parser",
        "OCR DOCX must use authoritative ooxmlsdk + OCR producer path"
    );
    output
        .validate_against_input(&input)
        .expect("protocol must validate");
    eprintln!(
        "OCR_RUNTIME_EVIDENCE parser={} pages={} blocks={} spans={} text_sha256={} parsed_artifact_present={}",
        output.parser_name,
        output.page_count,
        output.block_count,
        output.span_count,
        output
            .text_sha256
            .as_ref()
            .map(|h| h.to_hex())
            .unwrap_or_else(|| "<none>".to_string()),
        output.parsed_artifact.is_some()
    );
    // Single scanned page fixture: every media item shares this one OCR page.
    assert_eq!(
        output.page_count, 1,
        "OCR fixture must yield exactly one page"
    );
    assert!(
        output.block_count > 0,
        "OCR-derived text must produce blocks, got {}",
        output.block_count
    );
    assert!(
        output.span_count > 0,
        "OCR-derived text must produce spans, got {}",
        output.span_count
    );
    assert!(
        output.text_sha256.is_some(),
        "OCR-derived text must produce a non-empty text digest (native text is empty)"
    );
    // Exact deterministic OCR-content binding: with empty native text, the
    // producer adopts combined OCR text
    // "W014 OCR RUNTIME ALPHA\n" + "\n" + "W014 OCR RUNTIME BETA\n".
    // This digest is SHA256("W014 OCR RUNTIME ALPHA\n\nW014 OCR RUNTIME BETA\n").
    assert_eq!(
        output.text_sha256.as_ref().map(|h| h.to_hex()).as_deref(),
        Some("14e9a62298067c5e8a00356ae78622f81951a7f93df3f268eb95f122df265c2f"),
        "text digest must equal the deterministic OCR sentinel digest"
    );
}

#[tokio::test]
async fn test_production_image_missing_fails_closed() {
    if !docker_available() {
        if runtime_required() {
            panic!(
                "W014_REQUIRE_PRODUCTION_IMAGE_RUNTIME=1 but docker absent for image-missing probe"
            );
        }
        eprintln!("SKIP image_missing: docker absent");
        return;
    }
    let (docker, args) = ProcessSandboxRunner::platform_default_wrapper().expect("docker present");
    let input = sample_input(PDF_MEDIA, b"%PDF-1.7 probe".to_vec());
    let profile = SandboxSecurityProfile::frozen_default();
    let runner = ProcessSandboxRunner::new("w014-parser-sandbox")
        .with_oci_image("w014-parser-sandbox:nonexistent-404")
        .with_wrapper(docker, args);
    let err = runner.run(&profile, &input).await.unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        !dbg.contains("Success"),
        "missing image must never produce parser truth: {dbg}"
    );
}

#[tokio::test]
async fn test_production_image_malformed_input_fails_closed_no_success() {
    if !require_live_runtime("malformed_input") {
        return;
    }
    let bad = b"not a pdf at all".to_vec();
    let input = sample_input(PDF_MEDIA, bad);
    let profile = SandboxSecurityProfile::frozen_default();
    let runner = create_default_sandbox_runner();
    if let Ok(output) = runner.run(&profile, &input).await {
        assert_ne!(
            output.status,
            SandboxStatus::Success,
            "malformed input must never succeed"
        );
    }
}

#[test]
fn test_production_image_checksum_mismatch_fails_closed() {
    let pdf = sample_pdf_bytes("checksum probe");
    let wrong = Sha256::from_bytes([0xFF; 32]);
    let res = SandboxInput::new(
        WorkspaceId::new(),
        DocumentVersionId::new(),
        ObjectArtifactId::new(),
        Uuid::new_v4(),
        StoredMediaType::new(PDF_MEDIA).unwrap(),
        wrong,
        pdf.len() as i64,
        pdf,
    );
    assert!(
        res.is_err(),
        "checksum mismatch must fail closed with no parser truth"
    );
}

#[tokio::test]
async fn test_production_image_unsupported_media_fails_closed() {
    if !require_live_runtime("unsupported_media") {
        return;
    }
    let bytes = b"plain text bytes".to_vec();
    let input = sample_input("text/plain", bytes);
    let profile = SandboxSecurityProfile::frozen_default();
    let runner = create_default_sandbox_runner();
    let output = runner
        .run(&profile, &input)
        .await
        .expect("unsupported media must return typed envelope");
    assert_eq!(output.status, SandboxStatus::Unsupported);
    assert_ne!(output.status, SandboxStatus::Success);
}
