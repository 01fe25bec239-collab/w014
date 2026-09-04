//! Concrete production parser sandbox executable (WI-0205 D3, Part B).
//!
//! Binary name: `w014-parser-sandbox` (repository/build truth owned by
//! `w014-document-processing`).
//!
//! Contract:
//! 1. Consumes the scoped `SandboxInput` handoff via `W014_*` environment
//!    identity plus bounded stdin object bytes (single-object, immutable).
//! 2. Validates protocol/input identity, declared length, and SHA-256.
//! 3. Dispatches ONLY supported W2 parser kinds/media:
//!    - `application/pdf` -> authoritative PDFium path (`PdfSafeParser`).
//!    - accepted DOCX media -> authoritative ooxmlsdk + OCR producer path
//!      (`DocxOcrProducer` with the real `ProcessTesseractEngine`).
//! 4. Emits the bounded `SandboxOutput` JSON protocol expected by
//!    `ParserSandboxJobExecutor` on stdout.
//! 5. Contains no DB credentials, no S3/KMS credentials, no AI credentials;
//!    performs no network fetch; never writes authoritative database truth
//!    itself (persistence stays outside the sandbox after output validation
//!    and lease fencing).
//! 6. Fails closed on malformed/unsupported input (valid `Failed`/
//!    `Corrupted`/`Unsupported` envelope when identity permits, otherwise a
//!    non-zero exit with no success output).

use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::AsyncReadExt;
use uuid::Uuid;
use w014_document_processing::docx_producer::{
    DOCX_LOCATOR_VERSION, DOCX_PARSER_NAME, DOCX_PARSER_VERSION, DocxOcrProducer,
};
use w014_document_processing::ocr::ProcessTesseractEngine;
use w014_document_processing::parser::pdfium_backend::PINNED_PDFIUM_VERSION_STR;
use w014_document_processing::parser::{
    DEFAULT_PARSER_PROFILE_VERSION, ParserLimits, ParserRequest, PdfSafeParser,
};
use w014_document_processing::sandbox::{
    SANDBOX_PROTOCOL_VERSION, SandboxInput, SandboxOutput, SandboxStatus,
};
use w014_domain::LocatorVersion;
use w014_domain::Sha256;
use w014_domain::StoredMediaType;
use w014_domain::ids::{DocumentVersionId, ObjectArtifactId, WorkspaceId};

/// Canonical PDF media type dispatched to the authoritative PDFium path.
const PDF_MEDIA_TYPE: &str = "application/pdf";

/// Accepted DOCX media type dispatched to the ooxmlsdk + OCR producer path.
const DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// Authoritative parser name proving the PDFium native path.
const PDFIUM_PARSER_NAME: &str = "w014-pdfium-safe-parser";

/// Upper bound for stdin object bytes (512 MiB, matching hostile package limits).
const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;

fn env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing required sandbox identity env '{name}'"))
}

fn parse_uuid_env(name: &str, raw: &str) -> Result<Uuid, String> {
    Uuid::parse_str(raw.trim())
        .map_err(|e| format!("invalid UUID in sandbox identity env '{name}': {e}"))
}

/// Emits a fail-closed envelope when full input identity is available.
fn emit_envelope(output: &SandboxOutput) -> ! {
    let mut stdout = std::io::stdout();
    // Protocol outputs are bounded by parser ceilings (<= 10 MiB envelope).
    let json =
        serde_json::to_string(output).unwrap_or_else(|_| "{\"status\":\"failed\"}".to_string());
    let _ = stdout.write_all(json.as_bytes());
    let _ = stdout.flush();
    std::process::exit(0);
}

/// Fails closed without a valid envelope (identity itself unusable).
fn abort_without_envelope(detail: &str) -> ! {
    let _ = writeln!(
        std::io::stderr(),
        "w014-parser-sandbox: fail-closed: {detail}"
    );
    std::process::exit(2);
}

#[allow(clippy::too_many_arguments)]
fn fail_output(
    input: &SandboxInput,
    status: SandboxStatus,
    failure_code: &str,
    failure_detail: &str,
    parser_name: &str,
    parser_version: &str,
    locator_version: LocatorVersion,
    duration_ms: u64,
) -> SandboxOutput {
    SandboxOutput {
        protocol_version: SANDBOX_PROTOCOL_VERSION.to_string(),
        document_version_id: input.document_version_id,
        object_artifact_id: input.object_artifact_id,
        input_sha256: input.content_sha256,
        status,
        parser_name: parser_name.to_string(),
        parser_version: parser_version.to_string(),
        locator_version,
        page_count: 0,
        block_count: 0,
        span_count: 0,
        text_sha256: None,
        execution_duration_ms: duration_ms,
        failure_code: Some(failure_code.to_string()),
        failure_detail: Some(failure_detail.to_string()),
        parsed_artifact: None,
    }
}

fn docx_status_for(err: &w014_document_processing::DocxError) -> SandboxStatus {
    use w014_document_processing::DocxError as E;
    match err {
        E::ExternalRelationship { .. }
        | E::RemoteTemplate { .. }
        | E::OleOrEmbeddedPackage { .. }
        | E::MacroEnabledPackage { .. }
        | E::DtdOrExternalEntity { .. }
        | E::PolyglotOrAmbiguousPackage { .. }
        | E::InvalidContentType { .. } => SandboxStatus::Unsupported,
        E::MissingRequiredPart { .. } | E::XmlParseError { .. } => SandboxStatus::Corrupted,
        E::HostilePackage(_)
        | E::PackageLimitsExceeded { .. }
        | E::Io { .. }
        | E::Internal { .. } => SandboxStatus::Failed,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let start = Instant::now();

    // ---- 1. Scoped identity via W014-controlled environment ----
    let protocol = env_var("W014_SANDBOX_PROTOCOL").unwrap_or_else(|e| abort_without_envelope(&e));
    let workspace_raw = env_var("W014_WORKSPACE_ID").unwrap_or_else(|e| abort_without_envelope(&e));
    let version_raw =
        env_var("W014_DOCUMENT_VERSION_ID").unwrap_or_else(|e| abort_without_envelope(&e));
    let artifact_raw =
        env_var("W014_OBJECT_ARTIFACT_ID").unwrap_or_else(|e| abort_without_envelope(&e));
    let job_raw = env_var("W014_JOB_ID").unwrap_or_else(|e| abort_without_envelope(&e));
    let media_raw = env_var("W014_MEDIA_TYPE").unwrap_or_else(|e| abort_without_envelope(&e));
    let sha_raw = env_var("W014_INPUT_SHA256").unwrap_or_else(|e| abort_without_envelope(&e));
    let len_raw = env_var("W014_BYTE_LENGTH").unwrap_or_else(|e| abort_without_envelope(&e));

    if protocol.trim() != SANDBOX_PROTOCOL_VERSION {
        abort_without_envelope(&format!(
            "protocol mismatch: expected '{SANDBOX_PROTOCOL_VERSION}', got '{protocol}'"
        ));
    }

    let workspace_id = WorkspaceId::from_uuid(
        parse_uuid_env("W014_WORKSPACE_ID", &workspace_raw)
            .unwrap_or_else(|e| abort_without_envelope(&e)),
    );
    let document_version_id = DocumentVersionId::from_uuid(
        parse_uuid_env("W014_DOCUMENT_VERSION_ID", &version_raw)
            .unwrap_or_else(|e| abort_without_envelope(&e)),
    );
    let object_artifact_id = ObjectArtifactId::from_uuid(
        parse_uuid_env("W014_OBJECT_ARTIFACT_ID", &artifact_raw)
            .unwrap_or_else(|e| abort_without_envelope(&e)),
    );
    let job_id =
        parse_uuid_env("W014_JOB_ID", &job_raw).unwrap_or_else(|e| abort_without_envelope(&e));
    let media_type = StoredMediaType::new(media_raw.trim())
        .unwrap_or_else(|e| abort_without_envelope(&format!("invalid media type: {e}")));
    let declared_sha = Sha256::from_hex("W014_INPUT_SHA256", sha_raw.trim())
        .unwrap_or_else(|e| abort_without_envelope(&format!("invalid declared SHA-256: {e}")));
    let declared_len: i64 = len_raw
        .trim()
        .parse()
        .unwrap_or_else(|_| abort_without_envelope("invalid declared byte length"));
    if declared_len < 0 {
        abort_without_envelope("declared byte length must be non-negative");
    }

    // ---- 2. Bounded stdin: ONLY the scoped single-object bytes ----
    let stdin = tokio::io::stdin();
    let mut bytes = Vec::new();
    {
        let mut limited = stdin.take(MAX_INPUT_BYTES + 1);
        if let Err(e) = limited.read_to_end(&mut bytes).await {
            abort_without_envelope(&format!("failed reading scoped stdin bytes: {e}"));
        }
    }
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        abort_without_envelope("scoped stdin bytes exceed 512 MiB bound");
    }

    // ---- 3. Length + SHA-256 validation (fail closed) ----
    // Build the minimal identity first so length/checksum failures can still
    // be reported as typed envelopes when identity parses.
    let duration_ms_so_far = || start.elapsed().as_millis() as u64;
    if bytes.len() as i64 != declared_len {
        // Length mismatch: report typed failure without accepting bytes.
        let locator =
            LocatorVersion::new(w014_document_processing::parser::DEFAULT_LOCATOR_VERSION)
                .unwrap_or_else(|e| abort_without_envelope(&format!("invalid locator: {e}")));
        // Fabricate the smallest verifiable input for envelope binding.
        let placeholder = SandboxInput::new(
            workspace_id,
            document_version_id,
            object_artifact_id,
            job_id,
            media_type,
            declared_sha,
            declared_len,
            bytes.clone(),
        );
        match placeholder {
            Ok(input) => {
                // Unreachable when lengths differ, kept for clarity.
                let output = fail_output(
                    &input,
                    SandboxStatus::Failed,
                    "INPUT_LENGTH_MISMATCH",
                    &format!(
                        "declared byte length {declared_len} != actual {}",
                        bytes.len()
                    ),
                    "w014-parser-sandbox",
                    "0.1.0",
                    locator,
                    duration_ms_so_far(),
                );
                emit_envelope(&output);
            }
            Err(detail) => {
                // Length mismatch confirmed: emit envelope bound to declared
                // identity with zeroed proof fields where possible.
                let _ = writeln!(
                    std::io::stderr(),
                    "w014-parser-sandbox: input length mismatch: {detail}"
                );
                // Cannot bind via SandboxInput::new; abort non-zero (fail closed,
                // never success). The runner maps this to ProcessCrash.
                std::process::exit(2);
            }
        }
    }
    let actual_sha = Sha256::digest(&bytes);
    if actual_sha != declared_sha {
        let _ = writeln!(
            std::io::stderr(),
            "w014-parser-sandbox: input SHA-256 mismatch: declared {}, actual {}",
            declared_sha.to_hex(),
            actual_sha.to_hex()
        );
        std::process::exit(2);
    }

    // Full scoped handoff verified.
    let input = SandboxInput::new(
        workspace_id,
        document_version_id,
        object_artifact_id,
        job_id,
        media_type.clone(),
        declared_sha,
        declared_len,
        bytes.clone(),
    )
    .unwrap_or_else(|e| abort_without_envelope(&format!("input integrity rejected: {e}")));

    // ---- 4. Dispatch only supported W2 parser kinds/media ----
    let media_str = media_type.as_str();
    if media_str == PDF_MEDIA_TYPE {
        run_pdf_path(&input, &bytes, start);
    }
    if media_str == DOCX_MEDIA_TYPE {
        run_docx_path(&input, start).await;
    }

    let locator = LocatorVersion::new(w014_document_processing::parser::DEFAULT_LOCATOR_VERSION)
        .unwrap_or_else(|e| abort_without_envelope(&format!("invalid locator: {e}")));
    let output = fail_output(
        &input,
        SandboxStatus::Unsupported,
        "UNSUPPORTED_MEDIA_TYPE",
        &format!("media type '{media_str}' is not in the supported W2 parser set"),
        "w014-parser-sandbox",
        "0.1.0",
        locator,
        start.elapsed().as_millis() as u64,
    );
    if output.validate_against_input(&input).is_err() {
        abort_without_envelope("failed constructing unsupported-media envelope");
    }
    emit_envelope(&output);
}

/// Authoritative PDFium path for `application/pdf`.
fn run_pdf_path(input: &SandboxInput, bytes: &[u8], start: Instant) -> ! {
    let locator = LocatorVersion::new(w014_document_processing::parser::DEFAULT_LOCATOR_VERSION)
        .unwrap_or_else(|e| abort_without_envelope(&format!("invalid locator: {e}")));
    let request = ParserRequest::new(
        input.object_artifact_id.to_string(),
        input.content_sha256,
        input.media_type.clone(),
        None,
        ParserLimits::pdf_frozen_default(),
        DEFAULT_PARSER_PROFILE_VERSION,
    )
    .unwrap_or_else(|e| abort_without_envelope(&format!("invalid parser request: {e}")));

    let parser = PdfSafeParser::new(ParserLimits::pdf_frozen_default());
    match parser.parse(&request, bytes) {
        Ok(artifact) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let output = SandboxOutput {
                protocol_version: SANDBOX_PROTOCOL_VERSION.to_string(),
                document_version_id: input.document_version_id,
                object_artifact_id: input.object_artifact_id,
                input_sha256: input.content_sha256,
                status: SandboxStatus::Success,
                parser_name: PDFIUM_PARSER_NAME.to_string(),
                parser_version: PINNED_PDFIUM_VERSION_STR.to_string(),
                locator_version: locator,
                page_count: artifact.page_count as i32,
                block_count: artifact.blocks.len() as i32,
                span_count: artifact.spans.len() as i32,
                text_sha256: Some(artifact.text_sha256),
                execution_duration_ms: duration_ms,
                failure_code: None,
                failure_detail: None,
                parsed_artifact: Some(artifact),
            };
            if output.validate_against_input(input).is_err() {
                abort_without_envelope("constructed PDF output failed validation");
            }
            emit_envelope(&output);
        }
        Err(failure) => {
            let output = fail_output(
                input,
                failure.status(),
                failure.failure_code(),
                &failure.detail(),
                PDFIUM_PARSER_NAME,
                PINNED_PDFIUM_VERSION_STR,
                locator,
                start.elapsed().as_millis() as u64,
            );
            if output.validate_against_input(input).is_err() {
                abort_without_envelope("constructed PDF failure output failed validation");
            }
            emit_envelope(&output);
        }
    }
}

/// Authoritative ooxmlsdk + OCR producer path for accepted DOCX media.
async fn run_docx_path(input: &SandboxInput, start: Instant) -> ! {
    let engine: Arc<ProcessTesseractEngine> = Arc::new(ProcessTesseractEngine::default());
    let producer = DocxOcrProducer::new(engine);
    match producer.process_sandbox_input(input).await {
        Ok(out) => {
            if out.sandbox_output.validate_against_input(input).is_err() {
                abort_without_envelope("constructed DOCX output failed validation");
            }
            // Authoritative producer envelope already carries the DOCX parser
            // name/version and bounded counts.
            let _ = start;
            emit_envelope(&out.sandbox_output);
        }
        Err(docx_err) => {
            let locator = LocatorVersion::new(DOCX_LOCATOR_VERSION)
                .unwrap_or_else(|e| abort_without_envelope(&format!("invalid locator: {e}")));
            let output = fail_output(
                input,
                docx_status_for(&docx_err),
                docx_err.failure_code(),
                &docx_err.to_string(),
                DOCX_PARSER_NAME,
                DOCX_PARSER_VERSION,
                locator,
                start.elapsed().as_millis() as u64,
            );
            if output.validate_against_input(input).is_err() {
                abort_without_envelope("constructed DOCX failure output failed validation");
            }
            emit_envelope(&output);
        }
    }
}
