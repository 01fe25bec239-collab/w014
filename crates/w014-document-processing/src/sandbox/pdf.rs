//! PDF Safe-Subset Sandbox Runner implementation (WI-0206).
//!
//! Executes `PdfSafeParser` strictly within the bounds defined by `SandboxSecurityProfile`.
//! Enforces zero direct database writes from parser execution and returns typed `SandboxOutput`.

use std::time::Instant;

use async_trait::async_trait;

use super::error::SandboxError;
use super::input::SandboxInput;
use super::output::{SANDBOX_PROTOCOL_VERSION, SandboxOutput, SandboxStatus};
use super::profile::SandboxSecurityProfile;
use super::traits::SandboxRunner;
use crate::parser::pdf_parser::PdfSafeParser;
use crate::parser::request::{
    DEFAULT_LOCATOR_VERSION, DEFAULT_PARSER_PROFILE_VERSION, ParserLimits, ParserRequest,
};

/// Sandbox runner executing PDF safe-subset parsing.
#[derive(Debug, Clone)]
pub struct PdfSandboxRunner {
    parser: PdfSafeParser,
}

impl Default for PdfSandboxRunner {
    fn default() -> Self {
        Self::new(ParserLimits::pdf_frozen_default())
    }
}

impl PdfSandboxRunner {
    /// Creates a new `PdfSandboxRunner` with the given limits.
    #[must_use]
    pub fn new(limits: ParserLimits) -> Self {
        Self {
            parser: PdfSafeParser::new(limits),
        }
    }
}

#[async_trait]
impl SandboxRunner for PdfSandboxRunner {
    async fn run(
        &self,
        profile: &SandboxSecurityProfile,
        input: &SandboxInput,
    ) -> Result<SandboxOutput, SandboxError> {
        // 1. Validate security profile
        profile
            .validate()
            .map_err(|detail| SandboxError::SandboxViolation {
                violation_type: "INVALID_PROFILE".to_string(),
                detail,
            })?;

        // 2. Verify input integrity before execution
        input.verify_integrity().map_err(|detail| {
            SandboxError::OutputValidation(super::output::OutputValidationError::InvalidField {
                field: "input_integrity",
                reason: detail,
            })
        })?;

        let start = Instant::now();

        // 3. Build parser request
        let request = ParserRequest::new(
            input.object_artifact_id.to_string(),
            input.content_sha256,
            input.media_type.clone(),
            None,
            ParserLimits::pdf_frozen_default(),
            DEFAULT_PARSER_PROFILE_VERSION,
        )
        .map_err(|e| SandboxError::Internal { detail: e })?;

        // 4. Execute PDF Safe Parser
        let result = self.parser.parse(&request, &input.bytes);
        let duration_ms = start.elapsed().as_millis() as u64;

        let locator_version =
            w014_domain::LocatorVersion::new(DEFAULT_LOCATOR_VERSION).map_err(|e| {
                SandboxError::Internal {
                    detail: e.to_string(),
                }
            })?;

        match result {
            Ok(artifact) => {
                let output = SandboxOutput {
                    protocol_version: SANDBOX_PROTOCOL_VERSION.to_string(),
                    document_version_id: input.document_version_id,
                    object_artifact_id: input.object_artifact_id,
                    input_sha256: input.content_sha256,
                    status: SandboxStatus::Success,
                    parser_name: "pdf-safe-parser".to_string(),
                    parser_version: "1.0.0".to_string(),
                    locator_version,
                    page_count: artifact.page_count as i32,
                    block_count: artifact.blocks.len() as i32,
                    span_count: artifact.spans.len() as i32,
                    text_sha256: Some(artifact.text_sha256),
                    execution_duration_ms: duration_ms,
                    failure_code: None,
                    failure_detail: None,
                    parsed_artifact: Some(artifact),
                };

                output
                    .validate_against_input(input)
                    .map_err(SandboxError::OutputValidation)?;

                Ok(output)
            }
            Err(failure) => {
                let status = failure.status();
                let code = failure.failure_code().to_string();
                let detail = failure.detail();

                let output = SandboxOutput {
                    protocol_version: SANDBOX_PROTOCOL_VERSION.to_string(),
                    document_version_id: input.document_version_id,
                    object_artifact_id: input.object_artifact_id,
                    input_sha256: input.content_sha256,
                    status,
                    parser_name: "pdf-safe-parser".to_string(),
                    parser_version: "1.0.0".to_string(),
                    locator_version,
                    page_count: 0,
                    block_count: 0,
                    span_count: 0,
                    text_sha256: None,
                    execution_duration_ms: duration_ms,
                    failure_code: Some(code),
                    failure_detail: Some(detail),
                    parsed_artifact: None,
                };

                output
                    .validate_against_input(input)
                    .map_err(SandboxError::OutputValidation)?;

                Ok(output)
            }
        }
    }
}
