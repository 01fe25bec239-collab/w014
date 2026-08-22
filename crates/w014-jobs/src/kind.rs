//! Closed, non-AI W2 job-kind vocabulary.
//!
//! 0201-B supplies execution AUTHORITY only: the runtime knows how to enqueue,
//! claim, fence, retry, and complete these kinds. It deliberately does NOT
//! implement the ClamAV scanner, PDF/DOCX parsers, or OCR engines themselves
//! (WI-0204..0207). AI task kinds are forbidden in W2.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::JobError;

/// Canonical frozen queue identity for document malware-scan jobs.
pub const QUEUE_MALWARE_SCAN: &str = "documents.malware_scan";

/// Canonical frozen queue identity for document parse jobs.
pub const QUEUE_DOCUMENT_PARSE: &str = "documents.parse";

/// Closed W2 (non-AI) durable job kinds required for malware scan and
/// document parse execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// Malware scan of a single immutable document version (PDF path).
    MalwareScanDocumentPdf,
    /// Malware scan of a single immutable document version (DOCX/OCR path).
    MalwareScanDocumentDocxOcr,
    /// Parse of a scanned/born-digital PDF document version.
    ParseDocumentPdf,
    /// Parse of a DOCX document version with the OCR fallback path.
    ParseDocumentDocxOcr,
}

impl JobKind {
    /// Exact frozen PostgreSQL `jobs.job_type` representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MalwareScanDocumentPdf => "malware_scan_document_pdf",
            Self::MalwareScanDocumentDocxOcr => "malware_scan_document_docx_ocr",
            Self::ParseDocumentPdf => "parse_document_pdf",
            Self::ParseDocumentDocxOcr => "parse_document_docx_ocr",
        }
    }

    /// Parses a stored `jobs.job_type` value into the closed kind vocabulary.
    ///
    /// Unknown strings are rejected: no dynamic/open-ended kind authority.
    pub fn parse(raw: &str) -> Result<Self, JobError> {
        match raw {
            "malware_scan_document_pdf" => Ok(Self::MalwareScanDocumentPdf),
            "malware_scan_document_docx_ocr" => Ok(Self::MalwareScanDocumentDocxOcr),
            "parse_document_pdf" => Ok(Self::ParseDocumentPdf),
            "parse_document_docx_ocr" => Ok(Self::ParseDocumentDocxOcr),
            other => Err(JobError::InvalidJobKind(format!(
                "'{other}' is not a closed W2 job kind"
            ))),
        }
    }

    /// Canonical frozen queue this kind is enqueued onto.
    #[must_use]
    pub const fn default_queue(&self) -> &'static str {
        match self {
            Self::MalwareScanDocumentPdf | Self::MalwareScanDocumentDocxOcr => QUEUE_MALWARE_SCAN,
            Self::ParseDocumentPdf | Self::ParseDocumentDocxOcr => QUEUE_DOCUMENT_PARSE,
        }
    }
}

impl fmt::Display for JobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_kind_vocabulary_round_trips() {
        let all = [
            JobKind::MalwareScanDocumentPdf,
            JobKind::MalwareScanDocumentDocxOcr,
            JobKind::ParseDocumentPdf,
            JobKind::ParseDocumentDocxOcr,
        ];
        for kind in all {
            assert_eq!(JobKind::parse(kind.as_str()), Ok(kind));
        }
    }

    #[test]
    fn unknown_and_ai_kinds_are_rejected() {
        for unknown in [
            "document_parse",
            "ai_completion",
            "report_generation",
            "",
            "PARSE_DOCUMENT_PDF",
        ] {
            assert!(
                JobKind::parse(unknown).is_err(),
                "'{unknown}' must not parse"
            );
        }
    }

    #[test]
    fn queue_identity_is_canonical() {
        assert_eq!(
            JobKind::MalwareScanDocumentPdf.default_queue(),
            QUEUE_MALWARE_SCAN
        );
        assert_eq!(
            JobKind::MalwareScanDocumentDocxOcr.default_queue(),
            QUEUE_MALWARE_SCAN
        );
        assert_eq!(
            JobKind::ParseDocumentPdf.default_queue(),
            QUEUE_DOCUMENT_PARSE
        );
        assert_eq!(
            JobKind::ParseDocumentDocxOcr.default_queue(),
            QUEUE_DOCUMENT_PARSE
        );
    }
}
