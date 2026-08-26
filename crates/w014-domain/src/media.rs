//! Closed media-type domains for the P0 document pipeline.
//!
//! Uploads and immutable document versions accept only the frozen P0 media
//! types. Object artifacts retain their media type as inert data (media type
//! is never an authority), validated only for well-formedness.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::validation::validate_non_empty;

/// Frozen P0 upload/version media-type allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MediaType {
    /// `application/pdf` — P0 PDF path.
    ApplicationPdf,
    /// Frozen DOCX MIME type — P0 DOCX/OCR path.
    Docx,
}

impl MediaType {
    /// Exact canonical MIME representation stored in physical columns
    /// (`upload_intents.expected_media_type`, `document_versions.content_type`).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ApplicationPdf => "application/pdf",
            Self::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        }
    }

    /// Parses a stored media type into the closed P0 allowlist.
    ///
    /// Unknown strings are rejected: no open-ended media-type authority for
    /// uploads or versions.
    ///
    /// # Errors
    /// Fails closed on any value outside the frozen P0 allowlist.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "application/pdf" => Ok(Self::ApplicationPdf),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
                Ok(Self::Docx)
            }
            other => Err(DomainError::ValidationError {
                field: "media_type",
                reason: format!("'{other}' is not in the frozen P0 media-type allowlist"),
            }),
        }
    }
}

/// Media type retained as inert data on object artifacts.
///
/// Unlike [`MediaType`], this is not an allowlist: artifact media type is
/// retained descriptive data with no trust authority. It is still validated
/// to be a bounded, printable, slash-separated token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StoredMediaType(String);

impl StoredMediaType {
    /// Validates and wraps an artifact media type as data.
    ///
    /// # Errors
    /// Fails closed when empty, over 255 bytes, non-ASCII, containing control
    /// characters, or missing the `/` separator.
    pub fn new(raw: impl AsRef<str>) -> Result<Self, DomainError> {
        let raw = validate_non_empty("stored_media_type", raw.as_ref())?;
        if raw.len() > 255 {
            return Err(DomainError::ValidationError {
                field: "stored_media_type",
                reason: format!("media type exceeds 255 bytes: {}", raw.len()),
            });
        }
        if !raw.is_ascii() || raw.chars().any(char::is_control) {
            return Err(DomainError::ValidationError {
                field: "stored_media_type",
                reason: "media type must be ASCII without control characters".to_string(),
            });
        }
        if !raw.contains('/') {
            return Err(DomainError::ValidationError {
                field: "stored_media_type",
                reason: format!("'{raw}' is not a type/subtype pair"),
            });
        }
        Ok(Self(raw.to_string()))
    }

    /// The retained media-type data.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p0_allowlist_is_closed() {
        assert_eq!(
            MediaType::parse("application/pdf").unwrap().as_str(),
            "application/pdf"
        );
        assert!(MediaType::parse("text/html").is_err());
        assert!(MediaType::parse("application/x-msdownload").is_err());
        assert!(MediaType::parse("").is_err());
    }

    #[test]
    fn test_stored_media_type_wellformedness() {
        assert!(StoredMediaType::new("application/octet-stream").is_ok());
        assert!(StoredMediaType::new("noslash").is_err());
        assert!(StoredMediaType::new("a\nb/c").is_err());
        let big = "a/".repeat(200);
        assert!(StoredMediaType::new(big).is_err());
    }
}
