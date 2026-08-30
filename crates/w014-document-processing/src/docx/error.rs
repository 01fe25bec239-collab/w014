//! DOCX / OOXML fail-closed error taxonomy (WI-0207).

use thiserror::Error;

/// Fail-closed error taxonomy for DOCX / OOXML package and parsing operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DocxError {
    #[error("Hostile package detected: {0}")]
    HostilePackage(String),

    #[error("Package limit exceeded for '{limit_name}': actual {actual}, maximum allowed {limit}")]
    PackageLimitsExceeded {
        limit_name: &'static str,
        actual: u64,
        limit: u64,
    },

    #[error("External relationship rejected: type '{relationship_type}', target '{target}'")]
    ExternalRelationship {
        target: String,
        relationship_type: String,
    },

    #[error("Remote template rejected: target '{target}'")]
    RemoteTemplate { target: String },

    #[error("OLE or embedded package is unsupported: {detail}")]
    OleOrEmbeddedPackage { detail: String },

    #[error("Macro-enabled DOCX/DOCM is rejected: {detail}")]
    MacroEnabledPackage { detail: String },

    #[error("DTD or external entity declaration rejected in XML part: {detail}")]
    DtdOrExternalEntity { detail: String },

    #[error("Ambiguous or polyglot OOXML package rejected: {detail}")]
    PolyglotOrAmbiguousPackage { detail: String },

    #[error("Invalid or missing OOXML content type: {detail}")]
    InvalidContentType { detail: String },

    #[error("Missing required OOXML package part: '{part_name}'")]
    MissingRequiredPart { part_name: &'static str },

    #[error("XML parsing error in part '{part_name}': {detail}")]
    XmlParseError { part_name: String, detail: String },

    #[error("I/O error during DOCX processing: {detail}")]
    Io { detail: String },

    #[error("Internal error during DOCX processing: {detail}")]
    Internal { detail: String },
}

impl DocxError {
    /// Returns a machine-readable failure code suitable for `SandboxOutput` or audit records.
    #[must_use]
    pub const fn failure_code(&self) -> &'static str {
        match self {
            Self::HostilePackage(_) => "OOXML_HOSTILE_PACKAGE",
            Self::PackageLimitsExceeded { .. } => "OOXML_RESOURCE_LIMIT_EXCEEDED",
            Self::ExternalRelationship { .. } => "OOXML_EXTERNAL_RELATIONSHIP_REJECTED",
            Self::RemoteTemplate { .. } => "OOXML_REMOTE_TEMPLATE_REJECTED",
            Self::OleOrEmbeddedPackage { .. } => "OOXML_OLE_UNSUPPORTED",
            Self::MacroEnabledPackage { .. } => "OOXML_MACRO_REJECTED",
            Self::DtdOrExternalEntity { .. } => "OOXML_DTD_EXTERNAL_ENTITY_REJECTED",
            Self::PolyglotOrAmbiguousPackage { .. } => "OOXML_POLYGLOT_REJECTED",
            Self::InvalidContentType { .. } => "OOXML_INVALID_CONTENT_TYPE",
            Self::MissingRequiredPart { .. } => "OOXML_MISSING_PART",
            Self::XmlParseError { .. } => "OOXML_XML_PARSE_ERROR",
            Self::Io { .. } => "DOCX_IO_ERROR",
            Self::Internal { .. } => "DOCX_INTERNAL_ERROR",
        }
    }
}
