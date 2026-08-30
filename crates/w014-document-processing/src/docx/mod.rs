//! DOCX safe subset processing and OOXML security package preflight (WI-0207).

pub mod error;
pub mod package;
pub mod parser;

pub use error::DocxError;
pub use package::{
    DocxMediaItem, DocxPackage, MAX_AGGREGATE_COMPRESSION_RATIO, MAX_PART_SIZE,
    MAX_PER_ENTRY_COMPRESSION_RATIO, MAX_TOTAL_EXPANDED_BYTES, MAX_XML_PART_SIZE,
    MAX_ZIP_ENTRY_COUNT, validate_xml_security,
};
pub use parser::{DocxParser, ParsedDocxBlock, ParsedDocxDocument, ParsedDocxPage};
