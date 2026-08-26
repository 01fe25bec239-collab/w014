//! Frozen WI-0201 Document-Pipeline bounds.
//!
//! These constants are part of the frozen contract surface; they are not
//! tunable configuration. Domain validation and the repaired M002R physical
//! CHECK constraints must agree on these bounds.

/// Exact SHA-256 digest width in bytes.
pub const SHA256_BYTE_LEN: usize = 32;

/// Minimum upload size in bytes (uploads are non-empty).
pub const MIN_UPLOAD_BYTES: i64 = 1;

/// Maximum upload size in bytes: the frozen 100 MiB upload limit.
pub const MAX_UPLOAD_BYTES: i64 = 100 * 1024 * 1024;

/// Maximum upload-intent lifetime in seconds: expiry <= 10 minutes.
pub const MAX_INTENT_TTL_SECS: i64 = 600;

/// Maximum byte length of a logical document display title.
pub const MAX_TITLE_BYTES: usize = 512;

/// Maximum byte length of an original filename (display metadata only).
pub const MAX_FILENAME_BYTES: usize = 255;

/// Maximum byte length of a server-owned object key (matches physical CHECK).
pub const MAX_OBJECT_KEY_BYTES: usize = 1024;

/// Maximum bounded page count / page number for P0 documents.
pub const MAX_PAGE_NUMBER: u32 = 10_000;

/// Maximum canonical span text length in bytes (64 KiB).
pub const MAX_SPAN_TEXT_BYTES: usize = 64 * 1024;

/// Maximum serialized byte length of one bounded typed JSON snapshot.
pub const MAX_METADATA_JSON_BYTES: usize = 64 * 1024;

/// Maximum depth of a section path.
pub const MAX_SECTION_DEPTH: usize = 16;

/// Maximum byte length of one section-path segment.
pub const MAX_SECTION_SEGMENT_BYTES: usize = 256;

/// Maximum byte length of scanner identity / producer names / labels.
pub const MAX_SHORT_LABEL_BYTES: usize = 256;

/// Maximum byte length of a quarantine reason code.
pub const MAX_REASON_CODE_BYTES: usize = 128;
