//! PDFium authoritative binding and backend integration (WI-0206).
//!
//! Provides bindings over version-pinned PDFium via `pdfium-render`.
//! PDFium remains the authoritative native PDF path (P0).
//!
//! When PDFium is missing, unverifiable, or encounters a parse/extraction rejection,
//! the pipeline MUST FAIL CLOSED. Heuristic fallback or silent downgrade is prohibited.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use pdfium_render::prelude::*;
use w014_domain::Sha256;

use super::failure::ParserFailure;

/// Pinned authoritative PDFium build number (Prompt-11R / WI-0206).
pub const PINNED_PDFIUM_BUILD: u32 = 7881;

/// Pinned authoritative PDFium major version.
pub const PINNED_PDFIUM_MAJOR: u32 = 151;

/// Pinned authoritative PDFium version identifier string.
pub const PINNED_PDFIUM_VERSION_STR: &str = "pdfium-151.0.7881.0";

/// Known authoritative cryptographic digests for pinned PDFium release binaries.
pub const KNOWN_AUTHORITATIVE_PDFIUM_SHA256: &[&str] = &[
    // macOS arm64 release build 7881
    "1bc45b15466b34cef96641ce25c77a876e70010c6b114f909dda2f5325fc5bd7",
];

static AUTHORITATIVE_PDFIUM: OnceLock<Pdfium> = OnceLock::new();
static PDFIUM_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes PDFium operations across threads to protect non-thread-safe C++ global state.
pub fn lock_pdfium() -> std::sync::MutexGuard<'static, ()> {
    PDFIUM_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Resolves the candidate path for the PDFium dynamic library.
fn resolve_candidate_library_path() -> Result<PathBuf, ParserFailure> {
    if let Ok(path_str) = std::env::var("PDFIUM_LIB_PATH") {
        let trimmed = path_str.trim();
        if trimmed.is_empty() {
            return Err(ParserFailure::PdfiumUnavailable(
                "PDFIUM_LIB_PATH environment variable is empty".to_string(),
            ));
        }
        let path = PathBuf::from(trimmed);
        if !path.exists() {
            return Err(ParserFailure::PdfiumUnavailable(format!(
                "Configured PDFIUM_LIB_PATH does not exist: {trimmed}"
            )));
        }
        if !path.is_file() {
            return Err(ParserFailure::PdfiumUnavailable(format!(
                "Configured PDFIUM_LIB_PATH is not a regular file: {trimmed}"
            )));
        }
        Ok(path)
    } else {
        // Check platform default library name in system library paths
        let default_name = Pdfium::pdfium_platform_library_name();
        let default_path = PathBuf::from(&default_name);
        if default_path.exists() && default_path.is_file() {
            Ok(default_path)
        } else {
            Err(ParserFailure::PdfiumUnavailable(
                "PDFium dynamic library is not installed or configured via PDFIUM_LIB_PATH"
                    .to_string(),
            ))
        }
    }
}

/// Verifies that the native library at `path` matches the pinned PDFium identity and version.
///
/// Fails closed if the identity or version cannot be proven.
pub fn verify_pdfium_library_identity(path: &Path) -> Result<(), ParserFailure> {
    let expected_sha = std::env::var("PDFIUM_EXPECTED_SHA256").ok();
    let expected_ver = std::env::var("PDFIUM_EXPECTED_VERSION").ok();
    verify_pdfium_library_identity_with_expected(
        path,
        expected_sha.as_deref(),
        expected_ver.as_deref(),
    )
}

/// Verifies that the native library at `path` matches the specified or pinned expected SHA-256 and version.
pub fn verify_pdfium_library_identity_with_expected(
    path: &Path,
    expected_sha256: Option<&str>,
    expected_version: Option<&str>,
) -> Result<(), ParserFailure> {
    if !path.exists() {
        return Err(ParserFailure::PdfiumUnavailable(format!(
            "PDFium dynamic library file not found at {path:?}"
        )));
    }

    // 1. Read binary bytes to compute SHA-256 identity digest
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ParserFailure::PdfiumUnavailable(format!(
                "PDFium dynamic library file not found at {path:?}"
            ))
        } else {
            ParserFailure::PdfiumBindFailure(format!(
                "Failed reading PDFium binary for identity verification at {path:?}: {e}"
            ))
        }
    })?;

    let actual_sha = Sha256::digest(&bytes).to_hex().to_lowercase();

    // 2. Validate expected SHA-256 digest
    if let Some(expected_sha) = expected_sha256 {
        let expected_clean = expected_sha.trim().to_lowercase();
        if actual_sha != expected_clean {
            return Err(ParserFailure::PdfiumUnverified(format!(
                "PDFium binary identity verification failed: expected SHA-256 '{expected_clean}', actual '{actual_sha}'"
            )));
        }
    } else {
        // Verify against pinned release catalog
        let matches_known = KNOWN_AUTHORITATIVE_PDFIUM_SHA256
            .iter()
            .any(|known| known.eq_ignore_ascii_case(&actual_sha));

        if !matches_known {
            return Err(ParserFailure::PdfiumUnverified(format!(
                "PDFium binary at {path:?} with SHA-256 '{actual_sha}' does not match any pinned authoritative release build"
            )));
        }
    }

    // 3. Validate expected version metadata if explicitly provided
    if let Some(expected_ver) = expected_version {
        let expected_clean = expected_ver.trim();
        let pinned_build_str = PINNED_PDFIUM_BUILD.to_string();
        if expected_clean != PINNED_PDFIUM_VERSION_STR && expected_clean != pinned_build_str {
            return Err(ParserFailure::PdfiumUnverified(format!(
                "Configured PDFIUM_EXPECTED_VERSION '{expected_clean}' does not match pinned build {PINNED_PDFIUM_BUILD}"
            )));
        }
    }

    Ok(())
}

/// Returns a reference to the global authoritative `Pdfium` instance.
///
/// # Errors
/// Fails closed with typed `ParserFailure` if the library is missing, cannot bind,
/// or fails identity/version verification.
pub fn get_authoritative_pdfium() -> Result<&'static Pdfium, ParserFailure> {
    if let Some(instance) = AUTHORITATIVE_PDFIUM.get() {
        return Ok(instance);
    }

    let _guard = lock_pdfium();
    if let Some(instance) = AUTHORITATIVE_PDFIUM.get() {
        return Ok(instance);
    }

    let lib_path = resolve_candidate_library_path()?;

    // Establish pinned identity & integrity before loading
    verify_pdfium_library_identity(&lib_path)?;

    // Dynamically bind to the verified native library
    let pdfium = match Pdfium::bind_to_library(&lib_path) {
        Ok(bindings) => {
            // Verify API version compatibility
            let api_version = bindings.version();
            if api_version != version::PdfiumApiVersion::V7881
                && api_version != version::PdfiumApiVersion::Future
            {
                return Err(ParserFailure::PdfiumUnverified(format!(
                    "Loaded PDFium bindings report API version {:?}, expected build {}",
                    api_version, PINNED_PDFIUM_BUILD
                )));
            }
            Pdfium::new(bindings)
        }
        Err(pdfium_render::prelude::PdfiumError::PdfiumLibraryBindingsAlreadyInitialized) => {
            Pdfium::default()
        }
        Err(e) => {
            return Err(ParserFailure::PdfiumBindFailure(format!(
                "Failed binding to authoritative PDFium library at {lib_path:?}: {e}"
            )));
        }
    };

    let _ = AUTHORITATIVE_PDFIUM.set(pdfium);

    Ok(AUTHORITATIVE_PDFIUM
        .get()
        .expect("AUTHORITATIVE_PDFIUM was just set"))
}

/// Returns a reference to the global `Pdfium` instance if successfully initialized and verified.
#[must_use]
pub fn get_pdfium() -> Option<&'static Pdfium> {
    get_authoritative_pdfium().ok()
}

/// Version information about the active PDFium engine.
#[must_use]
pub fn pdfium_version_info() -> String {
    if get_authoritative_pdfium().is_ok() {
        format!("pdfium-render-v0.9.3-dynamic-build-{}", PINNED_PDFIUM_BUILD)
    } else {
        "pdfium-render-unavailable".to_string()
    }
}
