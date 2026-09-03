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
    // macOS x86_64 release build 7881
    "4eaad6c3e8d786cf6f66a45d7d014edf5c65f372f98c3070e66595ebb50e43d9",
    // Linux x86_64 release build 7881
    "f728930966f503652b92acc89b9374a2eeca00ce42e26dccd3e4b5c5161b2d64",
    // Linux aarch64 release build 7881
    "6252fce3da45e7f0dc5b27f4d4e1a1456ca3f7734cdb04f927967df772127478",
];

static AUTHORITATIVE_PDFIUM: OnceLock<Pdfium> = OnceLock::new();
static PDFIUM_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes PDFium operations across threads to protect non-thread-safe C++ global state.
pub fn lock_pdfium() -> std::sync::MutexGuard<'static, ()> {
    PDFIUM_SERIALIZE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Resolves the candidate path for the PDFium dynamic library.
///
/// Discovers candidates deterministically from:
/// 1. `PDFIUM_LIB_PATH` environment variable (file or directory).
/// 2. Crate and repository fixture directories.
/// 3. Relative working directory and crate paths.
/// 4. Executable / Cargo target directories.
/// 5. Dynamic linker search directories (`DYLD_LIBRARY_PATH` / `LD_LIBRARY_PATH`).
/// 6. Standard platform system library locations.
///
/// Security:
/// Candidate path alone is NOT authority; filename alone is NOT authority.
/// Candidates MUST undergo cryptographic binary SHA-256 and version verification.
/// An unverified candidate causes immediate fail-closed rejection.
pub fn resolve_candidate_library_path() -> Result<PathBuf, ParserFailure> {
    let platform_name = Pdfium::pdfium_platform_library_name();

    // 1. Explicit override via PDFIUM_LIB_PATH
    if let Ok(path_str) = std::env::var("PDFIUM_LIB_PATH") {
        let trimmed = path_str.trim();
        if trimmed.is_empty() {
            return Err(ParserFailure::PdfiumUnavailable(
                "PDFIUM_LIB_PATH environment variable is empty".to_string(),
            ));
        }
        let raw_path = PathBuf::from(trimmed);
        let resolved = if raw_path.is_dir() {
            raw_path.join(&platform_name)
        } else {
            raw_path
        };
        if !resolved.exists() {
            return Err(ParserFailure::PdfiumUnavailable(format!(
                "Configured PDFIUM_LIB_PATH does not exist: {trimmed}"
            )));
        }
        if !resolved.is_file() {
            return Err(ParserFailure::PdfiumUnavailable(format!(
                "Configured PDFIUM_LIB_PATH is not a regular file: {trimmed}"
            )));
        }
        // Explicitly configured path must be verified
        verify_pdfium_library_identity(&resolved)?;
        return Ok(resolved);
    }

    // 2. Discover deterministic platform candidates
    let mut candidate_paths: Vec<PathBuf> = Vec::new();

    // Crate and repository fixture paths
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidate_paths.push(manifest_dir.join("fixtures").join(&platform_name));
    candidate_paths.push(manifest_dir.join("lib").join(&platform_name));
    candidate_paths.push(
        manifest_dir
            .join("../..")
            .join("fixtures")
            .join(&platform_name),
    );

    // Working directory and relative workspace paths
    candidate_paths
        .push(PathBuf::from("crates/w014-document-processing/fixtures").join(&platform_name));
    candidate_paths.push(PathBuf::from("fixtures").join(&platform_name));
    candidate_paths.push(PathBuf::from(&platform_name));

    // Executable directory and Target directory paths
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        candidate_paths.push(exe_dir.join(&platform_name));
        candidate_paths.push(exe_dir.join("deps").join(&platform_name));
        if let Some(parent) = exe_dir.parent() {
            candidate_paths.push(parent.join(&platform_name));
        }
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let t = PathBuf::from(target_dir.trim());
        candidate_paths.push(t.join(&platform_name));
        candidate_paths.push(t.join("debug").join(&platform_name));
        candidate_paths.push(t.join("release").join(&platform_name));
    }

    // Dynamic linker library search paths
    #[cfg(target_os = "macos")]
    let dyld_var = "DYLD_LIBRARY_PATH";
    #[cfg(not(target_os = "macos"))]
    let dyld_var = "LD_LIBRARY_PATH";
    if let Ok(lib_paths) = std::env::var(dyld_var) {
        for dir in std::env::split_paths(&lib_paths) {
            candidate_paths.push(dir.join(&platform_name));
        }
    }

    // Standard platform system library locations
    #[cfg(target_os = "macos")]
    {
        candidate_paths.push(PathBuf::from("/opt/homebrew/lib").join(&platform_name));
        candidate_paths.push(PathBuf::from("/usr/local/lib").join(&platform_name));
        candidate_paths.push(PathBuf::from("/usr/lib").join(&platform_name));
    }
    #[cfg(target_os = "linux")]
    {
        candidate_paths.push(PathBuf::from("/usr/local/lib").join(&platform_name));
        candidate_paths.push(PathBuf::from("/usr/lib").join(&platform_name));
        candidate_paths.push(PathBuf::from("/usr/lib/x86_64-linux-gnu").join(&platform_name));
        candidate_paths.push(PathBuf::from("/usr/lib/aarch64-linux-gnu").join(&platform_name));
        candidate_paths.push(PathBuf::from("/lib").join(&platform_name));
    }
    #[cfg(target_os = "windows")]
    {
        candidate_paths.push(PathBuf::from(r"C:\Windows\System32").join(&platform_name));
    }

    // Evaluate candidates deterministically:
    // If a candidate exists, it MUST pass identity and version verification.
    // An unverified candidate file fails closed immediately.
    for candidate in candidate_paths {
        if candidate.exists() && candidate.is_file() {
            // Verify binary hash and version
            verify_pdfium_library_identity(&candidate)?;
            return Ok(candidate);
        }
    }

    Err(ParserFailure::PdfiumUnavailable(
        "PDFium dynamic library is not installed or configured via PDFIUM_LIB_PATH".to_string(),
    ))
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
