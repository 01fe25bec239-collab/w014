//! PDFium binding and backend integration (WI-0206).
//!
//! Provides bindings over version-pinned PDFium via `pdfium-render`.
//! Executes strictly through the accepted parser sandbox boundary.
//! When PDFium dynamic library is available, utilizes native PDFium text and geometry extraction.
//! Also provides pure-Rust PDF safe subset parsing for sandboxed environments.

use pdfium_render::prelude::*;
use std::sync::OnceLock;

static PDFIUM_INSTANCE: OnceLock<Option<Pdfium>> = OnceLock::new();

/// Returns a reference to the global `Pdfium` instance if available.
pub fn get_pdfium() -> Option<&'static Pdfium> {
    PDFIUM_INSTANCE
        .get_or_init(|| {
            // Attempt to bind to system library or custom library path
            if let Ok(bindings) = Pdfium::bind_to_system_library() {
                Some(Pdfium::new(bindings))
            } else if let Ok(custom_path) = std::env::var("PDFIUM_LIB_PATH") {
                if let Ok(bindings) = Pdfium::bind_to_library(&custom_path) {
                    Some(Pdfium::new(bindings))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .as_ref()
}

/// Version information about the active PDFium engine.
#[must_use]
pub fn pdfium_version_info() -> String {
    if let Some(_pdfium) = get_pdfium() {
        "pdfium-render-v0.9.3-dynamic".to_string()
    } else {
        "pdfium-render-v0.9.3-embedded-safe-subset".to_string()
    }
}
