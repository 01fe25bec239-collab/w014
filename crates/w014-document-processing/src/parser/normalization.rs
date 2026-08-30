//! Text normalization and evidence preservation (WI-0206).
//!
//! Enforces:
//! - Preservation of original evidence (raw character and byte offsets)
//! - Authoritative derived normalization is Unicode Normalization Form C (NFC)
//! - NFKC is STRICTLY PROHIBITED as authoritative text (`NFKC_AS_AUTHORITATIVE: NO`)
//! - Zero-width and control characters are preserved in original stream and flagged as warnings
//! - Bidirectional text: logical character sequence is preserved; NEVER visually reordered
//! - Confusable / homoglyph detection and flagging

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// Warning produced during text normalization and analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TextWarning {
    /// Machine-readable warning code.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// 0-based character offset in raw text where warning was triggered, if localized.
    pub raw_char_offset: Option<usize>,
}

/// Result of normalizing raw extracted text to canonical NFC form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationResult {
    /// Exact raw input text (preserved original evidence).
    pub raw_text: String,
    /// Canonical NFC normalized text (authoritative normalized text).
    pub normalized_text: String,
    /// Character offset map: index `i` in `normalized_text` (char index) maps to
    /// corresponding start char index in `raw_text`.
    pub norm_to_raw_char_map: Vec<usize>,
    /// Warnings triggered during normalization (zero-width, control, bidi, confusables).
    pub warnings: Vec<TextWarning>,
}

/// Normalizes raw text to canonical NFC form, tracking offset mapping and safety warnings.
///
/// # Invariants
/// - NFC is used for `normalized_text`.
/// - NFKC is NEVER applied to authoritative text.
/// - Original bytes and logical ordering are strictly preserved in `raw_text`.
#[must_use]
pub fn normalize_text_nfc(raw: &str) -> NormalizationResult {
    let mut warnings = Vec::new();

    // 1. Scan for safety warnings (zero-width, control, bidi, confusables)
    scan_unicode_safety_warnings(raw, &mut warnings);

    // 2. Compute NFC normalization per combining sequence unit
    let mut normalized_text = String::with_capacity(raw.len());
    let mut norm_to_raw_char_map = Vec::new();

    let raw_chars: Vec<char> = raw.chars().collect();
    let mut i = 0;

    while i < raw_chars.len() {
        let raw_start_idx = i;
        let mut unit_str = String::new();
        unit_str.push(raw_chars[i]);
        i += 1;

        // Collect any subsequent combining marks into this unit
        while i < raw_chars.len() && is_combining_character(raw_chars[i]) {
            unit_str.push(raw_chars[i]);
            i += 1;
        }

        // Normalize unit to NFC
        for nfc_ch in unit_str.nfc() {
            norm_to_raw_char_map.push(raw_start_idx);
            normalized_text.push(nfc_ch);
        }
    }

    NormalizationResult {
        raw_text: raw.to_string(),
        normalized_text,
        norm_to_raw_char_map,
        warnings,
    }
}

/// Determines whether a character is a Unicode combining character.
#[must_use]
pub fn is_combining_character(ch: char) -> bool {
    // Unicode combining character ranges (Mn, Mc, Me)
    matches!(ch,
        '\u{0300}'..='\u{036F}'   // Combining Diacritical Marks
        | '\u{1AB0}'..='\u{1AFF}' // Combining Diacritical Marks Extended
        | '\u{1DC0}'..='\u{1DFF}' // Combining Diacritical Marks Supplement
        | '\u{20D0}'..='\u{20FF}' // Combining Diacritical Marks for Symbols
        | '\u{FE20}'..='\u{FE2F}' // Combining Half Marks
    )
}

/// Maps a half-open normalized character offset range `[norm_start, norm_end)`
/// to its corresponding raw character offset range `[raw_start, raw_end)`.
#[must_use]
pub fn map_normalized_range_to_raw(
    norm_start: u32,
    norm_end: u32,
    norm_to_raw: &[usize],
    raw_len_chars: usize,
) -> (u32, u32) {
    if norm_to_raw.is_empty() || norm_start >= norm_end {
        return (norm_start, norm_end);
    }

    let start_idx = (norm_start as usize).min(norm_to_raw.len().saturating_sub(1));
    let raw_start = norm_to_raw[start_idx] as u32;

    let raw_end = if (norm_end as usize) < norm_to_raw.len() {
        (norm_to_raw[norm_end as usize] as u32).max(raw_start)
    } else if let Some(&last_raw) = norm_to_raw.last() {
        (last_raw as u32 + 1)
            .min(raw_len_chars as u32)
            .max(raw_start)
    } else {
        norm_end
    };

    (raw_start, raw_end)
}

/// Scans raw text for zero-width characters, control characters, bidi markers, and confusables.
fn scan_unicode_safety_warnings(raw: &str, warnings: &mut Vec<TextWarning>) {
    let mut has_cyrillic_lookalikes = false;
    let mut has_greek_lookalikes = false;
    let mut has_latin = false;

    for (idx, ch) in raw.chars().enumerate() {
        // Check for Zero-Width / Invisible characters
        if is_zero_width_or_invisible(ch) {
            warnings.push(TextWarning {
                code: "ZERO_WIDTH_CHARACTER_DETECTED".to_string(),
                message: format!(
                    "Zero-width / invisible Unicode character U+{:04X} detected",
                    ch as u32
                ),
                raw_char_offset: Some(idx),
            });
        }

        // Check for Control characters (excluding standard whitespace \n, \r, \t)
        if is_non_standard_control(ch) {
            warnings.push(TextWarning {
                code: "CONTROL_CHARACTER_DETECTED".to_string(),
                message: format!("Control character U+{:04X} detected", ch as u32),
                raw_char_offset: Some(idx),
            });
        }

        // Check for Bidirectional directional formatting characters
        if is_bidi_control(ch) {
            warnings.push(TextWarning {
                code: "BIDI_CONTROL_CHARACTER_DETECTED".to_string(),
                message: format!("Bidirectional formatting character U+{:04X} detected (preserved in logical order)", ch as u32),
                raw_char_offset: Some(idx),
            });
        }

        // Track scripts for mixed-script confusable detection
        if ch.is_ascii_alphabetic() || ('\u{00C0}'..='\u{024F}').contains(&ch) {
            has_latin = true;
        } else if is_cyrillic_latin_lookalike(ch) {
            has_cyrillic_lookalikes = true;
        } else if is_greek_latin_lookalike(ch) {
            has_greek_lookalikes = true;
        }
    }

    if has_latin && has_cyrillic_lookalikes {
        warnings.push(TextWarning {
            code: "MIXED_SCRIPT_CONFUSABLE_CYRILLIC".to_string(),
            message: "Document contains mixed Latin and Cyrillic homoglyph lookalikes".to_string(),
            raw_char_offset: None,
        });
    }

    if has_latin && has_greek_lookalikes {
        warnings.push(TextWarning {
            code: "MIXED_SCRIPT_CONFUSABLE_GREEK".to_string(),
            message: "Document contains mixed Latin and Greek homoglyph lookalikes".to_string(),
            raw_char_offset: None,
        });
    }
}

/// Identifies zero-width, soft hyphens, joiners, and BOM marks.
#[must_use]
pub fn is_zero_width_or_invisible(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // Zero-Width Space
        | '\u{200C}' // Zero-Width Non-Joiner
        | '\u{200D}' // Zero-Width Joiner
        | '\u{FEFF}' // Zero-Width No-Break Space / BOM
        | '\u{2060}' // Word Joiner
        | '\u{00AD}' // Soft Hyphen
        | '\u{180E}' // Mongolian Vowel Separator
        | '\u{200E}' // Left-to-Right Mark
        | '\u{200F}' // Right-to-Left Mark
        | '\u{2028}' // Line Separator
        | '\u{2029}' // Paragraph Separator
    )
}

/// Identifies control characters other than standard tab, LF, CR.
#[must_use]
pub fn is_non_standard_control(ch: char) -> bool {
    (ch < ' ' && ch != '\t' && ch != '\n' && ch != '\r') || ('\u{007F}'..='\u{009F}').contains(&ch)
}

/// Identifies Unicode Bidirectional control characters.
#[must_use]
pub fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}' // Left-to-Right Mark
        | '\u{200F}' // Right-to-Left Mark
        | '\u{202A}' // Left-to-Right Embedding
        | '\u{202B}' // Right-to-Left Embedding
        | '\u{202C}' // Pop Directional Formatting
        | '\u{202D}' // Left-to-Right Override
        | '\u{202E}' // Right-to-Left Override
        | '\u{2066}' // Left-to-Right Isolate
        | '\u{2067}' // Right-to-Left Isolate
        | '\u{2068}' // First Strong Isolate
        | '\u{2069}' // Pop Directional Isolate
    )
}

/// Identifies Cyrillic letters that are homoglyphs of basic Latin letters.
#[must_use]
pub fn is_cyrillic_latin_lookalike(ch: char) -> bool {
    matches!(
        ch,
        '\u{0430}' // а (Cyrillic Small Letter A) -> a
        | '\u{0435}' // е (Cyrillic Small Letter Ie) -> e
        | '\u{043E}' // о (Cyrillic Small Letter O) -> o
        | '\u{0440}' // р (Cyrillic Small Letter Er) -> p
        | '\u{0441}' // с (Cyrillic Small Letter Es) -> c
        | '\u{0443}' // у (Cyrillic Small Letter U) -> y
        | '\u{0445}' // х (Cyrillic Small Letter Ha) -> x
        | '\u{0410}' // А -> A
        | '\u{0412}' // В -> B
        | '\u{0415}' // Е -> E
        | '\u{041A}' // К -> K
        | '\u{041C}' // М -> M
        | '\u{041D}' // Н -> H
        | '\u{041E}' // О -> O
        | '\u{0420}' // Р -> P
        | '\u{0421}' // С -> C
        | '\u{0422}' // Т -> T
        | '\u{0425}' // Х -> X
    )
}

/// Identifies Greek letters that are homoglyphs of basic Latin letters.
#[must_use]
pub fn is_greek_latin_lookalike(ch: char) -> bool {
    matches!(
        ch,
        '\u{0391}' // Α -> A
        | '\u{0392}' // Β -> B
        | '\u{0395}' // Ε -> E
        | '\u{0397}' // Η -> H
        | '\u{0399}' // Ι -> I
        | '\u{039A}' // Κ -> K
        | '\u{039C}' // Μ -> M
        | '\u{039D}' // Ν -> N
        | '\u{039F}' // Ο -> O
        | '\u{03A1}' // Ρ -> P
        | '\u{03A4}' // Τ -> T
        | '\u{03A7}' // Χ -> X
        | '\u{03A5}' // Υ -> Y
        | '\u{03BF}' // ο -> o
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfc_normalization_produces_composed_forms() {
        // e + combining acute accent -> composed é
        let decomposed = "e\u{0301}";
        let res = normalize_text_nfc(decomposed);
        assert_eq!(res.normalized_text, "\u{00E9}");
        assert_eq!(res.raw_text, decomposed);
    }

    #[test]
    fn test_nfkc_is_not_authoritative() {
        // In NFKC, ligature 'ﬁ' becomes 'fi' and fraction '½' becomes '1/2'.
        // In NFC, ligature 'ﬁ' and '½' remain preserved as distinct characters!
        let ligature = "ﬁle ½";
        let res = normalize_text_nfc(ligature);
        assert_eq!(res.normalized_text, "ﬁle ½");
        // Verify NFKC would have changed it, proving NFC was used instead of NFKC:
        let nfkc_version: String = ligature.nfkc().collect();
        assert!(nfkc_version.starts_with("file"));
        assert_ne!(res.normalized_text, nfkc_version);
    }

    #[test]
    fn test_zero_width_and_control_characters_preserved_and_flagged() {
        let text_with_zw = "Sec\u{200B}ret\u{0007}Code";
        let res = normalize_text_nfc(text_with_zw);
        // Original evidence is preserved in both raw and NFC normalized text
        assert!(res.normalized_text.contains('\u{200B}'));
        assert!(res.normalized_text.contains('\u{0007}'));
        // Warnings are emitted
        assert!(
            res.warnings
                .iter()
                .any(|w| w.code == "ZERO_WIDTH_CHARACTER_DETECTED")
        );
        assert!(
            res.warnings
                .iter()
                .any(|w| w.code == "CONTROL_CHARACTER_DETECTED")
        );
    }

    #[test]
    fn test_bidi_markers_preserved_in_logical_order() {
        let bidi_text = "English \u{200E}\u{0639}\u{0631}\u{0628}\u{064A}\u{200E} more English";
        let res = normalize_text_nfc(bidi_text);
        assert_eq!(res.normalized_text, bidi_text);
        assert!(
            res.warnings
                .iter()
                .any(|w| w.code == "BIDI_CONTROL_CHARACTER_DETECTED")
        );
    }

    #[test]
    fn test_confusable_homoglyphs_flagged() {
        // "pаypаl" using Cyrillic 'а' (U+0430) mixed with Latin 'p', 'y', 'l'
        let spoofed = "p\u{0430}yp\u{0430}l";
        let res = normalize_text_nfc(spoofed);
        assert!(
            res.warnings
                .iter()
                .any(|w| w.code == "MIXED_SCRIPT_CONFUSABLE_CYRILLIC")
        );
    }
}
