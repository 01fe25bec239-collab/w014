//! Unicode NFC normalization and security anomaly detection (WI-0207).
//!
//! Enforces:
//! - Derived normalization: Unicode NFC (`normalize_nfc`)
//! - NFKC is NOT authoritative (does not collapse formatting/compatibility characters)
//! - Preserves original evidence while detecting and flagging:
//!   - Zero-width characters (`\u{200B}`, `\u{200C}`, `\u{200D}`, `\u{FEFF}`, `\u{2060}`, `\u{180E}`)
//!   - Unescaped control characters (ASCII 0x00..=0x1F except tab/newline/CR, 0x7F..=0x9F)
//!   - Bidirectional overrides and isolate markers (`\u{202A}`..=`\u{202E}`, `\u{2066}`..=`\u{2069}`, `\u{200E}`, `\u{200F}`)
//!   - Confusable homoglyphs / mixed scripts (e.g., Cyrillic homoglyphs in Latin tokens)

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// Canonical Unicode NFC normalization.
#[must_use]
pub fn normalize_nfc(input: &str) -> String {
    input.nfc().collect::<String>()
}

/// Anomaly classification for suspicious characters in document text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    /// Zero-width characters that may conceal invisible text or tamper with hashes.
    ZeroWidth,
    /// Non-printable control characters.
    ControlCharacter,
    /// Bidirectional text overrides or isolate markers.
    BidiOverride,
    /// Mixed-script confusable homoglyphs (e.g. Cyrillic characters in Latin words).
    ConfusableHomoglyph,
}

impl AnomalyKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ZeroWidth => "zero_width",
            Self::ControlCharacter => "control_character",
            Self::BidiOverride => "bidi_override",
            Self::ConfusableHomoglyph => "confusable_homoglyph",
        }
    }
}

/// A flagged text anomaly with character location and classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextAnomaly {
    /// Anomaly classification.
    pub kind: AnomalyKind,
    /// Character offset (Unicode codepoint index).
    pub char_index: usize,
    /// Byte offset in the input UTF-8 string.
    pub byte_offset: usize,
    /// The flagged character.
    pub character: char,
    /// Unicode hex representation (e.g., "U+200B").
    pub codepoint: String,
    /// Surrounding snippet context.
    pub context: String,
}

/// Inspects text for zero-width characters, control codes, bidi overrides, and confusables.
#[must_use]
pub fn inspect_text(text: &str) -> Vec<TextAnomaly> {
    let mut anomalies = Vec::new();
    let chars: Vec<(usize, char)> = text.char_indices().collect();

    for (char_idx, &(byte_offset, ch)) in chars.iter().enumerate() {
        let kind = if is_zero_width(ch) {
            Some(AnomalyKind::ZeroWidth)
        } else if is_control_character(ch) {
            Some(AnomalyKind::ControlCharacter)
        } else if is_bidi_control(ch) {
            Some(AnomalyKind::BidiOverride)
        } else {
            None
        };

        if let Some(k) = kind {
            let start = char_idx.saturating_sub(10);
            let end = (char_idx + 10).min(chars.len());
            let snippet: String = chars[start..end].iter().map(|(_, c)| *c).collect();

            anomalies.push(TextAnomaly {
                kind: k,
                char_index: char_idx,
                byte_offset,
                character: ch,
                codepoint: format!("U+{:04X}", ch as u32),
                context: snippet,
            });
        }
    }

    // Check for mixed-script confusable homoglyphs in alphanumeric words
    detect_confusable_tokens(text, &mut anomalies);

    anomalies
}

/// Checks whether a character is a zero-width or formatting separator.
#[must_use]
pub fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // Zero Width Space
        | '\u{200C}' // Zero Width Non-Joiner
        | '\u{200D}' // Zero Width Joiner
        | '\u{FEFF}' // Byte Order Mark / Zero Width No-Break Space
        | '\u{2060}' // Word Joiner
        | '\u{180E}' // Mongolian Vowel Separator
        | '\u{200A}' // Hair Space (near zero-width)
        | '\u{2009}' // Thin Space
    )
}

/// Checks whether a character is a non-printable control character.
#[must_use]
pub fn is_control_character(ch: char) -> bool {
    let u = ch as u32;
    // Allow tab (\t = 0x09), newline (\n = 0x0A), and carriage return (\r = 0x0D)
    if ch == '\t' || ch == '\n' || ch == '\r' {
        return false;
    }
    // C0 control codes
    if u <= 0x1F {
        return true;
    }
    // DEL and C1 control codes
    if (0x7F..=0x9F).contains(&u) {
        return true;
    }
    false
}

/// Checks whether a character is a bidirectional text override or isolate marker.
#[must_use]
pub fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{202A}' // Left-to-Right Embedding (LRE)
        | '\u{202B}' // Right-to-Left Embedding (RLE)
        | '\u{202C}' // Pop Directional Formatting (PDF)
        | '\u{202D}' // Left-to-Right Override (LRO)
        | '\u{202E}' // Right-to-Left Override (RLO)
        | '\u{2066}' // Left-to-Right Isolate (LRI)
        | '\u{2067}' // Right-to-Left Isolate (RLI)
        | '\u{2068}' // First Strong Isolate (FSI)
        | '\u{2069}' // Pop Directional Isolate (PDI)
        | '\u{200E}' // Left-to-Right Mark (LRM)
        | '\u{200F}' // Right-to-Left Mark (RLM)
    )
}

/// Common Cyrillic characters that are homoglyphs of Latin letters.
fn is_cyrillic_latin_homoglyph(ch: char) -> bool {
    matches!(
        ch,
        'а' | 'А' // Cyrillic A
        | 'в' | 'В' // Cyrillic Ve (looks like B)
        | 'е' | 'Е' // Cyrillic Ie (looks like E)
        | 'к' | 'К' // Cyrillic Ka (looks like K)
        | 'м' | 'М' // Cyrillic Em (looks like M)
        | 'н' | 'Н' // Cyrillic En (looks like H)
        | 'о' | 'О' // Cyrillic O
        | 'р' | 'Р' // Cyrillic Er (looks like P)
        | 'с' | 'С' // Cyrillic Es (looks like C)
        | 'т' | 'Т' // Cyrillic Te (looks like T)
        | 'у' | 'У' // Cyrillic U (looks like y)
        | 'х' | 'Х' // Cyrillic Kha (looks like X)
        | 'і' | 'І' // Cyrillic Byelorussian-Ukrainian I
        | 'ј' | 'Ј' // Cyrillic Je (looks like j)
        | 'ѕ' | 'Ѕ' // Cyrillic Dze (looks like S)
    )
}

fn detect_confusable_tokens(text: &str, anomalies: &mut Vec<TextAnomaly>) {
    for (word_start, word) in text.split_whitespace().map(|w| {
        let offset = w.as_ptr() as usize - text.as_ptr() as usize;
        (offset, w)
    }) {
        let mut latin_count = 0;
        let mut homoglyph_indices = Vec::new();

        for (idx, ch) in word.char_indices() {
            if ch.is_ascii_alphabetic() {
                latin_count += 1;
            } else if is_cyrillic_latin_homoglyph(ch) {
                homoglyph_indices.push((idx, ch));
            }
        }

        // If word is predominantly Latin but contains Cyrillic homoglyphs, flag them
        if latin_count >= 1 && !homoglyph_indices.is_empty() {
            for (local_byte_offset, ch) in homoglyph_indices {
                let abs_byte = word_start + local_byte_offset;
                anomalies.push(TextAnomaly {
                    kind: AnomalyKind::ConfusableHomoglyph,
                    char_index: 0, // approximate
                    byte_offset: abs_byte,
                    character: ch,
                    codepoint: format!("U+{:04X}", ch as u32),
                    context: word.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfc_normalization() {
        // e + combining acute accent (\u{0301}) -> é (\u{00E9}) in NFC
        let composed = "café";
        let decomposed = "cafe\u{0301}";
        assert_ne!(composed, decomposed);
        assert_eq!(normalize_nfc(decomposed), composed);
        assert_eq!(normalize_nfc(composed), composed);
    }

    #[test]
    fn test_nfkc_not_applied() {
        // NFKC decomposes formatting characters (e.g. 2⁵ -> 25 or ﬁ ligature -> fi).
        // NFC must PRESERVE ligatures and superscripts rather than collapsing them.
        let ligature = "ﬁle";
        assert_eq!(normalize_nfc(ligature), "ﬁle");
    }

    #[test]
    fn test_zero_width_detection() {
        let text = "contract\u{200B}number";
        let anomalies = inspect_text(text);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].kind, AnomalyKind::ZeroWidth);
        assert_eq!(anomalies[0].character, '\u{200B}');
        assert_eq!(anomalies[0].codepoint, "U+200B");
    }

    #[test]
    fn test_control_character_detection() {
        let text = "clean text\u{0007}with bell";
        let anomalies = inspect_text(text);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].kind, AnomalyKind::ControlCharacter);
        assert_eq!(anomalies[0].character, '\u{0007}');

        // Standard whitespace is not flagged
        let valid_whitespace = "line 1\nline 2\twith tab\r\n";
        let no_anomalies = inspect_text(valid_whitespace);
        assert!(no_anomalies.is_empty());
    }

    #[test]
    fn test_bidi_override_detection() {
        let text = "secret\u{202E}txt.exe";
        let anomalies = inspect_text(text);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].kind, AnomalyKind::BidiOverride);
        assert_eq!(anomalies[0].character, '\u{202E}');
    }

    #[test]
    fn test_confusable_homoglyph_detection() {
        // "pаypal" where 'а' is Cyrillic U+0430
        let spoofed = "p\u{0430}ypal";
        let anomalies = inspect_text(spoofed);
        assert!(
            anomalies
                .iter()
                .any(|a| a.kind == AnomalyKind::ConfusableHomoglyph)
        );
    }
}
