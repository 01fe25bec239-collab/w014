//! Test suite for Unicode NFC normalization and security anomaly inspection (WI-0207).
//!
//! Validates:
//! - Derived normalization: Unicode NFC
//! - NFKC is NOT authoritative (does not alter formatting / compatibility characters)
//! - Original evidence preservation
//! - Zero-width character detection (`\u{200B}`, `\u{200C}`, `\u{200D}`, `\u{FEFF}`, `\u{2060}`, `\u{180E}`)
//! - Control character detection (ASCII 0x00..=0x1F except \t, \n, \r, 0x7F..=0x9F)
//! - Bidirectional text overrides (`\u{202A}`..=`\u{202E}`, `\u{2066}`..=`\u{2069}`, `\u{200E}`, `\u{200F}`)
//! - Confusable homoglyph / mixed-script detection

use w014_document_processing::normalization::{
    AnomalyKind, inspect_text, is_bidi_control, is_control_character, is_zero_width, normalize_nfc,
};

#[test]
fn test_unicode_nfc_canonical_composition() {
    // Single composed character vs decomposed base + combining character
    let decomposed_angstrom = "A\u{030A}";
    let composed_angstrom = "\u{00C5}"; // Å

    assert_eq!(normalize_nfc(decomposed_angstrom), composed_angstrom);
    assert_eq!(normalize_nfc(composed_angstrom), composed_angstrom);

    // Decomposed e + acute
    let decomposed_e = "e\u{0301}";
    let composed_e = "\u{00E9}"; // é
    assert_eq!(normalize_nfc(decomposed_e), composed_e);
}

#[test]
fn test_nfkc_not_authoritative() {
    // Under NFKC:
    // 'ﬁ' (U+FB01) would become "fi"
    // '²' (U+00B2) would become "2"
    // '№' (U+2116) would become "No"
    // Under NFC:
    // All original representations are strictly preserved!

    let ligature = "scientific ﬁndings";
    assert_eq!(normalize_nfc(ligature), "scientific ﬁndings");

    let squared = "area: 100 m²";
    assert_eq!(normalize_nfc(squared), "area: 100 m²");

    let numero = "Document № 123";
    assert_eq!(normalize_nfc(numero), "Document № 123");
}

#[test]
fn test_zero_width_characters_flagged() {
    let test_cases = [
        ("hidden\u{200B}text", '\u{200B}', "Zero Width Space"),
        ("zwnj\u{200C}break", '\u{200C}', "Zero Width Non-Joiner"),
        ("zwj\u{200D}join", '\u{200D}', "Zero Width Joiner"),
        ("bom\u{FEFF}header", '\u{FEFF}', "Byte Order Mark"),
        ("word\u{2060}joiner", '\u{2060}', "Word Joiner"),
        ("mongolian\u{180E}vowel", '\u{180E}', "Mongolian Vowel"),
    ];

    for (sample, expected_char, name) in test_cases {
        assert!(
            is_zero_width(expected_char),
            "Character '{name}' should be recognized as zero-width"
        );
        let anomalies = inspect_text(sample);
        assert!(
            anomalies
                .iter()
                .any(|a| a.kind == AnomalyKind::ZeroWidth && a.character == expected_char),
            "Sample '{sample}' should produce ZeroWidth anomaly for {name}"
        );
    }
}

#[test]
fn test_control_characters_flagged_except_standard_whitespace() {
    // Standard whitespace is permitted
    let valid = "Line 1\r\nLine 2\tTabbed content\n";
    assert!(inspect_text(valid).is_empty());

    // Non-printable control characters must be flagged
    let controls = [
        ("bell\u{0007}sound", '\u{0007}'),
        ("backspace\u{0008}char", '\u{0008}'),
        ("null\u{0000}byte", '\u{0000}'),
        ("del\u{007F}char", '\u{007F}'),
        ("c1\u{0080}control", '\u{0080}'),
    ];

    for (sample, expected_char) in controls {
        assert!(
            is_control_character(expected_char),
            "Character {:?} should be recognized as control character",
            expected_char
        );
        let anomalies = inspect_text(sample);
        assert!(
            anomalies
                .iter()
                .any(|a| a.kind == AnomalyKind::ControlCharacter && a.character == expected_char),
            "Sample '{sample}' should produce ControlCharacter anomaly"
        );
    }
}

#[test]
fn test_bidi_override_characters_flagged() {
    let bidi_chars = [
        ('\u{202A}', "LRE"),
        ('\u{202B}', "RLE"),
        ('\u{202C}', "PDF"),
        ('\u{202D}', "LRO"),
        ('\u{202E}', "RLO"),
        ('\u{2066}', "LRI"),
        ('\u{2067}', "RLI"),
        ('\u{2068}', "FSI"),
        ('\u{2069}', "PDI"),
        ('\u{200E}', "LRM"),
        ('\u{200F}', "RLM"),
    ];

    for (ch, name) in bidi_chars {
        assert!(
            is_bidi_control(ch),
            "Character {name} should be recognized as bidi control"
        );
        let sample = format!("prefix{}suffix", ch);
        let anomalies = inspect_text(&sample);
        assert!(
            anomalies
                .iter()
                .any(|a| a.kind == AnomalyKind::BidiOverride && a.character == ch),
            "Sample with {name} should produce BidiOverride anomaly"
        );
    }
}

#[test]
fn test_confusable_homoglyphs_flagged() {
    // Cyrillic 'о' in word "contract" -> "cоntract"
    let mixed_contract = "c\u{043E}ntract";
    let anomalies = inspect_text(mixed_contract);
    assert!(
        anomalies
            .iter()
            .any(|a| a.kind == AnomalyKind::ConfusableHomoglyph),
        "Mixed script token should be flagged as ConfusableHomoglyph"
    );
}
