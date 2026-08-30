//! Native-vs-OCR precedence and conflict policy evaluation (WI-0207).
//!
//! Enforces:
//! - Native text precedence: structurally preserved separately when available
//! - OCR MUST NOT silently overwrite native text
//! - OCR text is provisional evidence candidate only
//! - OCR alone MUST NOT establish source authority, legal entitlement truth, deterministic PASS, or READY state
//! - Edit distance ratio > 5% triggers `REVIEW_INTEGRITY_SIGNAL`
//! - Critical identifier mismatch (contract number, legend field, revision, DID) triggers `REVIEW_INTEGRITY_SIGNAL`

use serde::{Deserialize, Serialize};

use super::config::MAX_NATIVE_OCR_EDIT_DISTANCE_RATIO;
use crate::normalization::normalize_nfc;

/// Critical identifier domain categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticalTokenType {
    ContractNumber,
    LegendField,
    Revision,
    DataIdOrDid,
}

impl CriticalTokenType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ContractNumber => "contract_number",
            Self::LegendField => "legend_field",
            Self::Revision => "revision",
            Self::DataIdOrDid => "did",
        }
    }
}

/// Extracted critical identifier fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticalToken {
    pub token_type: CriticalTokenType,
    pub value: String,
}

/// Review integrity signal raised when OCR conflicts with native text or critical invariants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "signal_type", rename_all = "snake_case")]
pub enum ReviewIntegritySignal {
    /// Edit distance between normalized native text and OCR text exceeded 5%.
    EditDistanceExceeded {
        ratio: f64,
        threshold: f64,
        edit_distance: usize,
        native_len: usize,
        ocr_len: usize,
    },
    /// Critical identifier found in native text is mismatched or absent in OCR text.
    CriticalTokenMismatch {
        token_type: CriticalTokenType,
        native_value: Option<String>,
        ocr_value: Option<String>,
        detail: String,
    },
    /// Low confidence or unverified OCR text used where native structure was absent.
    ProvisionalOcrEvidence {
        page_number: u32,
        confidence: Option<f64>,
    },
}

/// Conflict policy evaluation result comparing native text and OCR text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConflictEvaluationResult {
    /// Normalized native text.
    pub native_text: String,
    /// Normalized OCR text (if OCR ran).
    pub ocr_text: Option<String>,
    /// Calculated edit distance ratio in 0.0..=1.0 (if OCR ran).
    pub edit_distance_ratio: Option<f64>,
    /// Calculated raw edit distance (if OCR ran).
    pub edit_distance: Option<usize>,
    /// Any review integrity signals raised.
    pub signals: Vec<ReviewIntegritySignal>,
    /// Critical tokens extracted from native text.
    pub native_critical_tokens: Vec<CriticalToken>,
    /// Critical tokens extracted from OCR text.
    pub ocr_critical_tokens: Vec<CriticalToken>,
    /// Whether review is required.
    pub requires_review: bool,
}

/// Evaluates native text against OCR text enforcing precedence and conflict detection.
#[must_use]
pub fn evaluate_native_vs_ocr(
    native_text: &str,
    ocr_text_opt: Option<&str>,
    page_number: u32,
    ocr_confidence: Option<f64>,
) -> ConflictEvaluationResult {
    let norm_native = normalize_nfc(native_text);
    let native_tokens = extract_critical_tokens(&norm_native);

    let mut signals = Vec::new();
    let mut ocr_tokens = Vec::new();
    let mut edit_distance_val = None;
    let mut edit_ratio_val = None;
    let mut norm_ocr_out = None;

    if let Some(raw_ocr) = ocr_text_opt {
        let norm_ocr = normalize_nfc(raw_ocr);
        ocr_tokens = extract_critical_tokens(&norm_ocr);

        // 1. Compute edit distance on normalized NFC text
        let dist = levenshtein_distance(&norm_native, &norm_ocr);
        let max_len = norm_native.chars().count().max(norm_ocr.chars().count());
        let ratio = if max_len == 0 {
            0.0
        } else {
            dist as f64 / max_len as f64
        };

        edit_distance_val = Some(dist);
        edit_ratio_val = Some(ratio);
        norm_ocr_out = Some(norm_ocr);

        // 2. Check 5% edit distance threshold
        if ratio > MAX_NATIVE_OCR_EDIT_DISTANCE_RATIO {
            signals.push(ReviewIntegritySignal::EditDistanceExceeded {
                ratio,
                threshold: MAX_NATIVE_OCR_EDIT_DISTANCE_RATIO,
                edit_distance: dist,
                native_len: norm_native.chars().count(),
                ocr_len: norm_ocr_out.as_ref().map_or(0, |s| s.chars().count()),
            });
        }

        // 3. Compare critical tokens between native and OCR
        compare_critical_tokens(&native_tokens, &ocr_tokens, &mut signals);

        // 4. Record provisional OCR evidence notice
        signals.push(ReviewIntegritySignal::ProvisionalOcrEvidence {
            page_number,
            confidence: ocr_confidence,
        });
    }

    let requires_review = signals.iter().any(|s| {
        matches!(
            s,
            ReviewIntegritySignal::EditDistanceExceeded { .. }
                | ReviewIntegritySignal::CriticalTokenMismatch { .. }
        )
    });

    ConflictEvaluationResult {
        native_text: norm_native,
        ocr_text: norm_ocr_out,
        edit_distance_ratio: edit_ratio_val,
        edit_distance: edit_distance_val,
        signals,
        native_critical_tokens: native_tokens,
        ocr_critical_tokens: ocr_tokens,
        requires_review,
    }
}

/// Computes the Levenshtein distance between two Unicode strings.
#[must_use]
pub fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let chars1: Vec<char> = s1.chars().collect();
    let chars2: Vec<char> = s2.chars().collect();

    let len1 = chars1.len();
    let len2 = chars2.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut prev_row: Vec<usize> = (0..=len2).collect();
    let mut curr_row: Vec<usize> = vec![0; len2 + 1];

    for (i, c1) in chars1.iter().enumerate() {
        curr_row[0] = i + 1;
        for (j, c2) in chars2.iter().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            curr_row[j + 1] = (curr_row[j] + 1) // insertion
                .min(prev_row[j + 1] + 1) // deletion
                .min(prev_row[j] + cost); // substitution
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[len2]
}

/// Extracts critical identifiers: contract numbers, legend fields, revisions, and DIDs.
#[must_use]
pub fn extract_critical_tokens(text: &str) -> Vec<CriticalToken> {
    let mut tokens = Vec::new();
    let upper = text.to_uppercase();

    // 1. Legend fields
    let legends = [
        "DISTRIBUTION STATEMENT A",
        "DISTRIBUTION STATEMENT B",
        "DISTRIBUTION STATEMENT C",
        "DISTRIBUTION STATEMENT D",
        "DISTRIBUTION STATEMENT E",
        "DISTRIBUTION STATEMENT F",
        "CONTROLLED UNCLASSIFIED INFORMATION",
        "CUI",
        "PROPRIETARY INFORMATION",
        "PROPRIETARY",
        "CONFIDENTIAL",
        "RESTRICTED",
        "SECRET",
        "TOP SECRET",
    ];

    for legend in &legends {
        if upper.contains(legend) {
            tokens.push(CriticalToken {
                token_type: CriticalTokenType::LegendField,
                value: (*legend).to_string(),
            });
        }
    }

    // 2. Word-based token scanning
    for word in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == ':') {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
        if clean.is_empty() {
            continue;
        }

        // DID detection: e.g. "DI-MGMT-80004A", "DI-MISC-81419"
        if clean.starts_with("DI-") && clean.len() >= 8 {
            tokens.push(CriticalToken {
                token_type: CriticalTokenType::DataIdOrDid,
                value: clean.to_string(),
            });
            continue;
        }

        // Contract number patterns: e.g. "W911NF-20-C-0001", "FA8650-19-C-1234", "N00014-21-C-1002", "HQ0034-20-C-0050"
        if is_contract_number_pattern(clean) {
            tokens.push(CriticalToken {
                token_type: CriticalTokenType::ContractNumber,
                value: clean.to_string(),
            });
            continue;
        }

        // Revision patterns: e.g. "Rev-A", "Rev.1", "REV_2.0"
        let upper_clean = clean.to_uppercase();
        if (upper_clean.starts_with("REV") || upper_clean.starts_with("REVISION"))
            && clean.len() >= 4
        {
            tokens.push(CriticalToken {
                token_type: CriticalTokenType::Revision,
                value: clean.to_string(),
            });
        }
    }

    tokens.dedup();
    tokens
}

fn is_contract_number_pattern(word: &str) -> bool {
    let parts: Vec<&str> = word.split('-').collect();
    // Standard DoD/Federal contract format: 3 to 5 hyphenated alphanumeric segments
    if parts.len() >= 3 && parts.len() <= 5 {
        let is_all_alphanumeric = parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric()));
        let has_letters = word.chars().any(|c| c.is_ascii_alphabetic());
        let has_digits = word.chars().any(|c| c.is_ascii_digit());
        return is_all_alphanumeric && has_letters && has_digits && word.len() >= 8;
    }
    false
}

fn compare_critical_tokens(
    native_tokens: &[CriticalToken],
    ocr_tokens: &[CriticalToken],
    signals: &mut Vec<ReviewIntegritySignal>,
) {
    for n_tok in native_tokens {
        let matching_ocr = ocr_tokens.iter().find(|o| o.token_type == n_tok.token_type);
        match matching_ocr {
            Some(o_tok) if o_tok.value != n_tok.value => {
                signals.push(ReviewIntegritySignal::CriticalTokenMismatch {
                    token_type: n_tok.token_type,
                    native_value: Some(n_tok.value.clone()),
                    ocr_value: Some(o_tok.value.clone()),
                    detail: format!(
                        "Mismatch for {}: native '{}' vs OCR '{}'",
                        n_tok.token_type.as_str(),
                        n_tok.value,
                        o_tok.value
                    ),
                });
            }
            None => {
                signals.push(ReviewIntegritySignal::CriticalTokenMismatch {
                    token_type: n_tok.token_type,
                    native_value: Some(n_tok.value.clone()),
                    ocr_value: None,
                    detail: format!(
                        "Critical token '{}' ({}) present in native text but missing in OCR",
                        n_tok.value,
                        n_tok.token_type.as_str()
                    ),
                });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("agreement", "agreement"), 0);
        assert_eq!(levenshtein_distance("contract", "contracc"), 1);
    }

    #[test]
    fn test_edit_distance_conflict_signal_when_exceeds_5_percent() {
        let native = "The contractor shall deliver 100 units by December 2026.";
        // Introduce > 5% typo / difference
        let ocr = "The contractrr shxll deliver 900 unlts by Decembxr 2029.";
        let res = evaluate_native_vs_ocr(native, Some(ocr), 1, Some(0.8));
        assert!(res.requires_review);
        assert!(
            res.signals
                .iter()
                .any(|s| matches!(s, ReviewIntegritySignal::EditDistanceExceeded { .. }))
        );
    }

    #[test]
    fn test_critical_contract_number_conflict_triggers_signal() {
        let native = "Contract W911NF-20-C-0001 governs this procurement.";
        let ocr = "Contract W911NF-20-C-0002 governs this procurement.";
        let res = evaluate_native_vs_ocr(native, Some(ocr), 1, Some(0.8));
        assert!(res.requires_review);
        assert!(
            res.signals
                .iter()
                .any(|s| matches!(s, ReviewIntegritySignal::CriticalTokenMismatch { .. }))
        );
    }

    #[test]
    fn test_legend_field_extraction() {
        let text = "DOCUMENT MARKING: DISTRIBUTION STATEMENT A and PROPRIETARY";
        let tokens = extract_critical_tokens(text);
        assert!(
            tokens
                .iter()
                .any(|t| t.token_type == CriticalTokenType::LegendField
                    && t.value == "DISTRIBUTION STATEMENT A")
        );
        assert!(tokens.iter().any(|t| t.token_type == CriticalTokenType::LegendField && t.value == "PROPRIETARY"));
    }

    #[test]
    fn test_did_extraction() {
        let text = "Deliverable per DI-MGMT-80004A standard.";
        let tokens = extract_critical_tokens(text);
        assert!(
            tokens
                .iter()
                .any(|t| t.token_type == CriticalTokenType::DataIdOrDid
                    && t.value == "DI-MGMT-80004A")
        );
    }
}
