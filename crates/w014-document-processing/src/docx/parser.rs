//! DOCX P0 safe subset parser (WI-0207).
//!
//! Extracts structured document hierarchy from validated OOXML packages:
//! - Paragraphs (`BlockKind::Paragraph`)
//! - Headings (`BlockKind::Heading`) with hierarchical `SectionPath`
//! - Table cells (`BlockKind::TableCell`)
//! - Headers (`BlockKind::Header`)
//! - Footers (`BlockKind::Footer`)
//! - Image references (`BlockKind::ImageText` / media items)
//! - Page segmentation via `<w:br w:type="page"/>` and `<w:lastRenderedPageBreak/>`
//! - Unicode NFC normalized offsets for blocks and spans

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use w014_domain::BlockKind;
use w014_domain::limits::MAX_PAGE_NUMBER;

use super::error::DocxError;
use super::package::{DocxMediaItem, DocxPackage};
use crate::normalization::normalize_nfc;

/// A parsed structured block within a DOCX page.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDocxBlock {
    /// Ordinal index within page (0-based).
    pub ordinal: u32,
    /// Structural block kind.
    pub kind: BlockKind,
    /// Normalized text content.
    pub text: String,
    /// Half-open start offset in page normalized text.
    pub norm_start: u32,
    /// Half-open end offset in page normalized text.
    pub norm_end: u32,
    /// Hierarchical section path (e.g., `["1. Introduction", "1.1 Purpose"]`).
    pub section_path: Vec<String>,
    /// Confidence score (1.0 for native text).
    pub confidence: Option<f64>,
}

/// A parsed structured page within a DOCX document.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDocxPage {
    /// 1-based page number.
    pub page_number: u32,
    /// Full normalized text for this page.
    pub normalized_text: String,
    /// Ordered structural blocks on this page.
    pub blocks: Vec<ParsedDocxBlock>,
    /// Associated media / image items for this page.
    pub media_items: Vec<DocxMediaItem>,
    /// Whether this page contains embedded images that may warrant OCR.
    pub has_embedded_images: bool,
}

/// Full parsed DOCX document output.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDocxDocument {
    /// Ordered pages.
    pub pages: Vec<ParsedDocxPage>,
    /// Full normalized text concatenated across all pages.
    pub full_text: String,
    /// Total block count.
    pub total_block_count: usize,
    /// Total media images found in package.
    pub media_count: usize,
}

/// DOCX P0 Safe Subset Parser.
pub struct DocxParser;

impl DocxParser {
    /// Parses a validated `DocxPackage` into structured pages, blocks, and section paths.
    ///
    /// # Errors
    /// Fails closed if XML parsing fails or page counts exceed frozen limits.
    pub fn parse_package(package: &DocxPackage) -> Result<ParsedDocxDocument, DocxError> {
        let mut raw_pages = Vec::new();
        let mut current_page_blocks: Vec<RawBlock> = Vec::new();
        let mut current_section_path: Vec<String> = Vec::new();

        // 1. Parse headers (if any) as first page blocks or prepended facts
        for (_header_name, header_xml) in &package.headers {
            let header_blocks = parse_xml_part_blocks(header_xml, BlockKind::Header)?;
            current_page_blocks.extend(header_blocks);
        }

        // 2. Parse main document.xml
        parse_document_xml_into_pages(
            &package.document_xml,
            &mut current_page_blocks,
            &mut raw_pages,
            &mut current_section_path,
        )?;

        // 3. Parse footers (if any) onto last page
        for (_footer_name, footer_xml) in &package.footers {
            let footer_blocks = parse_xml_part_blocks(footer_xml, BlockKind::Footer)?;
            current_page_blocks.extend(footer_blocks);
        }

        // Push final page if any blocks remain
        if !current_page_blocks.is_empty() || raw_pages.is_empty() {
            raw_pages.push(current_page_blocks);
        }

        // 4. Construct final 1-based ParsedDocxPage structures
        let mut pages = Vec::with_capacity(raw_pages.len());
        let mut full_text_acc = String::new();
        let mut total_blocks = 0;

        for (page_idx, page_raw_blocks) in raw_pages.into_iter().enumerate() {
            let page_num = (page_idx + 1) as u32;
            if page_num > MAX_PAGE_NUMBER {
                return Err(DocxError::PackageLimitsExceeded {
                    limit_name: "MAX_PAGE_NUMBER",
                    actual: page_num as u64,
                    limit: MAX_PAGE_NUMBER as u64,
                });
            }

            let mut page_text = String::new();
            let mut parsed_blocks = Vec::with_capacity(page_raw_blocks.len());

            for (ordinal, raw_b) in page_raw_blocks.into_iter().enumerate() {
                let norm_b_text = normalize_nfc(&raw_b.text);
                if norm_b_text.is_empty() && raw_b.kind != BlockKind::ImageText {
                    continue;
                }

                let norm_start = page_text.len() as u32;
                if !page_text.is_empty() {
                    page_text.push('\n');
                }
                let block_start_offset = page_text.len() as u32;
                page_text.push_str(&norm_b_text);
                let norm_end = page_text.len() as u32;

                parsed_blocks.push(ParsedDocxBlock {
                    ordinal: ordinal as u32,
                    kind: raw_b.kind,
                    text: norm_b_text,
                    norm_start: if norm_start == 0 {
                        0
                    } else {
                        block_start_offset
                    },
                    norm_end,
                    section_path: raw_b.section_path,
                    confidence: Some(1.0),
                });
                total_blocks += 1;
            }

            let has_images = !package.media_items.is_empty();
            let page_media = package.media_items.clone();

            if !full_text_acc.is_empty() && !page_text.is_empty() {
                full_text_acc.push_str("\n\n");
            }
            full_text_acc.push_str(&page_text);

            pages.push(ParsedDocxPage {
                page_number: page_num,
                normalized_text: page_text,
                blocks: parsed_blocks,
                media_items: page_media,
                has_embedded_images: has_images,
            });
        }

        let media_count = package.media_items.len();
        Ok(ParsedDocxDocument {
            pages,
            full_text: full_text_acc,
            total_block_count: total_blocks,
            media_count,
        })
    }
}

/// Raw block collected during XML event streaming.
#[derive(Debug, Clone)]
struct RawBlock {
    kind: BlockKind,
    text: String,
    section_path: Vec<String>,
}

/// Parses `word/document.xml` using streaming XML events.
fn parse_document_xml_into_pages(
    xml_text: &str,
    current_page_blocks: &mut Vec<RawBlock>,
    pages: &mut Vec<Vec<RawBlock>>,
    current_section_path: &mut Vec<String>,
) -> Result<(), DocxError> {
    let mut reader = Reader::from_str(xml_text);
    reader.config_mut().trim_text(false);

    let mut buf = Vec::new();

    let mut inside_tbl = false;
    let mut inside_tc = false;
    let mut inside_t = false;

    let mut current_p_style = String::new();
    let mut current_p_text = String::new();
    let mut has_page_break_in_p = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_name = e.local_name();
                match local_name.as_ref() {
                    b"tbl" => inside_tbl = true,
                    b"tc" => inside_tc = true,
                    b"p" => {
                        current_p_style.clear();
                        current_p_text.clear();
                        has_page_break_in_p = false;
                    }
                    b"pStyle" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == b"val" {
                                current_p_style = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    b"t" => inside_t = true,
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                match local_name.as_ref() {
                    b"pStyle" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == b"val" {
                                current_p_style = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    b"br" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.local_name().as_ref() == b"type"
                                && attr.value.as_ref() == b"page"
                            {
                                has_page_break_in_p = true;
                            }
                        }
                    }
                    b"lastRenderedPageBreak" => {
                        has_page_break_in_p = true;
                    }
                    b"pageBreakBefore" => {
                        has_page_break_in_p = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if inside_t {
                    let decoded = e
                        .unescape()
                        .map_err(|err| DocxError::XmlParseError {
                            part_name: "word/document.xml".to_string(),
                            detail: format!("XML unescape error: {err}"),
                        })?
                        .to_string();
                    current_p_text.push_str(&decoded);
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                match local_name.as_ref() {
                    b"tbl" => inside_tbl = false,
                    b"tc" => inside_tc = false,
                    b"t" => inside_t = false,
                    b"p" => {
                        // Classify block kind
                        let trimmed = current_p_text.trim();
                        let kind = if inside_tbl || inside_tc {
                            BlockKind::TableCell
                        } else if is_heading_style(&current_p_style) {
                            BlockKind::Heading
                        } else {
                            BlockKind::Paragraph
                        };

                        // Update section path if Heading
                        if kind == BlockKind::Heading && !trimmed.is_empty() {
                            update_section_path(current_section_path, &current_p_style, trimmed);
                        }

                        if !current_p_text.is_empty() {
                            current_page_blocks.push(RawBlock {
                                kind,
                                text: current_p_text.clone(),
                                section_path: current_section_path.clone(),
                            });
                        }

                        // Page break trigger
                        if has_page_break_in_p {
                            let completed_page = std::mem::take(current_page_blocks);
                            pages.push(completed_page);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(DocxError::XmlParseError {
                    part_name: "word/document.xml".to_string(),
                    detail: format!("XML parse error: {e}"),
                });
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(())
}

/// Parses standalone XML parts like headers or footers into raw blocks.
fn parse_xml_part_blocks(xml_text: &str, kind: BlockKind) -> Result<Vec<RawBlock>, DocxError> {
    let mut reader = Reader::from_str(xml_text);
    reader.config_mut().trim_text(false);

    let mut buf = Vec::new();
    let mut blocks = Vec::new();
    let mut inside_t = false;
    let mut current_p_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.local_name().as_ref() == b"t" {
                    inside_t = true;
                } else if e.local_name().as_ref() == b"p" {
                    current_p_text.clear();
                }
            }
            Ok(Event::Text(e)) => {
                if inside_t {
                    let decoded = e
                        .unescape()
                        .map_err(|err| DocxError::XmlParseError {
                            part_name: "header/footer".to_string(),
                            detail: format!("XML unescape error: {err}"),
                        })?
                        .to_string();
                    current_p_text.push_str(&decoded);
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"t" {
                    inside_t = false;
                } else if e.local_name().as_ref() == b"p" && !current_p_text.is_empty() {
                    blocks.push(RawBlock {
                        kind,
                        text: current_p_text.clone(),
                        section_path: Vec::new(),
                    });
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(DocxError::XmlParseError {
                    part_name: "header/footer".to_string(),
                    detail: format!("XML parse error: {e}"),
                });
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(blocks)
}

fn is_heading_style(style: &str) -> bool {
    let lower = style.to_lowercase();
    lower.starts_with("heading")
        || lower.starts_with("title")
        || lower.starts_with("subtitle")
        || lower.starts_with("head")
}

fn update_section_path(path: &mut Vec<String>, style: &str, heading_text: &str) {
    let lower = style.to_lowercase();
    let level = if lower.contains('1') || lower == "title" {
        1
    } else if lower.contains('2') || lower == "subtitle" {
        2
    } else if lower.contains('3') {
        3
    } else if lower.contains('4') {
        4
    } else {
        1
    };

    while path.len() >= level {
        path.pop();
    }
    path.push(heading_text.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_docx_paragraphs_and_headings() {
        let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:body>
                <w:p>
                    <w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
                    <w:r><w:t>1. Executive Summary</w:t></w:r>
                </w:p>
                <w:p>
                    <w:r><w:t>This is the first paragraph of the document.</w:t></w:r>
                </w:p>
                <w:p>
                    <w:pPr><w:pStyle w:val="Heading2"/></w:pPr>
                    <w:r><w:t>1.1 Scope</w:t></w:r>
                </w:p>
                <w:p>
                    <w:r><w:t>Details of the project scope.</w:t></w:r>
                </w:p>
            </w:body>
        </w:document>"#;

        let pkg = DocxPackage {
            content_types_xml: String::new(),
            document_xml: doc_xml.to_string(),
            headers: Vec::new(),
            footers: Vec::new(),
            media_items: Vec::new(),
            relationships: std::collections::HashMap::new(),
            total_expanded_bytes: 1000,
            entry_count: 1,
        };

        let parsed = DocxParser::parse_package(&pkg).expect("Docx parsing should succeed");
        assert_eq!(parsed.pages.len(), 1);
        let page = &parsed.pages[0];
        assert_eq!(page.blocks.len(), 4);

        assert_eq!(page.blocks[0].kind, BlockKind::Heading);
        assert_eq!(page.blocks[0].text, "1. Executive Summary");
        assert_eq!(page.blocks[0].section_path, vec!["1. Executive Summary"]);

        assert_eq!(page.blocks[1].kind, BlockKind::Paragraph);
        assert_eq!(
            page.blocks[1].text,
            "This is the first paragraph of the document."
        );
        assert_eq!(page.blocks[1].section_path, vec!["1. Executive Summary"]);

        assert_eq!(page.blocks[2].kind, BlockKind::Heading);
        assert_eq!(page.blocks[2].text, "1.1 Scope");
        assert_eq!(
            page.blocks[2].section_path,
            vec!["1. Executive Summary", "1.1 Scope"]
        );
    }

    #[test]
    fn test_page_break_segmentation() {
        let doc_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:body>
                <w:p>
                    <w:r><w:t>Page 1 content</w:t></w:r>
                    <w:r><w:br w:type="page"/></w:r>
                </w:p>
                <w:p>
                    <w:r><w:t>Page 2 content</w:t></w:r>
                </w:p>
            </w:body>
        </w:document>"#;

        let pkg = DocxPackage {
            content_types_xml: String::new(),
            document_xml: doc_xml.to_string(),
            headers: Vec::new(),
            footers: Vec::new(),
            media_items: Vec::new(),
            relationships: std::collections::HashMap::new(),
            total_expanded_bytes: 1000,
            entry_count: 1,
        };

        let parsed = DocxParser::parse_package(&pkg).expect("Docx parsing should succeed");
        assert_eq!(parsed.pages.len(), 2);
        assert_eq!(parsed.pages[0].page_number, 1);
        assert_eq!(parsed.pages[0].normalized_text, "Page 1 content");
        assert_eq!(parsed.pages[1].page_number, 2);
        assert_eq!(parsed.pages[1].normalized_text, "Page 2 content");
    }
}
