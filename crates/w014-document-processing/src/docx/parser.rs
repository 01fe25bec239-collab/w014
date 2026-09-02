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
//!
//! Authoritative processing is routed through the frozen selected pure-Rust library
//! `ooxmlsdk = "0.12.0"` (P0 OOXML backend).

use std::io::Cursor;

use ooxmlsdk::parts::wordprocessing_document::WordprocessingDocument;
use ooxmlsdk::schemas::schemas_openxmlformats_org_wordprocessingml_2006_main as w;
use ooxmlsdk::sdk::SdkType;
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

/// DOCX P0 Safe Subset Parser backed authoritatively by `ooxmlsdk 0.12.0`.
pub struct DocxParser;

impl DocxParser {
    /// Parses a validated `DocxPackage` into structured pages, blocks, and section paths
    /// using `ooxmlsdk` 0.12.0 schemas.
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

        // 2. Parse main document.xml via authoritative ooxmlsdk
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

    /// Parses raw DOCX package bytes: executes preflight security limits, validates
    /// OPC packaging structure via `WordprocessingDocument`, and extracts hierarchy.
    pub fn parse_from_bytes(bytes: &[u8]) -> Result<ParsedDocxDocument, DocxError> {
        // 1. Hostile limits & security preflight
        let package = DocxPackage::open(bytes)?;

        // 2. Validate OPC packaging conventions via ooxmlsdk WordprocessingDocument
        let _doc = WordprocessingDocument::new(Cursor::new(bytes)).map_err(|e| {
            DocxError::XmlParseError {
                part_name: "[package]".to_string(),
                detail: format!("ooxmlsdk WordprocessingDocument packaging error: {e}"),
            }
        })?;

        // 3. Authoritative hierarchy extraction
        Self::parse_package(&package)
    }
}

/// Raw block collected during ooxmlsdk parsing.
#[derive(Debug, Clone)]
struct RawBlock {
    kind: BlockKind,
    text: String,
    section_path: Vec<String>,
}

/// Parses `word/document.xml` through `ooxmlsdk::schemas::...::Document`.
fn parse_document_xml_into_pages(
    xml_text: &str,
    current_page_blocks: &mut Vec<RawBlock>,
    pages: &mut Vec<Vec<RawBlock>>,
    current_section_path: &mut Vec<String>,
) -> Result<(), DocxError> {
    let doc =
        w::Document::from_bytes(xml_text.as_bytes()).map_err(|e| DocxError::XmlParseError {
            part_name: "word/document.xml".to_string(),
            detail: format!("ooxmlsdk Document deserialization failed: {e}"),
        })?;

    if let Some(body) = doc.body {
        for choice in body.body_choice {
            match choice {
                w::BodyChoice::Paragraph(p) => {
                    let (raw_block_opt, page_break) =
                        parse_ooxml_paragraph(&p, false, current_section_path);
                    if let Some(block) = raw_block_opt {
                        current_page_blocks.push(block);
                    }
                    if page_break {
                        let completed = std::mem::take(current_page_blocks);
                        pages.push(completed);
                    }
                }
                w::BodyChoice::Table(tbl) => {
                    for choice2 in tbl.table_choice2 {
                        if let w::TableChoice2::TableRow(row) = choice2 {
                            for cell_choice in row.table_row_choice {
                                if let w::TableRowChoice::TableCell(cell) = cell_choice {
                                    for item in cell.table_cell_choice {
                                        if let w::TableCellChoice::Paragraph(p) = item {
                                            let (raw_block_opt, page_break) = parse_ooxml_paragraph(
                                                &p,
                                                true,
                                                current_section_path,
                                            );
                                            if let Some(block) = raw_block_opt {
                                                current_page_blocks.push(block);
                                            }
                                            if page_break {
                                                let completed = std::mem::take(current_page_blocks);
                                                pages.push(completed);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                w::BodyChoice::Break(br) if br.r#type == Some(w::BreakValues::Page) => {
                    let completed = std::mem::take(current_page_blocks);
                    pages.push(completed);
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Helper extracting text and page breaks from a run using ooxmlsdk AST.
fn process_ooxml_run(run: &w::Run, text: &mut String, has_page_break: &mut bool) {
    for r_choice in &run.run_choice {
        match r_choice {
            w::RunChoice::Text(t) => {
                if let Some(content) = &t.0.xml_content {
                    text.push_str(content.as_str());
                }
            }
            w::RunChoice::Break(br) => {
                if br.r#type == Some(w::BreakValues::Page) {
                    *has_page_break = true;
                }
            }
            w::RunChoice::LastRenderedPageBreak => {
                *has_page_break = true;
            }
            w::RunChoice::TabChar => {
                text.push('\t');
            }
            w::RunChoice::CarriageReturn => {
                text.push('\r');
            }
            w::RunChoice::NoBreakHyphen => {
                text.push('-');
            }
            _ => {}
        }
    }
}

/// Helper extracting text and page breaks from a paragraph using ooxmlsdk AST.
fn parse_ooxml_paragraph(
    p: &w::Paragraph,
    is_table_cell: bool,
    current_section_path: &mut Vec<String>,
) -> (Option<RawBlock>, bool) {
    let mut current_p_style = String::new();
    let mut has_page_break = false;

    if let Some(props) = &p.paragraph_properties {
        if let Some(style) = &props.paragraph_style_id {
            current_p_style = style.val.to_string();
        }
        if props.page_break_before.is_some() {
            has_page_break = true;
        }
    }

    let mut current_p_text = String::new();

    for choice in &p.paragraph_choice {
        match choice {
            w::ParagraphChoice::WRun(run) => {
                process_ooxml_run(run, &mut current_p_text, &mut has_page_break);
            }
            w::ParagraphChoice::Break(br) => {
                if br.r#type == Some(w::BreakValues::Page) {
                    has_page_break = true;
                }
            }
            w::ParagraphChoice::Hyperlink(hl) => {
                for h_choice in &hl.hyperlink_choice {
                    if let w::HyperlinkChoice::WRun(run) = h_choice {
                        process_ooxml_run(run, &mut current_p_text, &mut has_page_break);
                    }
                }
            }
            w::ParagraphChoice::SimpleField(sf) => {
                for s_choice in &sf.simple_field_choice {
                    if let w::SimpleFieldChoice::WRun(run) = s_choice {
                        process_ooxml_run(run, &mut current_p_text, &mut has_page_break);
                    }
                }
            }
            _ => {}
        }
    }

    let trimmed = current_p_text.trim();
    let kind = if is_table_cell {
        BlockKind::TableCell
    } else if is_heading_style(&current_p_style) {
        BlockKind::Heading
    } else {
        BlockKind::Paragraph
    };

    if kind == BlockKind::Heading && !trimmed.is_empty() {
        update_section_path(current_section_path, &current_p_style, trimmed);
    }

    let raw_block = if !current_p_text.is_empty() {
        Some(RawBlock {
            kind,
            text: current_p_text,
            section_path: current_section_path.clone(),
        })
    } else {
        None
    };

    (raw_block, has_page_break)
}

/// Parses standalone XML parts like headers or footers into raw blocks via ooxmlsdk.
fn parse_xml_part_blocks(xml_text: &str, kind: BlockKind) -> Result<Vec<RawBlock>, DocxError> {
    let mut blocks = Vec::new();
    let mut dummy_section = Vec::new();

    if kind == BlockKind::Header {
        let header =
            w::Header::from_bytes(xml_text.as_bytes()).map_err(|e| DocxError::XmlParseError {
                part_name: "header.xml".to_string(),
                detail: format!("ooxmlsdk Header deserialization failed: {e}"),
            })?;
        for choice in header.header_choice {
            if let w::HeaderChoice::Paragraph(p) = choice {
                let (raw_block_opt, _) = parse_ooxml_paragraph(&p, false, &mut dummy_section);
                if let Some(mut b) = raw_block_opt {
                    b.kind = BlockKind::Header;
                    blocks.push(b);
                }
            }
        }
    } else if kind == BlockKind::Footer {
        let footer =
            w::Footer::from_bytes(xml_text.as_bytes()).map_err(|e| DocxError::XmlParseError {
                part_name: "footer.xml".to_string(),
                detail: format!("ooxmlsdk Footer deserialization failed: {e}"),
            })?;
        for choice in footer.footer_choice {
            if let w::FooterChoice::Paragraph(p) = choice {
                let (raw_block_opt, _) = parse_ooxml_paragraph(&p, false, &mut dummy_section);
                if let Some(mut b) = raw_block_opt {
                    b.kind = BlockKind::Footer;
                    blocks.push(b);
                }
            }
        }
    }

    Ok(blocks)
}

/// Checks if a style identifier represents a heading (case-insensitive).
fn is_heading_style(style_id: &str) -> bool {
    let s = style_id.to_ascii_lowercase();
    s.starts_with("heading") || s == "title" || s == "subtitle"
}

/// Extracts heading level from style identifier (e.g., "Heading 1" -> 1, "heading2" -> 2).
fn heading_level_from_style(style_id: &str) -> usize {
    let s = style_id.to_ascii_lowercase();
    if s == "title" {
        return 1;
    }
    if s == "subtitle" {
        return 2;
    }
    for ch in s.chars() {
        if let Some(digit) = ch.to_digit(10) {
            return digit.max(1) as usize;
        }
    }
    1
}

/// Updates section path hierarchy based on heading level and text.
fn update_section_path(section_path: &mut Vec<String>, style_id: &str, heading_text: &str) {
    let level = heading_level_from_style(style_id);
    while section_path.len() >= level {
        section_path.pop();
    }
    section_path.push(heading_text.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_style_id_case_insensitivity() {
        assert!(is_heading_style("Heading1"));
        assert!(is_heading_style("heading1"));
        assert!(is_heading_style("HEADING2"));
        assert!(is_heading_style("Heading 3"));
        assert!(is_heading_style("Title"));
        assert!(is_heading_style("title"));
        assert!(is_heading_style("Subtitle"));
        assert!(!is_heading_style("Normal"));
        assert!(!is_heading_style("BodyText"));
    }

    #[test]
    fn test_section_path_hierarchy() {
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
                    <w:r><w:t>Scope details paragraph.</w:t></w:r>
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

    #[test]
    fn test_ooxmlsdk_document_from_bytes() {
        use ooxmlsdk::schemas::schemas_openxmlformats_org_wordprocessingml_2006_main::Document;
        use ooxmlsdk::sdk::SdkType;
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:body>
                <w:p><w:r><w:t>Hello World</w:t></w:r></w:p>
            </w:body>
        </w:document>"#;
        let doc = Document::from_bytes(xml.as_bytes()).unwrap();
        assert!(doc.body.is_some());
    }

    #[test]
    fn test_ooxmlsdk_wordprocessing_document_new() {
        use ooxmlsdk::parts::wordprocessing_document::WordprocessingDocument;
        use std::io::Cursor;
        use std::io::Write;
        use zip::ZipWriter;
        use zip::write::SimpleFileOptions;

        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
                    <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
                    <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
                    <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
                </Types>").unwrap();

            zip.start_file("_rels/.rels", options).unwrap();
            zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
                    <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
                </Relationships>").unwrap();

            zip.start_file("word/document.xml", options).unwrap();
            zip.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
                    <w:body>\
                        <w:p><w:r><w:t>Hello World</w:t></w:r></w:p>\
                    </w:body>\
                </w:document>").unwrap();

            zip.finish().unwrap();
        }

        let mut doc = WordprocessingDocument::new(Cursor::new(&buf))
            .expect("WordprocessingDocument should open");
        let main_part = doc
            .main_document_part()
            .expect("Main document part should exist");
        let root = main_part
            .root_element(&mut doc)
            .expect("Root element should load");
        assert!(root.body.is_some());
    }
}
