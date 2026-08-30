"use client";

import React, { useState } from "react";

export interface SourceSpanInfo {
  id: string;
  page_number: number;
  span_sequence: number;
  normalized_range: { start: number; end: number };
  section_path?: string[];
  text: string;
  extraction: string;
  quality_score?: number;
  span_sha256?: string;
}

export interface SourceSpanViewerProps {
  selectedSpan: SourceSpanInfo | null;
  versionNumber: number;
  documentTitle: string;
  isStaleCitation?: boolean;
  citationError?: string | null;
  onClearSelection?: () => void;
}

export function SourceSpanViewer({
  selectedSpan,
  versionNumber,
  documentTitle,
  isStaleCitation = false,
  citationError = null,
  onClearSelection,
}: SourceSpanViewerProps) {
  const [copied, setCopied] = useState(false);

  const formatCitation = (span: SourceSpanInfo): string => {
    const secStr = span.section_path && span.section_path.length > 0
      ? ` § ${span.section_path.join(" > ")}`
      : "";
    return `[${documentTitle}, v${versionNumber}, p. ${span.page_number}${secStr} (offsets ${span.normalized_range.start}..${span.normalized_range.end})]`;
  };

  const handleCopyCitation = async () => {
    if (!selectedSpan) return;
    const citation = formatCitation(selectedSpan);
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(citation);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch {
        // clipboard fallback
      }
    }
  };

  return (
    <aside
      className="source-span-panel"
      aria-label="Evidence Source Span &amp; Citation Details"
      data-testid="source-span-panel"
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <h3 style={{ fontSize: "0.9375rem", fontWeight: 700, color: "var(--text-primary)" }}>
          Evidence Citation &amp; Span
        </h3>
        {selectedSpan && onClearSelection && (
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            style={{ padding: "1px 6px", fontSize: "0.6875rem" }}
            onClick={onClearSelection}
            data-testid="clear-span-btn"
          >
            Clear Selection
          </button>
        )}
      </div>

      {isStaleCitation || citationError ? (
        <div className="stale-citation-notice" role="alert" data-testid="stale-citation-notice">
          <strong>Citation Unresolvable:</strong>{" "}
          {citationError || "The requested evidence citation span cannot be resolved in this exact immutable version."}
          <div style={{ fontSize: "0.75rem", marginTop: "var(--space-1)", color: "var(--text-muted)" }}>
            Authoritative Rule: Stale or unresolvable citations are never silently substituted.
          </div>
        </div>
      ) : selectedSpan ? (
        <div className="span-card highlighted" data-testid="selected-span-card">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span className="font-mono font-semibold" style={{ fontSize: "0.8125rem" }}>
              Span #{selectedSpan.span_sequence} (p. {selectedSpan.page_number})
            </span>
            <span className="doc-class-badge" style={{ fontSize: "0.625rem" }}>
              {selectedSpan.extraction.toUpperCase()}
            </span>
          </div>

          {selectedSpan.section_path && selectedSpan.section_path.length > 0 && (
            <div className="text-xs text-secondary">
              <span className="font-semibold">Section:</span> {selectedSpan.section_path.join(" > ")}
            </div>
          )}

          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
            Normalized Offsets: [{selectedSpan.normalized_range.start}..{selectedSpan.normalized_range.end}]
            {selectedSpan.quality_score !== undefined && (
              <span> • Quality: {(selectedSpan.quality_score * 100).toFixed(1)}%</span>
            )}
          </div>

          <div
            style={{
              background: "var(--bg-surface-inset)",
              padding: "var(--space-2)",
              borderRadius: "3px",
              fontSize: "0.8125rem",
              lineHeight: 1.5,
              color: "var(--text-primary)",
              border: "1px solid var(--border-muted)",
              whiteSpace: "pre-wrap",
            }}
            data-testid="selected-span-text"
          >
            {selectedSpan.text}
          </div>

          {selectedSpan.span_sha256 && (
            <div className="text-xs font-mono text-muted" style={{ wordBreak: "break-all" }}>
              Canonical Span Hash: {selectedSpan.span_sha256}
            </div>
          )}

          <div style={{ marginTop: "var(--space-2)" }}>
            <span className="form-label" style={{ fontSize: "0.75rem", marginBottom: "var(--space-1)" }}>
              Generated Citable Evidence Reference:
            </span>
            <div className="citation-box" data-testid="generated-citation-box">
              {formatCitation(selectedSpan)}
            </div>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              style={{ marginTop: "var(--space-2)", width: "100%" }}
              onClick={handleCopyCitation}
              data-testid="copy-citation-btn"
            >
              {copied ? "✓ Citation Copied to Clipboard" : "Copy Evidence Citation"}
            </button>
          </div>
        </div>
      ) : (
        <div style={{ fontSize: "0.8125rem", color: "var(--text-muted)", padding: "var(--space-4) 0", textAlign: "center" }} data-testid="no-span-selected">
          <p>No specific source span selected.</p>
          <p className="text-xs" style={{ marginTop: "var(--space-1)" }}>
            Select a verified span from the document view or query parameter to inspect canonical provenance.
          </p>
        </div>
      )}
    </aside>
  );
}
