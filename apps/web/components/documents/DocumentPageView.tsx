"use client";

import React, { useState } from "react";

export interface DocumentPageViewProps {
  currentPage: number;
  totalPages?: number;
  pageText: string;
  onPageChange: (page: number) => void;
  isLoading?: boolean;
  highlightRange?: { start: number; end: number } | null;
}

/**
 * Safe, bounded page viewer rendering normalized inert text.
 * SEC-016: All extracted text is rendered as safe text nodes. Zero dangerouslySetInnerHTML.
 */
export function DocumentPageView({
  currentPage,
  totalPages = 1,
  pageText,
  onPageChange,
  isLoading = false,
  highlightRange = null,
}: DocumentPageViewProps) {
  const [jumpInput, setJumpInput] = useState<string>(String(currentPage));

  const handlePrev = () => {
    if (currentPage > 1) {
      const next = currentPage - 1;
      setJumpInput(String(next));
      onPageChange(next);
    }
  };

  const handleNext = () => {
    if (currentPage < totalPages) {
      const next = currentPage + 1;
      setJumpInput(String(next));
      onPageChange(next);
    }
  };

  const handleJumpSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = parseInt(jumpInput, 10);
    if (!isNaN(parsed) && parsed >= 1 && parsed <= totalPages) {
      onPageChange(parsed);
    } else {
      setJumpInput(String(currentPage));
    }
  };

  // Safe highlighted rendering without dangerouslySetInnerHTML
  const renderHighlightedContent = () => {
    if (!highlightRange || highlightRange.start < 0 || highlightRange.end > pageText.length || highlightRange.start >= highlightRange.end) {
      return <div className="normalized-page-text" data-testid="page-text-content">{pageText}</div>;
    }

    const before = pageText.slice(0, highlightRange.start);
    const highlighted = pageText.slice(highlightRange.start, highlightRange.end);
    const after = pageText.slice(highlightRange.end);

    return (
      <div className="normalized-page-text" data-testid="page-text-content">
        <span>{before}</span>
        <mark
          style={{
            backgroundColor: "rgba(56, 189, 248, 0.25)",
            color: "var(--text-primary)",
            border: "1px solid var(--border-focus)",
            borderRadius: "2px",
            padding: "0 2px",
          }}
          data-testid="highlighted-span-text"
        >
          {highlighted}
        </mark>
        <span>{after}</span>
      </div>
    );
  };

  return (
    <section
      className="page-view-container"
      aria-label={`Document Page ${currentPage}`}
      data-testid="document-page-view"
    >
      <div className="page-nav-bar">
        <div className="page-nav-controls">
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handlePrev}
            disabled={currentPage <= 1 || isLoading}
            aria-label="Previous Page"
            data-testid="prev-page-btn"
          >
            ← Previous
          </button>

          <form onSubmit={handleJumpSubmit} style={{ display: "inline-flex", alignItems: "center", gap: "4px" }}>
            <label htmlFor="page-jump-input" className="sr-only">Go to page</label>
            <span className="text-xs text-secondary font-mono">Page</span>
            <input
              id="page-jump-input"
              type="text"
              className="form-input font-mono"
              style={{ width: "50px", padding: "2px 6px", fontSize: "0.8125rem", textAlign: "center" }}
              value={jumpInput}
              onChange={(e) => setJumpInput(e.target.value)}
              aria-label="Page number"
              data-testid="page-jump-input"
            />
            <span className="text-xs text-secondary font-mono" data-testid="total-pages-label">
              of {totalPages}
            </span>
          </form>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handleNext}
            disabled={currentPage >= totalPages || isLoading}
            aria-label="Next Page"
            data-testid="next-page-btn"
          >
            Next →
          </button>
        </div>

        <div className="text-xs font-mono text-muted">
          <span>SEC-016 Inert Rendering • Lazy Bounded View</span>
        </div>
      </div>

      <div className="page-content-area" data-testid="page-content-area">
        {isLoading ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)" }} data-testid="page-text-loading">
            <div className="skeleton-line" style={{ width: "90%", height: "20px" }} />
            <div className="skeleton-line" style={{ width: "95%", height: "20px" }} />
            <div className="skeleton-line" style={{ width: "80%", height: "20px" }} />
            <div className="skeleton-line" style={{ width: "85%", height: "20px" }} />
          </div>
        ) : (
          renderHighlightedContent()
        )}
      </div>
    </section>
  );
}
