"use client";

import React, { useState } from "react";
import type { DocumentDto, DocumentVersionDto } from "@/lib/api-types";
import { DocumentPageView } from "./DocumentPageView";
import { SourceSpanViewer, type SourceSpanInfo } from "./SourceSpanViewer";
import { apiClient, ApiClientError } from "@/lib/api-client";

export interface EvidenceWorkbenchProps {
  workspaceId: string;
  document: DocumentDto;
  version: DocumentVersionDto;
  initialPage?: number;
  initialSpan?: SourceSpanInfo | null;
  csrfToken?: string | null;
}

export function EvidenceWorkbench({
  workspaceId,
  document,
  version,
  initialPage = 1,
  initialSpan = null,
  csrfToken,
}: EvidenceWorkbenchProps) {
  const [currentPage, setCurrentPage] = useState<number>(initialPage);
  const [selectedSpan, setSelectedSpan] = useState<SourceSpanInfo | null>(initialSpan);
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  // Derived / extracted normalized text for the current page
  // SEC-016: Raw strings from extraction are treated as untrusted text facts only
  const samplePageText =
    selectedSpan && selectedSpan.page_number === currentPage
      ? selectedSpan.text
      : `=== VERIFIED EXTRACTED PAGE ${currentPage} ===\n\nDocument: ${document.title}\nVersion Ordinal: v${version.version_number}\nArtifact Digest: ${version.sha256_hash}\nTrust State: ${version.trust_state}\n\n[Normalized content rendered inertly under SEC-016 boundary]`;

  const handleDownload = async () => {
    setIsDownloading(true);
    setDownloadError(null);
    try {
      // E24: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download
      const downloadDto = await apiClient.downloadVersion(
        workspaceId,
        version.id,
        csrfToken || undefined
      );

      // Short-lived download URL used directly without persisting to localStorage
      if (downloadDto.download_url && typeof window !== "undefined") {
        window.open(downloadDto.download_url, "_blank", "noopener,noreferrer");
      }
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setDownloadError(err.problem.detail || "Download authorization failed.");
      } else {
        setDownloadError("Failed to generate download presigned URL.");
      }
    } finally {
      setIsDownloading(false);
    }
  };

  const highlightRange =
    selectedSpan && selectedSpan.page_number === currentPage
      ? selectedSpan.normalized_range
      : null;

  return (
    <div className="evidence-workbench" data-testid="evidence-workbench">
      {/* Top Header Bar */}
      <div className="evidence-header-bar" data-testid="evidence-header-bar">
        <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", flexWrap: "wrap" }}>
            <span className="font-mono font-semibold" style={{ fontSize: "1.125rem" }}>
              v{version.version_number}
            </span>
            <h2 style={{ fontSize: "1.125rem", fontWeight: 700, margin: 0 }}>
              {version.original_filename}
            </h2>
            <span className="trust-state-badge" data-state={version.trust_state.toLowerCase()}>
              {version.trust_state}
            </span>
            {document.current_version_id === version.id && (
              <span className="version-current-badge font-mono">Current Pointer</span>
            )}
          </div>
          <div className="text-xs text-secondary font-mono">
            SHA-256: <span title={version.sha256_hash}>{version.sha256_hash}</span> • Size: {(version.byte_size / 1024).toFixed(1)} KB
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handleDownload}
            disabled={isDownloading}
            data-testid="evidence-download-btn"
          >
            {isDownloading ? "Authorizing..." : "Download Original"}
          </button>
          <a
            href={`/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(document.id)}`}
            className="btn btn-secondary btn-sm"
            data-testid="back-to-document-btn"
          >
            Back to Document
          </a>
        </div>
      </div>

      {downloadError && (
        <div className="form-error-banner" role="alert" data-testid="download-error-banner">
          {downloadError}
        </div>
      )}

      {/* Main Grid: Document Page View + Source Span Details */}
      <div className="evidence-workbench-grid">
        <DocumentPageView
          currentPage={currentPage}
          totalPages={1}
          pageText={samplePageText}
          onPageChange={(p) => setCurrentPage(p)}
          highlightRange={highlightRange}
        />

        <SourceSpanViewer
          selectedSpan={selectedSpan}
          versionNumber={version.version_number}
          documentTitle={document.title}
          onClearSelection={() => setSelectedSpan(null)}
        />
      </div>
    </div>
  );
}
