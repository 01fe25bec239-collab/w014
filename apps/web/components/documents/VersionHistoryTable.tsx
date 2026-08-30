"use client";

import React, { useState } from "react";
import type { DocumentVersionDto } from "@/lib/api-types";

export interface VersionHistoryTableProps {
  versions: DocumentVersionDto[];
  currentVersionId?: string;
  workspaceId: string;
  documentId: string;
  isLoading?: boolean;
  canManage?: boolean;
  onAcceptVersion?: (version: DocumentVersionDto) => void;
  onDownloadVersion?: (version: DocumentVersionDto) => Promise<void>;
  downloadingVersionId?: string | null;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function VersionHistoryTable({
  versions,
  currentVersionId,
  workspaceId,
  documentId,
  isLoading = false,
  canManage = false,
  onAcceptVersion,
  onDownloadVersion,
  downloadingVersionId = null,
}: VersionHistoryTableProps) {
  const [copiedHashId, setCopiedHashId] = useState<string | null>(null);

  const handleCopyHash = async (version: DocumentVersionDto) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(version.sha256_hash);
        setCopiedHashId(version.id);
        setTimeout(() => setCopiedHashId(null), 2000);
      } catch {
        // clipboard access denied in test/restricted env
      }
    }
  };

  if (isLoading) {
    return (
      <div className="table-container" data-testid="version-table-loading">
        <table className="data-table" aria-label="Loading Version History">
          <thead>
            <tr>
              <th scope="col">Version</th>
              <th scope="col">Authority</th>
              <th scope="col">Filename</th>
              <th scope="col">Size</th>
              <th scope="col">SHA-256 Digest</th>
              <th scope="col">Trust State</th>
              <th scope="col">Created</th>
              <th scope="col" className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2].map((idx) => (
              <tr key={idx}>
                <td><div className="skeleton-line" style={{ width: "40px", height: "18px" }} /></td>
                <td><div className="skeleton-line" style={{ width: "60px", height: "18px" }} /></td>
                <td><div className="skeleton-line" style={{ width: "120px", height: "18px" }} /></td>
                <td><div className="skeleton-line" style={{ width: "60px", height: "18px" }} /></td>
                <td><div className="skeleton-line" style={{ width: "100px", height: "18px" }} /></td>
                <td><div className="skeleton-line" style={{ width: "70px", height: "18px" }} /></td>
                <td><div className="skeleton-line" style={{ width: "90px", height: "18px" }} /></td>
                <td className="text-right"><div className="skeleton-line" style={{ width: "120px", height: "24px", marginLeft: "auto" }} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (versions.length === 0) {
    return (
      <div className="empty-state" data-testid="version-table-empty">
        <div className="empty-state-icon" aria-hidden="true">🗂️</div>
        <h3 className="empty-state-title">No Version History</h3>
        <p className="empty-state-desc">
          This document has no uploaded versions yet.
        </p>
        <a
          href={`/workspaces/${encodeURIComponent(workspaceId)}/upload?documentId=${encodeURIComponent(documentId)}`}
          className="btn btn-primary"
          data-testid="empty-upload-version-btn"
        >
          Upload Initial Version
        </a>
      </div>
    );
  }

  return (
    <div className="table-container" data-testid="version-table-container">
      <table className="data-table" aria-label="Immutable Version History" data-testid="version-table">
        <thead>
          <tr>
            <th scope="col">Version</th>
            <th scope="col">Authority</th>
            <th scope="col">Filename</th>
            <th scope="col">Size</th>
            <th scope="col">SHA-256 Digest</th>
            <th scope="col">Trust State</th>
            <th scope="col">Submitted</th>
            <th scope="col" className="text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {versions.map((ver) => {
            const isCurrent = ver.id === currentVersionId;
            return (
              <tr key={ver.id} data-testid={`version-row-${ver.id}`}>
                <td>
                  <span className="font-mono font-semibold" data-testid={`version-ordinal-${ver.id}`}>
                    v{ver.version_number}
                  </span>
                </td>
                <td>
                  {isCurrent ? (
                    <span
                      className="version-current-badge font-mono"
                      data-testid={`version-current-${ver.id}`}
                    >
                      Current
                    </span>
                  ) : (
                    <span
                      className="version-historical-badge"
                      data-testid={`version-historical-${ver.id}`}
                    >
                      Historical
                    </span>
                  )}
                </td>
                <td>
                  <div style={{ display: "flex", flexDirection: "column" }}>
                    <span className="font-semibold text-primary" data-testid={`version-filename-${ver.id}`}>
                      {ver.original_filename}
                    </span>
                    <span className="font-mono text-muted text-xs">
                      {ver.content_type}
                    </span>
                  </div>
                </td>
                <td className="font-mono text-xs text-secondary" data-testid={`version-size-${ver.id}`}>
                  {formatBytes(ver.byte_size)}
                </td>
                <td>
                  <div style={{ display: "inline-flex", alignItems: "center", gap: "4px" }}>
                    <span
                      className="font-mono text-xs text-secondary"
                      title={ver.sha256_hash}
                      data-testid={`version-sha256-${ver.id}`}
                    >
                      {ver.sha256_hash.slice(0, 12)}...
                    </span>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      style={{ padding: "1px 4px", fontSize: "0.6875rem" }}
                      onClick={() => handleCopyHash(ver)}
                      aria-label={`Copy SHA-256 hash for version ${ver.version_number}`}
                      data-testid={`copy-hash-btn-${ver.id}`}
                    >
                      {copiedHashId === ver.id ? "Copied" : "Copy"}
                    </button>
                  </div>
                </td>
                <td>
                  <span
                    className="trust-state-badge"
                    data-state={ver.trust_state.toLowerCase()}
                    data-testid={`version-trust-state-${ver.id}`}
                  >
                    {ver.trust_state}
                  </span>
                </td>
                <td className="text-xs text-secondary font-mono">
                  {new Date(ver.created_at).toLocaleString()}
                </td>
                <td className="text-right">
                  <div style={{ display: "inline-flex", gap: "var(--space-2)", alignItems: "center" }}>
                    <a
                      href={`/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(documentId)}/versions/${encodeURIComponent(ver.id)}`}
                      className="btn btn-primary btn-sm"
                      data-testid={`evidence-viewer-btn-${ver.id}`}
                    >
                      Evidence Viewer
                    </a>
                    {onDownloadVersion && (
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => onDownloadVersion(ver)}
                        disabled={downloadingVersionId === ver.id}
                        data-testid={`download-version-btn-${ver.id}`}
                      >
                        {downloadingVersionId === ver.id ? "Signing..." : "Download"}
                      </button>
                    )}
                    {canManage && !isCurrent && onAcceptVersion && (
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => onAcceptVersion(ver)}
                        data-testid={`accept-version-btn-${ver.id}`}
                      >
                        Set as Current
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
