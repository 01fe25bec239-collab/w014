"use client";

import React from "react";
import type { DocumentDto } from "@/lib/api-types";

export interface DocumentTableProps {
  documents: DocumentDto[];
  workspaceId: string;
  isLoading?: boolean;
}

export function DocumentTable({
  documents,
  workspaceId,
  isLoading = false,
}: DocumentTableProps) {
  if (isLoading) {
    return (
      <div className="table-container" data-testid="document-table-loading">
        <table className="data-table" aria-label="Loading Documents">
          <thead>
            <tr>
              <th scope="col">Document Title</th>
              <th scope="col">Class</th>
              <th scope="col">Current Version</th>
              <th scope="col">Status</th>
              <th scope="col">Created</th>
              <th scope="col" className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2, 3].map((idx) => (
              <tr key={idx}>
                <td>
                  <div className="skeleton-line" style={{ width: "70%", height: "20px" }} />
                </td>
                <td>
                  <div className="skeleton-line" style={{ width: "40px", height: "18px" }} />
                </td>
                <td>
                  <div className="skeleton-line" style={{ width: "80px", height: "18px" }} />
                </td>
                <td>
                  <div className="skeleton-line" style={{ width: "60px", height: "18px" }} />
                </td>
                <td>
                  <div className="skeleton-line" style={{ width: "90px", height: "18px" }} />
                </td>
                <td className="text-right">
                  <div className="skeleton-line" style={{ width: "80px", height: "24px", marginLeft: "auto" }} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (documents.length === 0) {
    return (
      <div className="empty-state" data-testid="document-table-empty">
        <div className="empty-state-icon" aria-hidden="true">📄</div>
        <h3 className="empty-state-title">No Documents Found</h3>
        <p className="empty-state-desc">
          No versioned documents have been created in this workspace yet.
        </p>
        <a
          href={`/workspaces/${encodeURIComponent(workspaceId)}/upload`}
          className="btn btn-primary"
          data-testid="empty-upload-doc-btn"
        >
          Upload First Document
        </a>
      </div>
    );
  }

  return (
    <div className="table-container" data-testid="document-table-container">
      <table className="data-table" aria-label="Workspace Documents" data-testid="document-table">
        <thead>
          <tr>
            <th scope="col">Document Title</th>
            <th scope="col">Class</th>
            <th scope="col">Current Version</th>
            <th scope="col">Status</th>
            <th scope="col">Created</th>
            <th scope="col" className="text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {documents.map((doc) => (
            <tr key={doc.id} data-testid={`doc-row-${doc.id}`}>
              <td>
                <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                  <a
                    href={`/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(doc.id)}`}
                    className="font-semibold text-primary"
                    data-testid={`doc-link-${doc.id}`}
                  >
                    {doc.title}
                  </a>
                  <span className="font-mono text-muted text-xs">
                    ID: {doc.id}
                  </span>
                </div>
              </td>
              <td>
                <span
                  className="doc-class-badge"
                  data-class={doc.document_class.toLowerCase()}
                  data-testid={`doc-class-${doc.id}`}
                >
                  {doc.document_class.toUpperCase()}
                </span>
              </td>
              <td>
                {doc.current_version_id ? (
                  <span
                    className="version-current-badge font-mono"
                    data-testid={`doc-current-version-${doc.id}`}
                  >
                    Current: {doc.current_version_id.slice(0, 8)}...
                  </span>
                ) : (
                  <span
                    className="version-historical-badge"
                    data-testid={`doc-unversioned-${doc.id}`}
                  >
                    Unversioned
                  </span>
                )}
              </td>
              <td>
                <span
                  className="trust-state-badge"
                  data-state={doc.status.toLowerCase()}
                  data-testid={`doc-status-${doc.id}`}
                >
                  {doc.status}
                </span>
              </td>
              <td className="text-xs text-secondary font-mono">
                {new Date(doc.created_at).toLocaleDateString()}
              </td>
              <td className="text-right">
                <div style={{ display: "inline-flex", gap: "var(--space-2)", alignItems: "center" }}>
                  <a
                    href={`/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(doc.id)}`}
                    className="btn btn-secondary btn-sm"
                    data-testid={`doc-view-btn-${doc.id}`}
                  >
                    View Detail
                  </a>
                  <a
                    href={`/workspaces/${encodeURIComponent(workspaceId)}/upload?documentId=${encodeURIComponent(doc.id)}`}
                    className="btn btn-secondary btn-sm"
                    data-testid={`doc-upload-version-btn-${doc.id}`}
                  >
                    Upload Version
                  </a>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
