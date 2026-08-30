"use client";

import React, { use, useCallback, useEffect, useState } from "react";
import {
  AppShell,
  PageHeader,
  DataBoundaryBadge,
  Breadcrumbs,
  WorkspaceSwitcher,
  ContextTabs,
  CapabilityControl,
} from "@/components/shell";
import { ProblemNotice } from "@/components/ui/ProblemNotice";
import { CursorPager } from "@/components/ui/CursorPager";
import { VersionHistoryTable } from "@/components/documents/VersionHistoryTable";
import { AcceptVersionModal } from "@/components/documents/AcceptVersionModal";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { useSession } from "@/lib/session-context";
import type {
  DocumentDto,
  DocumentVersionDto,
  DocumentVersionPage,
  ProblemDetails,
  WorkspaceDto,
} from "@/lib/api-types";

export interface DocumentDetailPageProps {
  params: Promise<{ workspaceId: string; documentId: string }> | { workspaceId: string; documentId: string };
}

export default function DocumentDetailPage({ params }: DocumentDetailPageProps) {
  const unwrappedParams = typeof (params as Promise<{ workspaceId: string; documentId: string }>).then === "function"
    ? use(params as Promise<{ workspaceId: string; documentId: string }>)
    : (params as { workspaceId: string; documentId: string });
  const { workspaceId, documentId } = unwrappedParams;

  const { csrfToken } = useSession();

  const [workspace, setWorkspace] = useState<WorkspaceDto | null>(null);
  const [document, setDocument] = useState<DocumentDto | null>(null);
  const [versionPage, setVersionPage] = useState<DocumentVersionPage | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ProblemDetails | null>(null);

  // Accept Version Modal State
  const [selectedVersionToAccept, setSelectedVersionToAccept] = useState<DocumentVersionDto | null>(null);
  const [isAccepting, setIsAccepting] = useState<boolean>(false);
  const [acceptError, setAcceptError] = useState<string | null>(null);

  // Download State
  const [downloadingVersionId, setDownloadingVersionId] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const fetchDocumentAndVersions = useCallback(async (wsId: string, docId: string, currentCursor?: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const wsData = await apiClient.getWorkspace(wsId);
      setWorkspace(wsData);

      // E18: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}
      const docData = await apiClient.getDocument(wsId, docId);
      setDocument(docData);

      // E19: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}/versions
      const versionsData = await apiClient.listDocumentVersions(wsId, docId, currentCursor, 50);
      setVersionPage(versionsData);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setError(err.problem);
      } else {
        setError({
          type: "urn:w014:error:document-fetch",
          title: "Failed to Load Document Details",
          status: 0,
          detail: "An unexpected error occurred while fetching document and versions.",
        });
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDocumentAndVersions(workspaceId, documentId, cursor);
  }, [workspaceId, documentId, cursor, fetchDocumentAndVersions]);

  const handleOpenAcceptModal = (version: DocumentVersionDto) => {
    setSelectedVersionToAccept(version);
    setAcceptError(null);
  };

  const handleConfirmAcceptVersion = async () => {
    if (!selectedVersionToAccept || !document) return;

    setIsAccepting(true);
    setAcceptError(null);
    try {
      const idempKey = `accept_ver_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
      // E23: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept
      // Precondition Guard: If-Match: "{row_version}"
      const updatedDoc = await apiClient.acceptVersion(
        workspaceId,
        selectedVersionToAccept.id,
        document.row_version,
        csrfToken || undefined,
        idempKey
      );

      setDocument(updatedDoc);
      setSelectedVersionToAccept(null);
      await fetchDocumentAndVersions(workspaceId, documentId, cursor);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setAcceptError(err.problem.detail || err.problem.title || "Failed to promote version.");
      } else {
        setAcceptError("An unexpected error occurred while promoting version.");
      }
    } finally {
      setIsAccepting(false);
    }
  };

  const handleDownloadVersion = async (version: DocumentVersionDto) => {
    setDownloadingVersionId(version.id);
    setDownloadError(null);
    try {
      // E24: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download
      const downloadDto = await apiClient.downloadVersion(
        workspaceId,
        version.id,
        csrfToken || undefined
      );

      if (downloadDto.download_url && typeof window !== "undefined") {
        window.open(downloadDto.download_url, "_blank", "noopener,noreferrer");
      }
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setDownloadError(err.problem.detail || "Failed to generate download presigned URL.");
      } else {
        setDownloadError("Download request failed.");
      }
    } finally {
      setDownloadingVersionId(null);
    }
  };

  const breadcrumbs = (
    <Breadcrumbs
      items={[
        { label: "W-014", href: "/" },
        { label: "Programs", href: "/programs" },
        {
          label: workspace?.name ? `Workspace: ${workspace.name}` : `Workspace (${workspaceId})`,
          href: `/workspaces/${encodeURIComponent(workspaceId)}`,
        },
        {
          label: "Document Library",
          href: `/workspaces/${encodeURIComponent(workspaceId)}/documents`,
        },
        {
          label: document?.title ? document.title : `Document (${documentId})`,
          current: true,
        },
      ]}
    />
  );

  const workspaceSlot = (
    <WorkspaceSwitcher
      currentWorkspace={
        workspace
          ? { name: workspace.name, slug: workspace.slug, id: workspace.id }
          : undefined
      }
      currentProgram={
        workspace ? { name: "Program Workspaces", id: workspace.program_id } : undefined
      }
    />
  );

  return (
    <AppShell breadcrumbs={breadcrumbs} workspaceSlot={workspaceSlot} enableW1Nav={true}>
      <PageHeader
        title={document ? document.title : `Document Details`}
        subtext="Logical document summary, authoritative current pointer, and immutable version history (S07)."
        badge={<DataBoundaryBadge />}
        actions={
          document ? (
            <a
              href={`/workspaces/${encodeURIComponent(workspaceId)}/upload?documentId=${encodeURIComponent(document.id)}`}
              className="btn btn-primary"
              data-testid="upload-new-version-btn"
            >
              + Upload New Version
            </a>
          ) : undefined
        }
      />

      {/* Context Navigation Tabs */}
      <ContextTabs
        tabs={[
          { id: "overview", label: "Overview", active: false },
          { id: "documents", label: "Document Library", active: false },
          { id: "document-detail", label: "Document Detail (S07)", active: true },
          { id: "verification", label: "Verification Engine", active: false },
        ]}
        className="mb-4"
      />

      {error && (
        <ProblemNotice
          problem={error}
          onRetry={() => fetchDocumentAndVersions(workspaceId, documentId, cursor)}
          className="mb-4"
        />
      )}

      {downloadError && (
        <div className="form-error-banner" role="alert" data-testid="document-download-error">
          {downloadError}
        </div>
      )}

      {isLoading ? (
        <div className="panel" data-testid="document-detail-loading">
          <div className="panel-header">
            <h2 className="panel-title">Loading Document Authority</h2>
          </div>
          <div className="panel-body">
            <div className="skeleton-line" style={{ width: "60%", height: "24px" }} />
            <div className="skeleton-line" style={{ width: "80%", height: "20px" }} />
            <div className="skeleton-line" style={{ width: "40%", height: "20px" }} />
          </div>
        </div>
      ) : document ? (
        <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
          {/* Panel 1: Logical Document Identity & Authoritative Current Pointer */}
          <section className="panel" aria-labelledby="heading-doc-summary" data-testid="doc-summary-panel">
            <div className="panel-header">
              <h2 id="heading-doc-summary" className="panel-title">
                Logical Document Summary
              </h2>
              <span
                className="doc-class-badge"
                data-class={document.document_class.toLowerCase()}
                data-testid="detail-doc-class"
              >
                {document.document_class.toUpperCase()}
              </span>
            </div>
            <div className="panel-body">
              <ul className="panel-item-list">
                <li className="panel-item">
                  <span className="panel-item-key">Document Title:</span>
                  <span className="panel-item-value" data-testid="detail-doc-title">
                    {document.title}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Document ID:</span>
                  <span className="panel-item-value font-mono" data-testid="detail-doc-id">
                    {document.id}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Authoritative Current Version:</span>
                  <span className="panel-item-value font-mono" data-testid="detail-doc-current-version">
                    {document.current_version_id ? (
                      <span className="version-current-badge font-mono">
                        {document.current_version_id}
                      </span>
                    ) : (
                      <span className="version-historical-badge">Unversioned</span>
                    )}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Document Status:</span>
                  <span className="trust-state-badge" data-state={document.status.toLowerCase()} data-testid="detail-doc-status">
                    {document.status}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Row Version (Precondition Guard):</span>
                  <span className="panel-item-value font-mono" data-testid="detail-doc-row-version">
                    {document.row_version}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Created:</span>
                  <span className="panel-item-value">
                    {new Date(document.created_at).toLocaleString()}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Last Updated:</span>
                  <span className="panel-item-value">
                    {new Date(document.updated_at).toLocaleString()}
                  </span>
                </li>
              </ul>
            </div>
          </section>

          {/* Panel 2: Immutable Version History */}
          <section className="panel" aria-labelledby="heading-version-history" data-testid="version-history-panel">
            <div className="panel-header">
              <h2 id="heading-version-history" className="panel-title">
                Immutable Version History
              </h2>
              <span className="nav-item-badge">
                {versionPage?.items.length || 0} {versionPage?.items.length === 1 ? "Version" : "Versions"} Recorded
              </span>
            </div>
            <div className="panel-body" style={{ padding: 0 }}>
              <VersionHistoryTable
                versions={versionPage?.items || []}
                currentVersionId={document.current_version_id}
                workspaceId={workspaceId}
                documentId={documentId}
                isLoading={isLoading}
                canManage={true}
                onAcceptVersion={handleOpenAcceptModal}
                onDownloadVersion={handleDownloadVersion}
                downloadingVersionId={downloadingVersionId}
              />
            </div>
          </section>

          {/* Version Cursor Pagination */}
          {versionPage && (
            <CursorPager
              hasMore={versionPage.has_more}
              hasPrevious={!!cursor}
              onNext={() => {
                if (versionPage.next_cursor) {
                  setCursor(versionPage.next_cursor);
                }
              }}
              onPrevious={() => setCursor(undefined)}
              isLoading={isLoading}
            />
          )}
        </div>
      ) : null}

      <div style={{ marginTop: "var(--space-6)" }}>
        <CapabilityControl
          label="DOCUMENT_READ / DOCUMENT_MANAGE Presentation Tier"
          ariaLabel="Document detail capability tier"
        />
      </div>

      {/* Accept Version Modal */}
      {document && (
        <AcceptVersionModal
          isOpen={!!selectedVersionToAccept}
          onClose={() => setSelectedVersionToAccept(null)}
          onConfirm={handleConfirmAcceptVersion}
          version={selectedVersionToAccept}
          rowVersion={document.row_version}
          isLoading={isAccepting}
          serverError={acceptError}
        />
      )}
    </AppShell>
  );
}
