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
import { FilterBar } from "@/components/ui/FilterBar";
import { DocumentTable } from "@/components/documents/DocumentTable";
import { CreateDocumentModal } from "@/components/documents/CreateDocumentModal";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { useSession } from "@/lib/session-context";
import type {
  CreateDocumentDto,
  DocumentDto,
  DocumentPage,
  ProblemDetails,
  WorkspaceDto,
} from "@/lib/api-types";

export interface DocumentLibraryPageProps {
  params: Promise<{ workspaceId: string }> | { workspaceId: string };
}

export default function DocumentLibraryPage({ params }: DocumentLibraryPageProps) {
  const unwrappedParams = typeof (params as Promise<{ workspaceId: string }>).then === "function"
    ? use(params as Promise<{ workspaceId: string }>)
    : (params as { workspaceId: string });
  const workspaceId = unwrappedParams.workspaceId;

  const { csrfToken } = useSession();

  // Authoritative State
  const [workspace, setWorkspace] = useState<WorkspaceDto | null>(null);
  const [documentPage, setDocumentPage] = useState<DocumentPage | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ProblemDetails | null>(null);

  // Pagination & Filtering state (presentation only)
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [searchFilter, setSearchFilter] = useState<string>("");
  const [classFilter, setClassFilter] = useState<string>("all");

  // Modal State
  const [isCreateModalOpen, setIsCreateModalOpen] = useState<boolean>(false);
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const fetchWorkspaceAndDocs = useCallback(async (wsId: string, currentCursor?: string) => {
    setIsLoading(true);
    setError(null);

    try {
      // E10: getWorkspace
      const wsData = await apiClient.getWorkspace(wsId);
      setWorkspace(wsData);

      // E16: listDocuments (bounded server cursor pagination)
      const docsData = await apiClient.listDocuments(wsId, currentCursor, 50);
      setDocumentPage(docsData);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setError(err.problem);
      } else {
        setError({
          type: "urn:w014:error:document-fetch",
          title: "Failed to Load Document Library",
          status: 0,
          detail: "An unexpected error occurred while fetching workspace documents.",
        });
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchWorkspaceAndDocs(workspaceId, cursor);
  }, [workspaceId, cursor, fetchWorkspaceAndDocs]);

  const handleCreateDocument = async (dto: CreateDocumentDto) => {
    setIsCreating(true);
    setCreateError(null);
    try {
      const idempKey = `doc_create_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
      await apiClient.createDocument(
        workspaceId,
        dto,
        csrfToken || undefined,
        idempKey
      );
      setIsCreateModalOpen(false);
      await fetchWorkspaceAndDocs(workspaceId, cursor);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setCreateError(err.problem.detail || err.problem.title || "Failed to create document.");
      } else {
        setCreateError("An unexpected error occurred while creating document.");
      }
    } finally {
      setIsCreating(false);
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

  // Client-side presentation filtering over fetched bounded page
  const filteredDocuments = (documentPage?.items || []).filter((doc: DocumentDto) => {
    const matchesSearch =
      searchFilter === "" ||
      doc.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
      doc.id.toLowerCase().includes(searchFilter.toLowerCase());

    const matchesClass =
      classFilter === "all" || doc.document_class.toLowerCase() === classFilter.toLowerCase();

    return matchesSearch && matchesClass;
  });

  return (
    <AppShell breadcrumbs={breadcrumbs} workspaceSlot={workspaceSlot} enableW1Nav={true}>
      <PageHeader
        title="Document Library"
        subtext="Versioned evidence documents, immutable lineage, and authoritative current pointers (S05)."
        badge={<DataBoundaryBadge />}
        actions={
          <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setIsCreateModalOpen(true)}
              data-testid="create-doc-modal-btn"
            >
              + Create Logical Document
            </button>
            <a
              href={`/workspaces/${encodeURIComponent(workspaceId)}/upload`}
              className="btn btn-primary"
              data-testid="upload-document-btn"
            >
              Secure Upload (S06)
            </a>
          </div>
        }
      />

      {/* Context Tabs */}
      <ContextTabs
        tabs={[
          { id: "overview", label: "Overview", active: false },
          { id: "documents", label: "Document Library (S05)", active: true },
          { id: "verification", label: "Verification Engine", active: false },
          { id: "compliance", label: "Compliance & CDRL", active: false },
        ]}
        className="mb-4"
      />

      {error && (
        <ProblemNotice
          problem={error}
          onRetry={() => fetchWorkspaceAndDocs(workspaceId, cursor)}
          className="mb-4"
        />
      )}

      {/* Filter and Search Bar */}
      <div className="filter-bar" data-testid="document-filter-bar">
        <FilterBar
          value={searchFilter}
          onChange={setSearchFilter}
          count={filteredDocuments.length}
          placeholder="Filter documents by title or ID..."
        />

        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
          <label htmlFor="class-filter" className="text-xs text-secondary font-mono">Class:</label>
          <select
            id="class-filter"
            className="form-input"
            style={{ width: "auto", padding: "4px 8px", fontSize: "0.8125rem" }}
            value={classFilter}
            onChange={(e) => setClassFilter(e.target.value)}
            data-testid="class-filter-select"
          >
            <option value="all">All Classes</option>
            <option value="pdf">PDF</option>
            <option value="docx">DOCX</option>
          </select>
        </div>
      </div>

      {/* Primary Document Table */}
      <DocumentTable
        documents={filteredDocuments}
        workspaceId={workspaceId}
        isLoading={isLoading}
      />

      {/* Bounded Cursor Pagination */}
      {documentPage && (
        <div style={{ marginTop: "var(--space-4)" }}>
          <CursorPager
            hasMore={documentPage.has_more}
            hasPrevious={!!cursor}
            onNext={() => {
              if (documentPage.next_cursor) {
                setCursor(documentPage.next_cursor);
              }
            }}
            onPrevious={() => setCursor(undefined)}
            isLoading={isLoading}
          />
        </div>
      )}

      <div style={{ marginTop: "var(--space-6)" }}>
        <CapabilityControl
          label="DOCUMENT_READ Presentation Tier"
          ariaLabel="Document library capability tier"
        />
      </div>

      {/* Create Document Modal */}
      <CreateDocumentModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSubmit={handleCreateDocument}
        isLoading={isCreating}
        serverError={createError}
      />
    </AppShell>
  );
}
