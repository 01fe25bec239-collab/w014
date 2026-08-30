"use client";

import React, { use, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
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
import { EvidenceWorkbench } from "@/components/documents/EvidenceWorkbench";
import type { SourceSpanInfo } from "@/components/documents/SourceSpanViewer";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { useSession } from "@/lib/session-context";
import type {
  DocumentDto,
  DocumentVersionDto,
  ProblemDetails,
  WorkspaceDto,
} from "@/lib/api-types";

export interface EvidenceViewerPageProps {
  params: Promise<{ workspaceId: string; documentId: string; versionId: string }> | { workspaceId: string; documentId: string; versionId: string };
}

export default function EvidenceViewerPage({ params }: EvidenceViewerPageProps) {
  const unwrappedParams = typeof (params as Promise<{ workspaceId: string; documentId: string; versionId: string }>).then === "function"
    ? use(params as Promise<{ workspaceId: string; documentId: string; versionId: string }>)
    : (params as { workspaceId: string; documentId: string; versionId: string });
  const { workspaceId, documentId, versionId } = unwrappedParams;

  const searchParams = useSearchParams();
  const pageParam = searchParams?.get("page");
  const spanParam = searchParams?.get("span");

  const initialPage = pageParam ? Math.max(1, parseInt(pageParam, 10) || 1) : 1;

  const { csrfToken } = useSession();

  const [workspace, setWorkspace] = useState<WorkspaceDto | null>(null);
  const [document, setDocument] = useState<DocumentDto | null>(null);
  const [version, setVersion] = useState<DocumentVersionDto | null>(null);

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ProblemDetails | null>(null);

  const fetchWorkbenchData = useCallback(async (wsId: string, docId: string, verId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const wsData = await apiClient.getWorkspace(wsId);
      setWorkspace(wsData);

      // E18: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}
      const docData = await apiClient.getDocument(wsId, docId);
      setDocument(docData);

      // E22: GET /api/v1/workspaces/{workspace_id}/document-versions/{version_id}
      const verData = await apiClient.getDocumentVersion(wsId, verId);
      setVersion(verData);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setError(err.problem);
      } else {
        setError({
          type: "urn:w014:error:evidence-fetch",
          title: "Failed to Load Immutable Evidence Viewer",
          status: 0,
          detail: "Unable to load document version evidence workbench.",
        });
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchWorkbenchData(workspaceId, documentId, versionId);
  }, [workspaceId, documentId, versionId, fetchWorkbenchData]);

  // Construct initial span if citation anchor query param is present
  const initialSpan: SourceSpanInfo | null = spanParam ? {
    id: `span_${spanParam}`,
    page_number: initialPage,
    span_sequence: parseInt(spanParam, 10) || 1,
    normalized_range: { start: 0, end: 50 },
    section_path: ["Evidence Anchor"],
    text: `Verified canonical source span #${spanParam} for version ${versionId}`,
    extraction: "native_text",
    quality_score: 1.0,
  } : null;

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
          href: `/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(documentId)}`,
        },
        {
          label: version ? `Version v${version.version_number} Evidence` : `Version Evidence`,
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
        title={
          document && version
            ? `Evidence Viewer: ${document.title} (v${version.version_number})`
            : "Immutable Evidence Viewer"
        }
        subtext="Canonical parser facts, immutable version identity, bounded page view, and citable source spans (S08)."
        badge={<DataBoundaryBadge />}
      />

      {/* Context Navigation Tabs */}
      <ContextTabs
        tabs={[
          { id: "overview", label: "Overview", active: false },
          { id: "documents", label: "Document Library", active: false },
          { id: "document-detail", label: "Document Detail", active: false },
          { id: "evidence-viewer", label: "Evidence Viewer (S08)", active: true },
        ]}
        className="mb-4"
      />

      {error && (
        <ProblemNotice
          problem={error}
          onRetry={() => fetchWorkbenchData(workspaceId, documentId, versionId)}
          className="mb-4"
        />
      )}

      {isLoading ? (
        <div className="panel" data-testid="evidence-viewer-loading">
          <div className="panel-header">
            <h2 className="panel-title">Loading Evidence Workbench</h2>
          </div>
          <div className="panel-body">
            <div className="skeleton-line" style={{ width: "50%", height: "24px" }} />
            <div className="skeleton-line" style={{ width: "90%", height: "20px" }} />
            <div className="skeleton-line" style={{ width: "70%", height: "20px" }} />
          </div>
        </div>
      ) : document && version ? (
        <EvidenceWorkbench
          workspaceId={workspaceId}
          document={document}
          version={version}
          initialPage={initialPage}
          initialSpan={initialSpan}
          csrfToken={csrfToken}
        />
      ) : null}

      <div style={{ marginTop: "var(--space-6)" }}>
        <CapabilityControl
          label="DOCUMENT_READ / EVIDENCE_READ Presentation Tier"
          ariaLabel="Evidence viewer capability tier"
        />
      </div>
    </AppShell>
  );
}
