"use client";

import React, { use, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  AppShell,
  PageHeader,
  DataBoundaryBadge,
  Breadcrumbs,
  WorkspaceSwitcher,
  CapabilityControl,
} from "@/components/shell";
import { ProblemNotice } from "@/components/ui/ProblemNotice";
import { UploadFlow } from "@/components/documents/UploadFlow";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { useSession } from "@/lib/session-context";
import type { DocumentDto, ProblemDetails, WorkspaceDto } from "@/lib/api-types";

export interface SecureUploadPageProps {
  params: Promise<{ workspaceId: string }> | { workspaceId: string };
}

export default function SecureUploadPage({ params }: SecureUploadPageProps) {
  const unwrappedParams = typeof (params as Promise<{ workspaceId: string }>).then === "function"
    ? use(params as Promise<{ workspaceId: string }>)
    : (params as { workspaceId: string });
  const workspaceId = unwrappedParams.workspaceId;

  const searchParams = useSearchParams();
  const initialDocumentId = searchParams?.get("documentId") || undefined;

  const { csrfToken } = useSession();

  const [workspace, setWorkspace] = useState<WorkspaceDto | null>(null);
  const [documents, setDocuments] = useState<DocumentDto[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ProblemDetails | null>(null);

  const fetchWorkspaceAndDocs = useCallback(async (wsId: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const wsData = await apiClient.getWorkspace(wsId);
      setWorkspace(wsData);

      const docsData = await apiClient.listDocuments(wsId, undefined, 100);
      setDocuments(docsData.items);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setError(err.problem);
      } else {
        setError({
          type: "urn:w014:error:upload-init-failed",
          title: "Failed to Initialize Secure Upload",
          status: 0,
          detail: "Unable to load workspace authorization for document upload.",
        });
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchWorkspaceAndDocs(workspaceId);
  }, [workspaceId, fetchWorkspaceAndDocs]);

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
          label: "Secure Upload",
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
        title="Secure Document Upload"
        subtext="Direct storage transfer, mandatory portfolio-data attestation, and quarantine gate (S06)."
        badge={<DataBoundaryBadge />}
      />

      {error && (
        <ProblemNotice
          problem={error}
          onRetry={() => fetchWorkspaceAndDocs(workspaceId)}
          className="mb-4"
        />
      )}

      {isLoading ? (
        <div className="panel" data-testid="upload-page-loading">
          <div className="panel-header">
            <h2 className="panel-title">Initializing Secure Upload Sequence</h2>
          </div>
          <div className="panel-body">
            <div className="skeleton-line" style={{ width: "50%", height: "24px" }} />
            <div className="skeleton-line" style={{ width: "80%", height: "20px" }} />
            <div className="skeleton-line" style={{ width: "60%", height: "20px" }} />
          </div>
        </div>
      ) : (
        <UploadFlow
          workspaceId={workspaceId}
          initialDocumentId={initialDocumentId}
          documents={documents}
          csrfToken={csrfToken}
        />
      )}

      <div style={{ marginTop: "var(--space-6)" }}>
        <CapabilityControl
          label="DOCUMENT_UPLOAD Presentation Tier"
          ariaLabel="Document upload capability tier"
        />
      </div>
    </AppShell>
  );
}
