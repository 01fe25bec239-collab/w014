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
import { apiClient, ApiClientError } from "@/lib/api-client";
import type { ProblemDetails, WorkspaceDto } from "@/lib/api-types";

export interface WorkspaceShellPageProps {
  params: Promise<{ workspaceId: string }> | { workspaceId: string };
}

export default function WorkspaceShellPage({ params }: WorkspaceShellPageProps) {
  const unwrappedParams = typeof (params as Promise<{ workspaceId: string }>).then === "function"
    ? use(params as Promise<{ workspaceId: string }>)
    : (params as { workspaceId: string });
  const workspaceId = unwrappedParams.workspaceId;

  // Authoritative workspace state scoped strictly to the current workspaceId
  const [workspace, setWorkspace] = useState<WorkspaceDto | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ProblemDetails | null>(null);

  const fetchWorkspace = useCallback(async (id: string) => {
    setIsLoading(true);
    // Explicitly reset prior workspace state to prevent cross-workspace data leakage
    setWorkspace(null);
    setError(null);

    try {
      // Sole authorized W1 backend call: GET /api/v1/workspaces/{workspace_id}
      // HARD RULE: E11 / source-state MUST NOT BE CALLED
      const data = await apiClient.getWorkspace(id);
      setWorkspace(data);
      setError(null);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setError(err.problem);
      } else {
        setError({
          type: "urn:w014:error:workspace-fetch",
          title: "Failed to Load Workspace",
          status: 0,
          detail: "An unexpected error occurred while loading workspace.",
        });
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchWorkspace(workspaceId);
  }, [workspaceId, fetchWorkspace]);

  const breadcrumbs = (
    <Breadcrumbs
      items={[
        { label: "W-014", href: "/" },
        { label: "Programs", href: "/programs" },
        {
          label: workspace?.name ? `Workspace: ${workspace.name}` : `Workspace (${workspaceId})`,
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
        title={workspace ? workspace.name : `Workspace: ${workspaceId}`}
        subtext={
          workspace
            ? `Operational workspace shell for verification, compliance, and evidence tracking (WI-0106 / S04).`
            : "Operational workspace shell (loading authoritative state)."
        }
        badge={<DataBoundaryBadge />}
      />

      {/* Context Navigation Tabs */}
      <ContextTabs
        tabs={[
          { id: "overview", label: "Overview (W1)", active: true },
          { id: "verification", label: "Verification Engine (W2)", active: false },
          { id: "compliance", label: "Compliance & CDRL (W3)", active: false },
          { id: "evidence", label: "Evidence & Audit (W4)", active: false },
        ]}
        className="mb-4"
      />

      {error && (
        <ProblemNotice
          problem={error}
          onRetry={() => fetchWorkspace(workspaceId)}
          className="mb-4"
        />
      )}

      {isLoading ? (
        <div className="panel" data-testid="workspace-shell-loading">
          <div className="panel-header">
            <h2 className="panel-title">Loading Workspace Authority</h2>
            <span className="nav-item-badge">E10 Inspection</span>
          </div>
          <div className="panel-body">
            <p>Fetching authoritative workspace metadata under RLS isolation...</p>
            <div className="skeleton-line" style={{ height: "28px", width: "50%" }} />
            <div className="skeleton-line" style={{ height: "20px", width: "70%" }} />
            <div className="skeleton-line" style={{ height: "20px", width: "40%" }} />
          </div>
        </div>
      ) : workspace ? (
        <div className="panel-grid" data-testid="workspace-shell-content">
          {/* Panel 1: Authoritative Workspace Identity & Lineage */}
          <section className="panel" aria-labelledby="heading-ws-identity" data-testid="ws-identity-panel">
            <div className="panel-header">
              <h2 id="heading-ws-identity" className="panel-title">
                Authoritative Workspace Identity
              </h2>
              <span className="environment-badge" data-env="local" style={{ fontSize: "0.625rem" }}>
                ACTIVE
              </span>
            </div>
            <div className="panel-body">
              <p>
                Authoritative domain metadata verified by Rust core under tenant and membership isolation.
              </p>
              <ul className="panel-item-list">
                <li className="panel-item">
                  <span className="panel-item-key">Workspace Name:</span>
                  <span className="panel-item-value" data-testid="ws-meta-name">
                    {workspace.name}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Workspace Slug:</span>
                  <span className="panel-item-value font-mono" data-testid="ws-meta-slug">
                    {workspace.slug}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Workspace ID:</span>
                  <span className="panel-item-value font-mono" data-testid="ws-meta-id">
                    {workspace.id}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Parent Program ID:</span>
                  <span className="panel-item-value font-mono" data-testid="ws-meta-program-id">
                    {workspace.program_id}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Organization ID:</span>
                  <span className="panel-item-value font-mono">
                    {workspace.organization_id}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Created:</span>
                  <span className="panel-item-value">
                    {new Date(workspace.created_at).toLocaleString()}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Updated:</span>
                  <span className="panel-item-value">
                    {new Date(workspace.updated_at).toLocaleString()}
                  </span>
                </li>
              </ul>
            </div>
          </section>

          {/* Panel 2: Truthful Prerequisite / Deferred W2 Verification Engine */}
          <section className="panel" aria-labelledby="heading-ws-w2" data-testid="deferred-w2-panel">
            <div className="panel-header">
              <h2 id="heading-ws-w2" className="panel-title">
                Verification Engine (Wave 2)
              </h2>
              <span className="nav-item-badge">Prerequisite / Deferred</span>
            </div>
            <div className="panel-body">
              <p>
                Rule sets, preflight verification checks, and automated compliance diagnostics arrive in Wave 2 (WI-0201).
              </p>
              <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Authoritative truth boundary: No simulated verification results or fake READY statuses are rendered in W1.
              </p>
            </div>
          </section>

          {/* Panel 3: Truthful Prerequisite / Deferred W3 Source State & Compliance */}
          <section className="panel" aria-labelledby="heading-ws-w3" data-testid="deferred-w3-panel">
            <div className="panel-header">
              <h2 id="heading-ws-w3" className="panel-title">
                Source State &amp; Compliance Matrix (Wave 3)
              </h2>
              <span className="nav-item-badge">Prerequisite / Deferred</span>
            </div>
            <div className="panel-body">
              <p>
                Source state ingestion (E11 / WI-0303) and CDRL delivery tracking arrive in Wave 3.
              </p>
              <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Authoritative truth boundary: E11 is not queried. No invented source state or synthetic evidence is rendered.
              </p>
            </div>
          </section>

          {/* Panel 4: Truthful Prerequisite / Deferred W4 Evidence & Audit */}
          <section className="panel" aria-labelledby="heading-ws-w4" data-testid="deferred-w4-panel">
            <div className="panel-header">
              <h2 id="heading-ws-w4" className="panel-title">
                Evidence Chain &amp; Audit (Wave 4)
              </h2>
              <span className="nav-item-badge">Prerequisite / Deferred</span>
            </div>
            <div className="panel-body">
              <p>
                Cryptographic audit chain exploration, evidence package export, and tamper-evident proof validation arrive in Wave 4.
              </p>
              <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Authoritative truth boundary: Atomic audit events are recorded server-side during workspace creation and remain tamper-evident.
              </p>
            </div>
          </section>
        </div>
      ) : null}

      <div style={{ marginTop: "var(--space-6)" }}>
        <CapabilityControl
          label="WORKSPACE_READ Presentation Tier"
          ariaLabel="Workspace shell capability tier"
        />
      </div>
    </AppShell>
  );
}
