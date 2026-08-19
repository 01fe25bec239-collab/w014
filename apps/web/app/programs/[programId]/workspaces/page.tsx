"use client";

import React, { use, useCallback, useEffect, useMemo, useState } from "react";
import {
  AppShell,
  PageHeader,
  DataBoundaryBadge,
  Breadcrumbs,
  CapabilityControl,
} from "@/components/shell";
import { DataTable, type ColumnDef } from "@/components/ui/DataTable";
import { CursorPager } from "@/components/ui/CursorPager";
import { FilterBar } from "@/components/ui/FilterBar";
import { ProblemNotice } from "@/components/ui/ProblemNotice";
import { CreateWorkspaceModal } from "@/components/workspaces/CreateWorkspaceModal";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { useSession } from "@/lib/session-context";
import type {
  CreateWorkspaceDto,
  ProblemDetails,
  ProgramDto,
  WorkspaceDto,
} from "@/lib/api-types";

export interface ProgramWorkspacesPageProps {
  params: Promise<{ programId: string }> | { programId: string };
}

export default function ProgramWorkspacesPage({ params }: ProgramWorkspacesPageProps) {
  const unwrappedParams = typeof (params as Promise<{ programId: string }>).then === "function"
    ? use(params as Promise<{ programId: string }>)
    : (params as { programId: string });
  const programId = unwrappedParams.programId;

  const { csrfToken } = useSession();

  const [program, setProgram] = useState<ProgramDto | null>(null);
  const [workspaces, setWorkspaces] = useState<WorkspaceDto[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ProblemDetails | null>(null);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [hasMore, setHasMore] = useState<boolean>(false);
  const [cursorHistory, setCursorHistory] = useState<string[]>([]);
  const [filterText, setFilterText] = useState<string>("");

  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createServerError, setCreateServerError] = useState<string | null>(null);

  const fetchProgramAndWorkspaces = useCallback(
    async (cursor?: string) => {
      setIsLoading(true);
      setError(null);
      try {
        // Fetch program metadata and workspaces concurrently
        const [progData, wsPage] = await Promise.all([
          apiClient.getProgram(programId),
          apiClient.listWorkspaces(programId, cursor, 50),
        ]);
        setProgram(progData);
        setWorkspaces(wsPage.items);
        setNextCursor(wsPage.next_cursor);
        setHasMore(wsPage.has_more);
        setError(null);
      } catch (err: unknown) {
        if (err instanceof ApiClientError) {
          setError(err.problem);
        } else {
          setError({
            type: "urn:w014:error:workspaces-fetch",
            title: "Failed to Fetch Workspaces",
            status: 0,
            detail: "An unexpected error occurred while loading program workspaces.",
          });
        }
      } finally {
        setIsLoading(false);
      }
    },
    [programId]
  );

  useEffect(() => {
    fetchProgramAndWorkspaces();
  }, [fetchProgramAndWorkspaces]);

  const handleNextPage = () => {
    if (!nextCursor || !hasMore) return;
    setCursorHistory((prev) => [...prev, nextCursor]);
    fetchProgramAndWorkspaces(nextCursor);
  };

  const handlePrevPage = () => {
    if (cursorHistory.length === 0) return;
    const nextHistory = [...cursorHistory];
    nextHistory.pop();
    const prevCursor = nextHistory[nextHistory.length - 1];
    setCursorHistory(nextHistory);
    fetchProgramAndWorkspaces(prevCursor);
  };

  const handleCreateWorkspace = async (dto: CreateWorkspaceDto) => {
    setIsCreating(true);
    setCreateServerError(null);
    try {
      await apiClient.createWorkspace(programId, dto, csrfToken || undefined);
      setIsCreateModalOpen(false);
      await fetchProgramAndWorkspaces(); // Refresh list after creation
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setCreateServerError(err.problem.detail || err.problem.title);
      } else {
        setCreateServerError("Failed to create workspace.");
      }
    } finally {
      setIsCreating(false);
    }
  };

  const filteredWorkspaces = useMemo(() => {
    if (!filterText.trim()) return workspaces;
    const term = filterText.toLowerCase();
    return workspaces.filter(
      (ws) =>
        ws.name.toLowerCase().includes(term) ||
        ws.slug.toLowerCase().includes(term) ||
        ws.id.toLowerCase().includes(term)
    );
  }, [workspaces, filterText]);

  const columns: ColumnDef<WorkspaceDto>[] = useMemo(
    () => [
      {
        key: "name",
        header: "Workspace Name",
        render: (ws) => (
          <div>
            <span className="font-semibold text-primary">{ws.name}</span>
          </div>
        ),
      },
      {
        key: "slug",
        header: "Slug",
        render: (ws) => <code className="text-muted font-mono">{ws.slug}</code>,
      },
      {
        key: "id",
        header: "Workspace ID",
        render: (ws) => (
          <code className="text-secondary text-xs font-mono">{ws.id}</code>
        ),
      },
      {
        key: "created_at",
        header: "Created",
        render: (ws) => (
          <span className="text-secondary text-xs">
            {new Date(ws.created_at).toLocaleDateString()}
          </span>
        ),
      },
      {
        key: "actions",
        header: "Action",
        className: "text-right",
        headerClassName: "text-right",
        render: (ws) => (
          <a
            href={`/workspaces/${encodeURIComponent(ws.id)}`}
            className="btn btn-primary btn-sm"
            data-testid={`open-workspace-btn-${ws.id}`}
          >
            Open Shell →
          </a>
        ),
      },
    ],
    []
  );

  const breadcrumbs = (
    <Breadcrumbs
      items={[
        { label: "W-014", href: "/" },
        { label: "Programs", href: "/programs" },
        {
          label: program?.name || "Program Workspaces",
          current: true,
        },
      ]}
    />
  );

  return (
    <AppShell breadcrumbs={breadcrumbs} enableW1Nav={true}>
      <PageHeader
        title={program ? `${program.name} Workspaces` : "Program Workspaces"}
        subtext={
          program?.description ||
          `Operational workspaces scoped to program ${program?.slug || programId} (WI-0106 / S03).`
        }
        badge={<DataBoundaryBadge />}
        actions={
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setIsCreateModalOpen(true)}
            data-testid="create-workspace-btn"
          >
            + Create Workspace
          </button>
        }
      />

      {error && (
        <ProblemNotice
          problem={error}
          onRetry={() => fetchProgramAndWorkspaces()}
          className="mb-4"
        />
      )}

      <div className="portfolio-content">
        <div className="portfolio-controls">
          <FilterBar
            value={filterText}
            onChange={setFilterText}
            placeholder="Filter workspaces by name, slug, or ID..."
            label="Filter workspaces"
            count={filteredWorkspaces.length}
            totalCount={workspaces.length}
          />
        </div>

        <DataTable
          columns={columns}
          data={filteredWorkspaces}
          keyExtractor={(ws) => ws.id}
          caption={
            program
              ? `Workspaces for program ${program.name}`
              : "Program Workspaces"
          }
          isLoading={isLoading}
          emptyMessage={
            filterText
              ? `No workspaces match filter "${filterText}".`
              : "No workspaces exist in this program. Create your first workspace to begin."
          }
          testId="workspaces-data-table"
        />

        {(hasMore || cursorHistory.length > 0) && (
          <div style={{ marginTop: "var(--space-4)" }}>
            <CursorPager
              hasMore={hasMore}
              hasPrevious={cursorHistory.length > 0}
              onNext={handleNextPage}
              onPrevious={handlePrevPage}
              isLoading={isLoading}
            />
          </div>
        )}

        <div style={{ marginTop: "var(--space-6)" }}>
          <CapabilityControl
            label="WORKSPACE_READ / WORKSPACE_CREATE Presentation Tier"
            ariaLabel="Program workspaces capability tier"
          />
        </div>
      </div>

      <CreateWorkspaceModal
        isOpen={isCreateModalOpen}
        programName={program?.name}
        onClose={() => {
          setIsCreateModalOpen(false);
          setCreateServerError(null);
        }}
        onSubmit={handleCreateWorkspace}
        isLoading={isCreating}
        serverError={createServerError}
      />
    </AppShell>
  );
}
