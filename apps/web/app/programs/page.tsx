"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
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
import { CreateProgramModal } from "@/components/programs/CreateProgramModal";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { useSession } from "@/lib/session-context";
import type { CreateProgramDto, ProblemDetails, ProgramDto } from "@/lib/api-types";

export default function ProgramsPage() {
  const { csrfToken } = useSession();

  const [programs, setPrograms] = useState<ProgramDto[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ProblemDetails | null>(null);
  const [nextCursor, setNextCursor] = useState<string | undefined>(undefined);
  const [hasMore, setHasMore] = useState<boolean>(false);
  const [cursorHistory, setCursorHistory] = useState<string[]>([]);
  const [filterText, setFilterText] = useState<string>("");

  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createServerError, setCreateServerError] = useState<string | null>(null);

  const fetchPrograms = useCallback(async (cursor?: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const page = await apiClient.listPrograms(cursor, 50);
      setPrograms(page.items);
      setNextCursor(page.next_cursor);
      setHasMore(page.has_more);
      setError(null);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setError(err.problem);
      } else {
        setError({
          type: "urn:w014:error:programs-fetch",
          title: "Failed to Fetch Programs",
          status: 0,
          detail: "An unexpected error occurred while fetching programs.",
        });
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPrograms();
  }, [fetchPrograms]);

  const handleNextPage = () => {
    if (!nextCursor || !hasMore) return;
    setCursorHistory((prev) => [...prev, nextCursor]);
    fetchPrograms(nextCursor);
  };

  const handlePrevPage = () => {
    if (cursorHistory.length === 0) return;
    const nextHistory = [...cursorHistory];
    nextHistory.pop(); // remove current
    const prevCursor = nextHistory[nextHistory.length - 1]; // get previous or undefined
    setCursorHistory(nextHistory);
    fetchPrograms(prevCursor);
  };

  const handleCreateProgram = async (dto: CreateProgramDto) => {
    setIsCreating(true);
    setCreateServerError(null);
    try {
      await apiClient.createProgram(dto, csrfToken || undefined);
      setIsCreateModalOpen(false);
      await fetchPrograms(); // Refresh list after successful creation
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setCreateServerError(err.problem.detail || err.problem.title);
      } else {
        setCreateServerError("Failed to create program.");
      }
    } finally {
      setIsCreating(false);
    }
  };

  const filteredPrograms = useMemo(() => {
    if (!filterText.trim()) return programs;
    const term = filterText.toLowerCase();
    return programs.filter(
      (p) =>
        p.name.toLowerCase().includes(term) ||
        p.slug.toLowerCase().includes(term) ||
        (p.description && p.description.toLowerCase().includes(term))
    );
  }, [programs, filterText]);

  const columns: ColumnDef<ProgramDto>[] = useMemo(
    () => [
      {
        key: "name",
        header: "Program Name",
        render: (p) => (
          <div>
            <span className="font-semibold text-primary">{p.name}</span>
            {p.description && (
              <p className="text-secondary text-xs" style={{ marginTop: "2px" }}>
                {p.description}
              </p>
            )}
          </div>
        ),
      },
      {
        key: "slug",
        header: "Slug",
        render: (p) => <code className="text-muted font-mono">{p.slug}</code>,
      },
      {
        key: "created_at",
        header: "Created",
        render: (p) => (
          <span className="text-secondary text-xs">
            {new Date(p.created_at).toLocaleDateString()}
          </span>
        ),
      },
      {
        key: "actions",
        header: "Workspaces",
        className: "text-right",
        headerClassName: "text-right",
        render: (p) => (
          <a
            href={`/programs/${encodeURIComponent(p.id)}/workspaces`}
            className="btn btn-secondary btn-sm"
            data-testid={`view-workspaces-btn-${p.id}`}
          >
            View Workspaces →
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
        { label: "Programs Portfolio", current: true },
      ]}
    />
  );

  return (
    <AppShell breadcrumbs={breadcrumbs} enableW1Nav={true}>
      <PageHeader
        title="Programs Portfolio"
        subtext="Authoritative portfolio view of organizational programs and workspace boundaries (WI-0106 / S02)."
        badge={<DataBoundaryBadge />}
        actions={
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setIsCreateModalOpen(true)}
            data-testid="create-program-btn"
          >
            + Create Program
          </button>
        }
      />

      {error && (
        <ProblemNotice
          problem={error}
          onRetry={() => fetchPrograms()}
          className="mb-4"
        />
      )}

      <div className="portfolio-content">
        <div className="portfolio-controls">
          <FilterBar
            value={filterText}
            onChange={setFilterText}
            placeholder="Filter programs by name, slug, or description..."
            label="Filter programs"
            count={filteredPrograms.length}
            totalCount={programs.length}
          />
        </div>

        <DataTable
          columns={columns}
          data={filteredPrograms}
          keyExtractor={(p) => p.id}
          caption="Organizational Programs Portfolio"
          isLoading={isLoading}
          emptyMessage={
            filterText
              ? `No programs match filter "${filterText}".`
              : "No programs found in your organization. Create your first program to begin."
          }
          testId="programs-data-table"
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
            label="PROGRAM_READ / PROGRAM_CREATE Presentation Tier"
            ariaLabel="Programs portfolio capability tier"
          />
        </div>
      </div>

      <CreateProgramModal
        isOpen={isCreateModalOpen}
        onClose={() => {
          setIsCreateModalOpen(false);
          setCreateServerError(null);
        }}
        onSubmit={handleCreateProgram}
        isLoading={isCreating}
        serverError={createServerError}
      />
    </AppShell>
  );
}
