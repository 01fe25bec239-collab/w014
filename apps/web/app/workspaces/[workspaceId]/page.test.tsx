import React from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { axe } from "vitest-axe";
import WorkspaceShellPage from "./page";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { SessionProvider } from "@/lib/session-context";

function renderWithSessionProvider(workspaceId: string) {
  return render(
    <SessionProvider>
      <WorkspaceShellPage params={{ workspaceId }} />
    </SessionProvider>
  );
}

describe("S04: Workspace Shell Page", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiClient, "getSession").mockResolvedValue({
      session_id: "sess_1",
      principal_id: "test@defense.example.com",
      status: "active",
      created_at: "2026-08-19T10:00:00Z",
      last_seen_at: "2026-08-19T10:05:00Z",
      idle_expires_at: "2026-08-19T11:00:00Z",
      absolute_expires_at: "2026-08-19T18:00:00Z",
      rotation_counter: 1,
      csrf_token: "csrf_ws_test",
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders authoritative workspace metadata from GET /api/v1/workspaces/{workspace_id}", async () => {
    const mockWorkspace = {
      id: "ws-alpha-1234",
      program_id: "prog-alpha",
      organization_id: "org-001",
      name: "Flight Control Primary",
      slug: "flight-control-primary",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    const getWsSpy = vi
      .spyOn(apiClient, "getWorkspace")
      .mockResolvedValue(mockWorkspace);

    renderWithSessionProvider("ws-alpha-1234");

    await waitFor(() => {
      expect(screen.getByTestId("workspace-shell-content")).toBeInTheDocument();
    });

    expect(getWsSpy).toHaveBeenCalledWith("ws-alpha-1234");
    expect(screen.getByTestId("ws-meta-name")).toHaveTextContent(
      "Flight Control Primary"
    );
    expect(screen.getByTestId("ws-meta-slug")).toHaveTextContent(
      "flight-control-primary"
    );
    expect(screen.getByTestId("ws-meta-id")).toHaveTextContent("ws-alpha-1234");
    expect(screen.getByTestId("ws-meta-program-id")).toHaveTextContent(
      "prog-alpha"
    );
  });

  it("HARD RULE: Never calls E11 / source-state endpoint", async () => {
    const mockWorkspace = {
      id: "ws-hard-check",
      program_id: "prog-1",
      organization_id: "org-1",
      name: "E11 Verification",
      slug: "e11-check",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    const fetchSpy = vi.spyOn(global, "fetch");
    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue(mockWorkspace);

    renderWithSessionProvider("ws-hard-check");

    await waitFor(() => {
      expect(screen.getByTestId("workspace-shell-content")).toBeInTheDocument();
    });

    // Verify no fetch call contained 'source-state'
    for (const call of fetchSpy.mock.calls) {
      const url = String(call[0]);
      expect(url).not.toContain("source-state");
    }
  });

  it("renders truthful deferred/prerequisite presentation for unarrived waves (W2, W3, W4)", async () => {
    const mockWorkspace = {
      id: "ws-deferred-check",
      program_id: "prog-1",
      organization_id: "org-1",
      name: "Deferred Lineage Workspace",
      slug: "deferred-lineage",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue(mockWorkspace);

    renderWithSessionProvider("ws-deferred-check");

    await waitFor(() => {
      expect(screen.getByTestId("deferred-w2-panel")).toBeInTheDocument();
      expect(screen.getByTestId("deferred-w3-panel")).toBeInTheDocument();
      expect(screen.getByTestId("deferred-w4-panel")).toBeInTheDocument();
    });

    // Verify NO fabricated status
    expect(screen.queryByText(/^READY$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^BLOCKED$/i)).not.toBeInTheDocument();
  });

  it("CROSS-WORKSPACE PRIVACY NEGATIVE TEST: Workspace A authoritative state never flashes in Workspace B", async () => {
    const workspaceA = {
      id: "ws-alpha-secret",
      program_id: "prog-alpha",
      organization_id: "org-001",
      name: "Secret Missile Guidance System",
      slug: "secret-missile-guidance",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    const workspaceB = {
      id: "ws-beta-public",
      program_id: "prog-beta",
      organization_id: "org-001",
      name: "Civilian Weather Radar",
      slug: "civilian-weather-radar",
      created_at: "2026-08-19T11:00:00Z",
      updated_at: "2026-08-19T11:00:00Z",
    };

    const getWsSpy = vi
      .spyOn(apiClient, "getWorkspace")
      .mockImplementation(async (id) => {
        if (id === "ws-alpha-secret") return workspaceA;
        if (id === "ws-beta-public") return workspaceB;
        throw new ApiClientError({
          type: "urn:w014:error:not-found",
          title: "Not Found",
          status: 404,
        });
      });

    // 1. Render Workspace A
    const { rerender } = render(
      <SessionProvider>
        <WorkspaceShellPage params={{ workspaceId: "ws-alpha-secret" }} />
      </SessionProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId("ws-meta-name")).toHaveTextContent(
        "Secret Missile Guidance System"
      );
    });

    expect(screen.getByTestId("ws-meta-slug")).toHaveTextContent(
      "secret-missile-guidance"
    );

    // 2. Transition route to Workspace B
    rerender(
      <SessionProvider>
        <WorkspaceShellPage params={{ workspaceId: "ws-beta-public" }} />
      </SessionProvider>
    );

    // Verify Workspace A data is purged immediately and replaced with Workspace B
    await waitFor(() => {
      expect(screen.getByTestId("ws-meta-name")).toHaveTextContent(
        "Civilian Weather Radar"
      );
    });

    // Workspace A name/slug MUST NOT be in the document
    expect(
      screen.queryByText("secret-missile-guidance")
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("ws-meta-slug")).toHaveTextContent(
      "civilian-weather-radar"
    );

    expect(getWsSpy).toHaveBeenCalledWith("ws-alpha-secret");
    expect(getWsSpy).toHaveBeenCalledWith("ws-beta-public");
  });

  it("handles privacy-safe 404/403 ProblemNotice on missing or forbidden workspace", async () => {
    vi.spyOn(apiClient, "getWorkspace").mockRejectedValue(
      new ApiClientError({
        type: "urn:w014:error:not-found",
        title: "Not Found",
        status: 404,
        detail: "Workspace 'ws-unknown' was not found",
        code: "NOT_FOUND",
      })
    );

    renderWithSessionProvider("ws-unknown");

    await waitFor(() => {
      expect(screen.getByTestId("problem-notice")).toBeInTheDocument();
      expect(
        screen.getByText("Workspace 'ws-unknown' was not found")
      ).toBeInTheDocument();
    });

    expect(
      screen.queryByTestId("workspace-shell-content")
    ).not.toBeInTheDocument();
  });

  it("has 0 axe accessibility violations", async () => {
    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue({
      id: "ws-axe",
      program_id: "prog-axe",
      organization_id: "org-001",
      name: "Accessible Workspace Shell",
      slug: "accessible-workspace",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    });

    const { container } = renderWithSessionProvider("ws-axe");
    await waitFor(() => {
      expect(screen.getByTestId("ws-meta-name")).toHaveTextContent(
        "Accessible Workspace Shell"
      );
    });

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
