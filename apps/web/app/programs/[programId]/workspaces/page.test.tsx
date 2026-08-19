import React from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import ProgramWorkspacesPage from "./page";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { SessionProvider } from "@/lib/session-context";

function renderWithSessionProvider(programId: string) {
  return render(
    <SessionProvider>
      <ProgramWorkspacesPage params={{ programId }} />
    </SessionProvider>
  );
}

describe("S03: Program Workspaces Page", () => {
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

  it("renders program metadata and authoritative workspace list", async () => {
    const mockProg = {
      id: "prog_001",
      organization_id: "org_001",
      name: "Avionics Core",
      slug: "avionics-core",
      description: "Flight control systems",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    const mockWorkspaces = [
      {
        id: "ws_001",
        program_id: "prog_001",
        organization_id: "org_001",
        name: "Flight Control Primary",
        slug: "flight-control-primary",
        created_at: "2026-08-19T10:00:00Z",
        updated_at: "2026-08-19T10:00:00Z",
      },
    ];

    vi.spyOn(apiClient, "getProgram").mockResolvedValue(mockProg);
    vi.spyOn(apiClient, "listWorkspaces").mockResolvedValue({
      items: mockWorkspaces,
      has_more: false,
    });

    renderWithSessionProvider("prog_001");

    await waitFor(() => {
      expect(screen.getByText("Avionics Core Workspaces")).toBeInTheDocument();
      expect(screen.getByText("Flight Control Primary")).toBeInTheDocument();
    });

    expect(screen.getByTestId("open-workspace-btn-ws_001")).toHaveAttribute(
      "href",
      "/workspaces/ws_001"
    );
  });

  it("creates a new workspace scoped to programId", async () => {
    const mockProg = {
      id: "prog_001",
      organization_id: "org_001",
      name: "Avionics Core",
      slug: "avionics-core",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    vi.spyOn(apiClient, "getProgram").mockResolvedValue(mockProg);
    vi.spyOn(apiClient, "listWorkspaces").mockResolvedValue({
      items: [],
      has_more: false,
    });

    const createWsSpy = vi.spyOn(apiClient, "createWorkspace").mockResolvedValue({
      id: "ws_new",
      program_id: "prog_001",
      organization_id: "org_001",
      name: "Telemetry Subsystem",
      slug: "telemetry-subsystem",
      created_at: "2026-08-19T11:00:00Z",
      updated_at: "2026-08-19T11:00:00Z",
    });

    const user = userEvent.setup();
    renderWithSessionProvider("prog_001");

    await waitFor(() => {
      expect(screen.getByTestId("create-workspace-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("create-workspace-btn"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    const nameInput = screen.getByLabelText(/workspace name/i);
    await user.type(nameInput, "Telemetry Subsystem");

    const submitBtn = screen.getByRole("button", { name: /^create workspace$/i });
    await user.click(submitBtn);

    expect(createWsSpy).toHaveBeenCalledWith(
      "prog_001",
      {
        name: "Telemetry Subsystem",
        slug: "telemetry-subsystem",
      },
      "csrf_ws_test"
    );
  });

  it("renders privacy-safe ProblemNotice on 404/403", async () => {
    vi.spyOn(apiClient, "getProgram").mockRejectedValue(
      new ApiClientError({
        type: "urn:w014:error:not-found",
        title: "Not Found",
        status: 404,
        detail: "Program 'prog_unknown' was not found",
        code: "NOT_FOUND",
      })
    );
    vi.spyOn(apiClient, "listWorkspaces").mockRejectedValue(
      new ApiClientError({
        type: "urn:w014:error:not-found",
        title: "Not Found",
        status: 404,
        detail: "Program 'prog_unknown' was not found",
        code: "NOT_FOUND",
      })
    );

    renderWithSessionProvider("prog_unknown");

    await waitFor(() => {
      expect(screen.getByTestId("problem-notice")).toBeInTheDocument();
      expect(screen.getByText("Not Found")).toBeInTheDocument();
    });
  });

  it("has 0 axe accessibility violations", async () => {
    vi.spyOn(apiClient, "getProgram").mockResolvedValue({
      id: "prog_axe",
      organization_id: "org_001",
      name: "Axe Accessible Program",
      slug: "axe-prog",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    });
    vi.spyOn(apiClient, "listWorkspaces").mockResolvedValue({
      items: [
        {
          id: "ws_axe",
          program_id: "prog_axe",
          organization_id: "org_001",
          name: "Axe Workspace",
          slug: "axe-ws",
          created_at: "2026-08-19T10:00:00Z",
          updated_at: "2026-08-19T10:00:00Z",
        },
      ],
      has_more: false,
    });

    const { container } = renderWithSessionProvider("prog_axe");
    await waitFor(() => {
      expect(screen.getByText("Axe Workspace")).toBeInTheDocument();
    });

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
