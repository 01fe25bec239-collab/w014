import React from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import ProgramsPage from "./page";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { SessionProvider } from "@/lib/session-context";

function renderWithSessionProvider() {
  return render(
    <SessionProvider>
      <ProgramsPage />
    </SessionProvider>
  );
}

describe("S02: Programs Portfolio Page", () => {
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
      csrf_token: "csrf_prog_test",
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders server-backed program list", async () => {
    const mockPrograms = [
      {
        id: "prog_001",
        organization_id: "org_001",
        name: "Avionics Defense Platform",
        slug: "avionics-defense",
        description: "Core defense flight control architecture",
        created_at: "2026-08-19T10:00:00Z",
        updated_at: "2026-08-19T10:00:00Z",
      },
      {
        id: "prog_002",
        organization_id: "org_001",
        name: "Satellite Telemetry",
        slug: "satellite-telemetry",
        description: null as unknown as string,
        created_at: "2026-08-19T11:00:00Z",
        updated_at: "2026-08-19T11:00:00Z",
      },
    ];

    vi.spyOn(apiClient, "listPrograms").mockResolvedValue({
      items: mockPrograms,
      has_more: false,
    });

    renderWithSessionProvider();

    expect(
      screen.getByRole("heading", { level: 1, name: "Programs Portfolio" })
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("Avionics Defense Platform")).toBeInTheDocument();
      expect(screen.getByText("Satellite Telemetry")).toBeInTheDocument();
    });

    expect(screen.getByTestId("view-workspaces-btn-prog_001")).toHaveAttribute(
      "href",
      "/programs/prog_001/workspaces"
    );
  });

  it("renders truthful empty state when 0 programs exist", async () => {
    vi.spyOn(apiClient, "listPrograms").mockResolvedValue({
      items: [],
      has_more: false,
    });

    renderWithSessionProvider();

    await waitFor(() => {
      expect(
        screen.getByText(/No programs found in your organization/i)
      ).toBeInTheDocument();
    });
  });

  it("filters program items based on FilterBar query", async () => {
    const mockPrograms = [
      {
        id: "prog_001",
        organization_id: "org_001",
        name: "Avionics Defense Platform",
        slug: "avionics-defense",
        created_at: "2026-08-19T10:00:00Z",
        updated_at: "2026-08-19T10:00:00Z",
      },
      {
        id: "prog_002",
        organization_id: "org_001",
        name: "Satellite Telemetry",
        slug: "satellite-telemetry",
        created_at: "2026-08-19T11:00:00Z",
        updated_at: "2026-08-19T11:00:00Z",
      },
    ];

    vi.spyOn(apiClient, "listPrograms").mockResolvedValue({
      items: mockPrograms,
      has_more: false,
    });

    const user = userEvent.setup();
    renderWithSessionProvider();

    await waitFor(() => {
      expect(screen.getByText("Avionics Defense Platform")).toBeInTheDocument();
    });

    const searchInput = screen.getByRole("searchbox");
    await user.type(searchInput, "satellite");

    expect(screen.queryByText("Avionics Defense Platform")).not.toBeInTheDocument();
    expect(screen.getByText("Satellite Telemetry")).toBeInTheDocument();
  });

  it("opens create modal and invokes apiClient.createProgram", async () => {
    vi.spyOn(apiClient, "listPrograms").mockResolvedValue({
      items: [],
      has_more: false,
    });

    const createSpy = vi.spyOn(apiClient, "createProgram").mockResolvedValue({
      id: "prog_new",
      organization_id: "org_001",
      name: "New Space Program",
      slug: "new-space-program",
      created_at: "2026-08-19T12:00:00Z",
      updated_at: "2026-08-19T12:00:00Z",
    });

    const user = userEvent.setup();
    renderWithSessionProvider();

    await waitFor(() => {
      expect(screen.getByTestId("create-program-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("create-program-btn"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    const nameInput = screen.getByLabelText(/program name/i);
    await user.type(nameInput, "New Space Program");

    const submitBtn = screen.getByRole("button", { name: /^create program$/i });
    await user.click(submitBtn);

    expect(createSpy).toHaveBeenCalledWith(
      {
        name: "New Space Program",
        slug: "new-space-program",
        description: undefined,
      },
      "csrf_prog_test"
    );
  });

  it("renders ProblemNotice on API error", async () => {
    vi.spyOn(apiClient, "listPrograms").mockRejectedValue(
      new ApiClientError({
        type: "urn:w014:error:forbidden",
        title: "Forbidden",
        status: 403,
        detail: "Missing PROGRAM_READ capability grant.",
        code: "FORBIDDEN",
      })
    );

    renderWithSessionProvider();

    await waitFor(() => {
      expect(screen.getByTestId("problem-notice")).toBeInTheDocument();
      expect(
        screen.getByText("Missing PROGRAM_READ capability grant.")
      ).toBeInTheDocument();
    });
  });

  it("has 0 axe accessibility violations", async () => {
    vi.spyOn(apiClient, "listPrograms").mockResolvedValue({
      items: [
        {
          id: "prog_axe",
          organization_id: "org_001",
          name: "Axe Accessible Program",
          slug: "axe-program",
          created_at: "2026-08-19T10:00:00Z",
          updated_at: "2026-08-19T10:00:00Z",
        },
      ],
      has_more: false,
    });

    const { container } = renderWithSessionProvider();
    await waitFor(() => {
      expect(screen.getByText("Axe Accessible Program")).toBeInTheDocument();
    });

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
