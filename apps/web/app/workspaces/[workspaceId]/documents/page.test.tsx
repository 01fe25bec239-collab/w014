import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import DocumentLibraryPage from "./page";
import { apiClient } from "@/lib/api-client";
import { SessionProvider } from "@/lib/session-context";

describe("S05 DocumentLibraryPage", () => {
  const mockWorkspace = {
    id: "ws_avionics",
    program_id: "prog_flight",
    organization_id: "org_defense",
    name: "Avionics Core Workspace",
    slug: "avionics-core",
    created_at: "2026-08-30T10:00:00Z",
    updated_at: "2026-08-30T10:00:00Z",
  };

  const mockDocuments = [
    {
      id: "doc_001",
      workspace_id: "ws_avionics",
      title: "Telemetry Flight Interface Spec",
      document_class: "pdf",
      status: "active",
      current_version_id: "ver_111",
      created_at: "2026-08-30T10:00:00Z",
      updated_at: "2026-08-30T10:00:00Z",
      row_version: 1,
    },
    {
      id: "doc_002",
      workspace_id: "ws_avionics",
      title: "Guidance Bus ICD",
      document_class: "docx",
      status: "active",
      current_version_id: undefined,
      created_at: "2026-08-30T11:00:00Z",
      updated_at: "2026-08-30T11:00:00Z",
      row_version: 1,
    },
  ];

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders loading state then authoritative document library list", async () => {
    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue(mockWorkspace);
    vi.spyOn(apiClient, "listDocuments").mockResolvedValue({
      items: mockDocuments,
      has_more: false,
    });
    vi.spyOn(apiClient, "getSession").mockResolvedValue({
      session_id: "s1",
      principal_id: "p1",
      status: "active",
      created_at: "2026-08-30T10:00:00Z",
      last_seen_at: "2026-08-30T10:00:00Z",
      idle_expires_at: "2026-08-30T12:00:00Z",
      absolute_expires_at: "2026-08-30T18:00:00Z",
      rotation_counter: 1,
    });

    render(
      <SessionProvider>
        <DocumentLibraryPage params={{ workspaceId: "ws_avionics" }} />
      </SessionProvider>
    );

    // Initial loading skeleton
    expect(screen.getByTestId("document-table-loading")).toBeInTheDocument();

    // Authoritative content loaded
    await waitFor(() => {
      expect(screen.getByText("Telemetry Flight Interface Spec")).toBeInTheDocument();
    });

    expect(screen.getByText("Guidance Bus ICD")).toBeInTheDocument();
    expect(screen.getByTestId("doc-class-doc_001")).toHaveTextContent("PDF");
    expect(screen.getByTestId("doc-class-doc_002")).toHaveTextContent("DOCX");
    expect(screen.getByTestId("doc-current-version-doc_001")).toHaveTextContent("Current: ver_111");
    expect(screen.getByTestId("doc-unversioned-doc_002")).toHaveTextContent("Unversioned");
  });

  it("filters documents locally by title and class", async () => {
    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue(mockWorkspace);
    vi.spyOn(apiClient, "listDocuments").mockResolvedValue({
      items: mockDocuments,
      has_more: false,
    });
    vi.spyOn(apiClient, "getSession").mockResolvedValue({
      session_id: "s1",
      principal_id: "p1",
      status: "active",
      created_at: "2026-08-30T10:00:00Z",
      last_seen_at: "2026-08-30T10:00:00Z",
      idle_expires_at: "2026-08-30T12:00:00Z",
      absolute_expires_at: "2026-08-30T18:00:00Z",
      rotation_counter: 1,
    });

    const user = userEvent.setup();

    render(
      <SessionProvider>
        <DocumentLibraryPage params={{ workspaceId: "ws_avionics" }} />
      </SessionProvider>
    );

    await waitFor(() => {
      expect(screen.getByText("Telemetry Flight Interface Spec")).toBeInTheDocument();
    });

    // Filter by text
    const searchInput = screen.getByTestId("filter-input");
    await user.type(searchInput, "Telemetry");

    expect(screen.getByText("Telemetry Flight Interface Spec")).toBeInTheDocument();
    expect(screen.queryByText("Guidance Bus ICD")).not.toBeInTheDocument();

    // Filter by class
    await user.clear(searchInput);
    const classSelect = screen.getByTestId("class-filter-select");
    await user.selectOptions(classSelect, "docx");

    expect(screen.queryByText("Telemetry Flight Interface Spec")).not.toBeInTheDocument();
    expect(screen.getByText("Guidance Bus ICD")).toBeInTheDocument();
  });

  it("opens create document modal and submits new document", async () => {
    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue(mockWorkspace);
    vi.spyOn(apiClient, "listDocuments").mockResolvedValue({
      items: mockDocuments,
      has_more: false,
    });
    vi.spyOn(apiClient, "createDocument").mockResolvedValue({
      id: "doc_new_999",
      workspace_id: "ws_avionics",
      title: "New Subsystem Doc",
      document_class: "pdf",
      status: "active",
      created_at: "2026-08-30T12:00:00Z",
      updated_at: "2026-08-30T12:00:00Z",
      row_version: 1,
    });
    vi.spyOn(apiClient, "getSession").mockResolvedValue({
      session_id: "s1",
      principal_id: "p1",
      status: "active",
      created_at: "2026-08-30T10:00:00Z",
      last_seen_at: "2026-08-30T10:00:00Z",
      idle_expires_at: "2026-08-30T12:00:00Z",
      absolute_expires_at: "2026-08-30T18:00:00Z",
      rotation_counter: 1,
    });

    const user = userEvent.setup();

    render(
      <SessionProvider>
        <DocumentLibraryPage params={{ workspaceId: "ws_avionics" }} />
      </SessionProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId("create-doc-modal-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("create-doc-modal-btn"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    const titleInput = screen.getByTestId("document-title-input");
    await user.type(titleInput, "New Subsystem Doc");

    const submitBtn = screen.getByTestId("submit-document-btn");
    await user.click(submitBtn);

    expect(apiClient.createDocument).toHaveBeenCalledWith(
      "ws_avionics",
      { title: "New Subsystem Doc", document_class: "pdf" },
      undefined,
      expect.any(String)
    );
  });
});
