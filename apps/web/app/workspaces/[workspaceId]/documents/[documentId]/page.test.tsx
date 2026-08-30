import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import DocumentDetailPage from "./page";
import { apiClient } from "@/lib/api-client";
import { SessionProvider } from "@/lib/session-context";

describe("S07 DocumentDetailPage", () => {
  const mockWorkspace = {
    id: "ws_avionics",
    program_id: "prog_flight",
    organization_id: "org_defense",
    name: "Avionics Core Workspace",
    slug: "avionics-core",
    created_at: "2026-08-30T10:00:00Z",
    updated_at: "2026-08-30T10:00:00Z",
  };

  const mockDoc = {
    id: "doc_001",
    workspace_id: "ws_avionics",
    title: "Flight Control Software Interface",
    document_class: "pdf",
    status: "active",
    current_version_id: "ver_1",
    created_at: "2026-08-30T10:00:00Z",
    updated_at: "2026-08-30T10:00:00Z",
    row_version: 3,
  };

  const mockVersions = [
    {
      id: "ver_1",
      document_id: "doc_001",
      workspace_id: "ws_avionics",
      version_number: 1,
      object_artifact_id: "art_1",
      byte_size: 1024,
      sha256_hash: "hash_ver_1",
      content_type: "application/pdf",
      original_filename: "spec_v1.pdf",
      trust_state: "trusted",
      created_at: "2026-08-30T10:00:00Z",
    },
    {
      id: "ver_2",
      document_id: "doc_001",
      workspace_id: "ws_avionics",
      version_number: 2,
      object_artifact_id: "art_2",
      byte_size: 2048,
      sha256_hash: "hash_ver_2",
      content_type: "application/pdf",
      original_filename: "spec_v2.pdf",
      trust_state: "trusted",
      created_at: "2026-08-30T11:00:00Z",
    },
  ];

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders document summary and version history with authoritative Current marker", async () => {
    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue(mockWorkspace);
    vi.spyOn(apiClient, "getDocument").mockResolvedValue(mockDoc);
    vi.spyOn(apiClient, "listDocumentVersions").mockResolvedValue({
      items: mockVersions,
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
        <DocumentDetailPage params={{ workspaceId: "ws_avionics", documentId: "doc_001" }} />
      </SessionProvider>
    );

    // Initial loading
    expect(screen.getByTestId("document-detail-loading")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId("detail-doc-title")).toHaveTextContent("Flight Control Software Interface");
    });

    expect(screen.getByTestId("detail-doc-row-version")).toHaveTextContent("3");
    expect(screen.getByTestId("version-current-ver_1")).toBeInTheDocument();
    expect(screen.getByTestId("version-historical-ver_2")).toBeInTheDocument();
  });

  it("handles accept version flow with If-Match precondition", async () => {
    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue(mockWorkspace);
    vi.spyOn(apiClient, "getDocument").mockResolvedValue(mockDoc);
    vi.spyOn(apiClient, "listDocumentVersions").mockResolvedValue({
      items: mockVersions,
      has_more: false,
    });
    vi.spyOn(apiClient, "acceptVersion").mockResolvedValue({
      ...mockDoc,
      current_version_id: "ver_2",
      row_version: 4,
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
      csrf_token: "csrf_accept",
    });

    const user = userEvent.setup();

    render(
      <SessionProvider>
        <DocumentDetailPage params={{ workspaceId: "ws_avionics", documentId: "doc_001" }} />
      </SessionProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId("accept-version-btn-ver_2")).toBeInTheDocument();
    });

    // Click "Set as Current" for ver_2
    await user.click(screen.getByTestId("accept-version-btn-ver_2"));

    // Modal opens
    expect(screen.getByTestId("accept-version-modal")).toBeInTheDocument();
    expect(screen.getByText(/If-Match: "3"/i)).toBeInTheDocument();

    // Confirm promotion
    await user.click(screen.getByTestId("confirm-accept-btn"));

    expect(apiClient.acceptVersion).toHaveBeenCalledWith(
      "ws_avionics",
      "ver_2",
      3,
      "csrf_accept",
      expect.any(String)
    );
  });
});
