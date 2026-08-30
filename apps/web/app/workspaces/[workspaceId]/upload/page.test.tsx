import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import SecureUploadPage from "./page";
import { apiClient } from "@/lib/api-client";
import { SessionProvider } from "@/lib/session-context";

describe("S06 SecureUploadPage", () => {
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
  ];

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("loads workspace context and renders upload flow", async () => {
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
        <SecureUploadPage params={{ workspaceId: "ws_avionics" }} />
      </SessionProvider>
    );

    // Initial loading state
    expect(screen.getByTestId("upload-page-loading")).toBeInTheDocument();

    // Authoritative upload flow loaded
    await waitFor(() => {
      expect(screen.getByTestId("upload-flow-container")).toBeInTheDocument();
    });

    expect(screen.getByTestId("upload-dropzone")).toBeInTheDocument();
    expect(screen.getByTestId("attestation-card")).toBeInTheDocument();
  });
});
