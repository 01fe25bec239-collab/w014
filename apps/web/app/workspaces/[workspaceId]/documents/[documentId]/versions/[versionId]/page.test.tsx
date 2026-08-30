import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import EvidenceViewerPage from "./page";
import { apiClient } from "@/lib/api-client";
import { SessionProvider } from "@/lib/session-context";

describe("S08 EvidenceViewerPage", () => {
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
    title: "Flight Software Verification Plan",
    document_class: "pdf",
    status: "active",
    current_version_id: "ver_100",
    created_at: "2026-08-30T10:00:00Z",
    updated_at: "2026-08-30T10:00:00Z",
    row_version: 1,
  };

  const mockVersion = {
    id: "ver_100",
    document_id: "doc_001",
    workspace_id: "ws_avionics",
    version_number: 2,
    object_artifact_id: "art_999",
    byte_size: 8192,
    sha256_hash: "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
    content_type: "application/pdf",
    original_filename: "verification_plan_v2.pdf",
    trust_state: "trusted",
    created_at: "2026-08-30T11:00:00Z",
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("loads document and version details into evidence workbench", async () => {
    vi.spyOn(apiClient, "getWorkspace").mockResolvedValue(mockWorkspace);
    vi.spyOn(apiClient, "getDocument").mockResolvedValue(mockDoc);
    vi.spyOn(apiClient, "getDocumentVersion").mockResolvedValue(mockVersion);
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
        <EvidenceViewerPage
          params={{
            workspaceId: "ws_avionics",
            documentId: "doc_001",
            versionId: "ver_100",
          }}
        />
      </SessionProvider>
    );

    expect(screen.getByTestId("evidence-viewer-loading")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId("evidence-workbench")).toBeInTheDocument();
    });

    expect(screen.getByText("verification_plan_v2.pdf")).toBeInTheDocument();
    expect(screen.getByTestId("document-page-view")).toBeInTheDocument();
    expect(screen.getByTestId("source-span-panel")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-download-btn")).toBeInTheDocument();
  });
});
