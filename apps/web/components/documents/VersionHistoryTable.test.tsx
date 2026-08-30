import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VersionHistoryTable } from "./VersionHistoryTable";
import type { DocumentVersionDto } from "@/lib/api-types";

describe("VersionHistoryTable", () => {
  const mockVersions: DocumentVersionDto[] = [
    {
      id: "ver_1",
      document_id: "doc_1",
      workspace_id: "ws_1",
      version_number: 1,
      object_artifact_id: "art_1",
      byte_size: 2048,
      sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      content_type: "application/pdf",
      original_filename: "spec_v1.pdf",
      trust_state: "trusted",
      submitted_by: "eng_1",
      created_at: "2026-08-30T10:00:00Z",
    },
    {
      id: "ver_2",
      document_id: "doc_1",
      workspace_id: "ws_1",
      version_number: 2,
      object_artifact_id: "art_2",
      byte_size: 4096,
      sha256_hash: "f4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afb",
      content_type: "application/pdf",
      original_filename: "spec_v2.pdf",
      trust_state: "pending",
      submitted_by: "eng_2",
      created_at: "2026-08-30T11:00:00Z",
    },
  ];

  it("renders loading skeleton state", () => {
    render(
      <VersionHistoryTable
        versions={[]}
        workspaceId="ws_1"
        documentId="doc_1"
        isLoading={true}
      />
    );
    expect(screen.getByTestId("version-table-loading")).toBeInTheDocument();
  });

  it("renders empty state", () => {
    render(
      <VersionHistoryTable
        versions={[]}
        workspaceId="ws_1"
        documentId="doc_1"
        isLoading={false}
      />
    );
    expect(screen.getByTestId("version-table-empty")).toBeInTheDocument();
  });

  it("authoritatively assigns Current ONLY to version matching currentVersionId", () => {
    // Note: ver_1 is older timestamp, but currentVersionId is "ver_1"
    render(
      <VersionHistoryTable
        versions={mockVersions}
        currentVersionId="ver_1"
        workspaceId="ws_1"
        documentId="doc_1"
        isLoading={false}
        canManage={true}
      />
    );

    // ver_1 is Current
    expect(screen.getByTestId("version-current-ver_1")).toBeInTheDocument();
    expect(screen.queryByTestId("version-historical-ver_1")).not.toBeInTheDocument();

    // ver_2 is Historical (even though higher ordinal / newer timestamp)
    expect(screen.getByTestId("version-historical-ver_2")).toBeInTheDocument();
    expect(screen.queryByTestId("version-current-ver_2")).not.toBeInTheDocument();
  });

  it("provides download and manage actions", async () => {
    const handleDownload = vi.fn().mockResolvedValue(undefined);
    const handleAccept = vi.fn();
    const user = userEvent.setup();

    render(
      <VersionHistoryTable
        versions={mockVersions}
        currentVersionId="ver_1"
        workspaceId="ws_1"
        documentId="doc_1"
        isLoading={false}
        canManage={true}
        onDownloadVersion={handleDownload}
        onAcceptVersion={handleAccept}
      />
    );

    const downloadBtn = screen.getByTestId("download-version-btn-ver_1");
    await user.click(downloadBtn);
    expect(handleDownload).toHaveBeenCalledWith(mockVersions[0]);

    // Accept button should only appear for non-current version
    expect(screen.queryByTestId("accept-version-btn-ver_1")).not.toBeInTheDocument();
    const acceptBtn = screen.getByTestId("accept-version-btn-ver_2");
    await user.click(acceptBtn);
    expect(handleAccept).toHaveBeenCalledWith(mockVersions[1]);
  });
});
