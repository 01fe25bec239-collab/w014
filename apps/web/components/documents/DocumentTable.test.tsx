import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DocumentTable } from "./DocumentTable";
import type { DocumentDto } from "@/lib/api-types";

describe("DocumentTable", () => {
  const mockDocs: DocumentDto[] = [
    {
      id: "doc_111",
      workspace_id: "ws_1",
      title: "Avionics System Architecture",
      document_class: "pdf",
      status: "active",
      current_version_id: "ver_aaa_12345",
      created_at: "2026-08-30T10:00:00Z",
      updated_at: "2026-08-30T10:00:00Z",
      row_version: 1,
    },
    {
      id: "doc_222",
      workspace_id: "ws_1",
      title: "Draft ICD Spec",
      document_class: "docx",
      status: "pending",
      current_version_id: undefined,
      created_at: "2026-08-30T11:00:00Z",
      updated_at: "2026-08-30T11:00:00Z",
      row_version: 1,
    },
  ];

  it("renders loading skeleton state", () => {
    render(<DocumentTable documents={[]} workspaceId="ws_1" isLoading={true} />);
    expect(screen.getByTestId("document-table-loading")).toBeInTheDocument();
  });

  it("renders empty state with upload action", () => {
    render(<DocumentTable documents={[]} workspaceId="ws_1" isLoading={false} />);
    expect(screen.getByTestId("document-table-empty")).toBeInTheDocument();
    expect(screen.getByText("No Documents Found")).toBeInTheDocument();
    expect(screen.getByTestId("empty-upload-doc-btn")).toHaveAttribute(
      "href",
      "/workspaces/ws_1/upload"
    );
  });

  it("renders document rows with class badges and authoritative current version", () => {
    render(<DocumentTable documents={mockDocs} workspaceId="ws_1" isLoading={false} />);

    expect(screen.getByTestId("doc-row-doc_111")).toBeInTheDocument();
    expect(screen.getByText("Avionics System Architecture")).toBeInTheDocument();
    expect(screen.getByTestId("doc-class-doc_111")).toHaveTextContent("PDF");
    expect(screen.getByTestId("doc-current-version-doc_111")).toHaveTextContent("Current: ver_aaa_");

    expect(screen.getByTestId("doc-row-doc_222")).toBeInTheDocument();
    expect(screen.getByText("Draft ICD Spec")).toBeInTheDocument();
    expect(screen.getByTestId("doc-class-doc_222")).toHaveTextContent("DOCX");
    expect(screen.getByTestId("doc-unversioned-doc_222")).toHaveTextContent("Unversioned");
  });
});
