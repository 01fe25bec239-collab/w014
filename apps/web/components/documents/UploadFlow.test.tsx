import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { UploadFlow } from "./UploadFlow";
import { apiClient } from "@/lib/api-client";

describe("UploadFlow", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("requires file selection and mandatory attestation before allowing submission", async () => {
    render(<UploadFlow workspaceId="ws_1" />);

    const submitBtn = screen.getByTestId("submit-upload-btn");
    expect(submitBtn).toBeDisabled();

    // Attestation box is present
    const attestationCheckbox = screen.getByTestId("attestation-checkbox");
    expect(attestationCheckbox).not.toBeChecked();
  });

  it("validates file size and unsupported extensions locally", async () => {
    render(<UploadFlow workspaceId="ws_1" />);

    const fileInput = screen.getByTestId("file-input");

    // Test unsupported format (.exe)
    const badFile = new File(["malicious"], "virus.exe", { type: "application/x-msdownload" });
    fireEvent.change(fileInput, { target: { files: [badFile] } });

    expect(screen.getByTestId("file-validation-error")).toHaveTextContent(
      "Unsupported format. Only PDF (.pdf) and Word DOCX (.docx) documents are permitted."
    );

    // Test oversized file (> 100 MiB)
    const bigFile = new File([new ArrayBuffer(101 * 1024 * 1024)], "huge.pdf", { type: "application/pdf" });
    Object.defineProperty(bigFile, "size", { value: 101 * 1024 * 1024 });
    fireEvent.change(fileInput, { target: { files: [bigFile] } });

    expect(screen.getByTestId("file-validation-error")).toHaveTextContent(
      "exceeds the 100 MiB maximum limit"
    );
  });

  it("executes upload intent -> storage transfer -> finalize, presenting truthful quarantine state", async () => {
    const user = userEvent.setup();

    // Mock API client methods
    vi.spyOn(apiClient, "createDocument").mockResolvedValue({
      id: "doc_new_123",
      workspace_id: "ws_1",
      title: "Avionics Safety Plan",
      document_class: "pdf",
      status: "active",
      created_at: "2026-08-30T10:00:00Z",
      updated_at: "2026-08-30T10:00:00Z",
      row_version: 1,
    });

    vi.spyOn(apiClient, "createUploadIntent").mockResolvedValue({
      id: "intent_123",
      workspace_id: "ws_1",
      document_id: "doc_new_123",
      filename: "safety_plan.pdf",
      expected_media_type: "application/pdf",
      expected_length: 1024,
      opaque_object_key: "obj_k1",
      status: "pending",
      expires_at: "2026-08-30T10:10:00Z",
      created_at: "2026-08-30T10:00:00Z",
      presigned_put: {
        upload_url: "https://s3.example.com/put",
        method: "PUT",
        expires_at: "2026-08-30T10:10:00Z",
        headers: { "Content-Type": "application/pdf" },
      },
    });

    vi.spyOn(apiClient, "uploadFileToStorage").mockResolvedValue(undefined);

    vi.spyOn(apiClient, "finalizeUploadIntent").mockResolvedValue({
      upload_intent_id: "intent_123",
      document_id: "doc_new_123",
      document_version_id: "ver_new_456",
      version_number: 1,
      object_artifact_id: "art_789",
      quarantine_record_id: "quarantine_rec_001",
      scan_job_id: "job_scan_001",
      status: "quarantined_processing",
      trust_state: "pending",
    });

    render(<UploadFlow workspaceId="ws_1" csrfToken="csrf_test" />);

    // Enter title
    const titleInput = screen.getByTestId("new-doc-title-input");
    await user.clear(titleInput);
    await user.type(titleInput, "Avionics Safety Plan");

    // Select valid file
    const file = new File(["valid pdf content"], "safety_plan.pdf", { type: "application/pdf" });
    const fileInput = screen.getByTestId("file-input");
    fireEvent.change(fileInput, { target: { files: [file] } });

    // Check attestation
    const attestationCheckbox = screen.getByTestId("attestation-checkbox");
    await user.click(attestationCheckbox);

    // Submit
    const submitBtn = screen.getByTestId("submit-upload-btn");
    expect(submitBtn).not.toBeDisabled();
    await user.click(submitBtn);

    // Verify API calls
    expect(apiClient.createDocument).toHaveBeenCalledWith(
      "ws_1",
      { title: "Avionics Safety Plan", document_class: "pdf" },
      "csrf_test",
      expect.any(String)
    );

    expect(apiClient.createUploadIntent).toHaveBeenCalledWith(
      "ws_1",
      "doc_new_123",
      expect.objectContaining({
        filename: "safety_plan.pdf",
        media_type: "application/pdf",
      }),
      "csrf_test",
      expect.any(String)
    );

    expect(apiClient.uploadFileToStorage).toHaveBeenCalledWith(
      "https://s3.example.com/put",
      "PUT",
      { "Content-Type": "application/pdf" },
      file
    );

    expect(apiClient.finalizeUploadIntent).toHaveBeenCalledWith(
      "ws_1",
      "intent_123",
      "csrf_test",
      expect.any(String)
    );

    // Verify truthful post-finalize quarantine state (NEVER "Document Ready")
    expect(
      screen.getByRole("heading", { name: /Upload Complete — Security Checks Pending/i })
    ).toBeInTheDocument();
    expect(screen.queryByText(/Document Ready/i)).not.toBeInTheDocument();

    expect(screen.getByTestId("completed-quarantine-id")).toHaveTextContent("quarantine_rec_001");
    expect(screen.getByTestId("completed-job-id")).toHaveTextContent("job_scan_001");
    expect(screen.getByTestId("completed-trust-state")).toHaveTextContent("pending");
  });
});
