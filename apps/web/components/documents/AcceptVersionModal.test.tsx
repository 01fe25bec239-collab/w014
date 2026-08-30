import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AcceptVersionModal } from "./AcceptVersionModal";
import type { DocumentVersionDto } from "@/lib/api-types";

describe("AcceptVersionModal", () => {
  const mockVersion: DocumentVersionDto = {
    id: "ver_target",
    document_id: "doc_1",
    workspace_id: "ws_1",
    version_number: 3,
    object_artifact_id: "art_3",
    byte_size: 4096,
    sha256_hash: "abcd1234efgh5678",
    content_type: "application/pdf",
    original_filename: "final_spec.pdf",
    trust_state: "trusted",
    created_at: "2026-08-30T12:00:00Z",
  };

  it("renders when open and responds to escape key", async () => {
    const handleClose = vi.fn();
    const handleConfirm = vi.fn();
    const user = userEvent.setup();

    render(
      <AcceptVersionModal
        isOpen={true}
        onClose={handleClose}
        onConfirm={handleConfirm}
        version={mockVersion}
        rowVersion={4}
      />
    );

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Promote to Current Version")).toBeInTheDocument();
    expect(screen.getByText("v3 (ver_target)")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(handleClose).toHaveBeenCalledTimes(1);
  });

  it("calls onConfirm when promote button is clicked", async () => {
    const handleConfirm = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();

    render(
      <AcceptVersionModal
        isOpen={true}
        onClose={() => {}}
        onConfirm={handleConfirm}
        version={mockVersion}
        rowVersion={4}
      />
    );

    const confirmBtn = screen.getByTestId("confirm-accept-btn");
    await user.click(confirmBtn);
    expect(handleConfirm).toHaveBeenCalledTimes(1);
  });
});
