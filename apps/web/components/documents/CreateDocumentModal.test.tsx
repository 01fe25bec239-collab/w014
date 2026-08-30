import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CreateDocumentModal } from "./CreateDocumentModal";

describe("CreateDocumentModal", () => {
  it("renders when open and handles escape key to close", async () => {
    const handleClose = vi.fn();
    const handleSubmit = vi.fn();
    const user = userEvent.setup();

    render(
      <CreateDocumentModal
        isOpen={true}
        onClose={handleClose}
        onSubmit={handleSubmit}
      />
    );

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Create Logical Document")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(handleClose).toHaveBeenCalledTimes(1);
  });

  it("validates required title field", async () => {
    const handleSubmit = vi.fn();
    const user = userEvent.setup();

    render(
      <CreateDocumentModal
        isOpen={true}
        onClose={() => {}}
        onSubmit={handleSubmit}
      />
    );

    const submitBtn = screen.getByTestId("submit-document-btn");
    await user.click(submitBtn);

    expect(screen.getByText("Document title is required.")).toBeInTheDocument();
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it("submits valid form data", async () => {
    const handleSubmit = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();

    render(
      <CreateDocumentModal
        isOpen={true}
        onClose={() => {}}
        onSubmit={handleSubmit}
      />
    );

    const titleInput = screen.getByTestId("document-title-input");
    const classSelect = screen.getByTestId("document-class-select");
    const submitBtn = screen.getByTestId("submit-document-btn");

    await user.type(titleInput, "Avionics Safety Manual");
    await user.selectOptions(classSelect, "docx");
    await user.click(submitBtn);

    expect(handleSubmit).toHaveBeenCalledWith({
      title: "Avionics Safety Manual",
      document_class: "docx",
    });
  });
});
