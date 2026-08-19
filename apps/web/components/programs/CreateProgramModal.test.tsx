import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { CreateProgramModal } from "./CreateProgramModal";

describe("CreateProgramModal", () => {
  it("renders modal dialog with accessible labels", () => {
    render(
      <CreateProgramModal
        isOpen={true}
        onClose={() => {}}
        onSubmit={async () => {}}
      />
    );

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByLabelText(/program name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/program slug/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/description/i)).toBeInTheDocument();
  });

  it("validates required fields and auto-slugifies name", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();

    render(
      <CreateProgramModal
        isOpen={true}
        onClose={() => {}}
        onSubmit={onSubmit}
      />
    );

    const nameInput = screen.getByLabelText(/program name/i);
    const slugInput = screen.getByLabelText(/program slug/i);
    const submitBtn = screen.getByRole("button", { name: /^create program$/i });

    // Type program name
    await user.type(nameInput, "NextGen Spacecraft");
    expect(slugInput).toHaveValue("nextgen-spacecraft");

    await user.click(submitBtn);
    expect(onSubmit).toHaveBeenCalledWith({
      name: "NextGen Spacecraft",
      slug: "nextgen-spacecraft",
      description: undefined,
    });
  });

  it("displays validation error when required fields are empty", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();

    render(
      <CreateProgramModal
        isOpen={true}
        onClose={() => {}}
        onSubmit={onSubmit}
      />
    );

    const submitBtn = screen.getByRole("button", { name: /^create program$/i });
    await user.click(submitBtn);

    expect(screen.getByText("Program name is required.")).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("handles server errors and close button", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();

    render(
      <CreateProgramModal
        isOpen={true}
        onClose={onClose}
        onSubmit={async () => {}}
        serverError="Program slug already exists."
      />
    );

    expect(screen.getByText("Program slug already exists.")).toBeInTheDocument();

    const closeBtn = screen.getByRole("button", { name: /close dialog/i });
    await user.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("has 0 axe accessibility violations", async () => {
    const { container } = render(
      <CreateProgramModal
        isOpen={true}
        onClose={() => {}}
        onSubmit={async () => {}}
      />
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
