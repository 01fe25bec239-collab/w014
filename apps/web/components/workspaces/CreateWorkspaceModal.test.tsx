import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { CreateWorkspaceModal } from "./CreateWorkspaceModal";

describe("CreateWorkspaceModal", () => {
  it("renders modal dialog with accessible labels", () => {
    render(
      <CreateWorkspaceModal
        isOpen={true}
        programName="Avionics Platform"
        onClose={() => {}}
        onSubmit={async () => {}}
      />
    );

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByLabelText(/workspace name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/workspace slug/i)).toBeInTheDocument();
  });

  it("validates required fields and calls onSubmit", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();

    render(
      <CreateWorkspaceModal
        isOpen={true}
        onClose={() => {}}
        onSubmit={onSubmit}
      />
    );

    const nameInput = screen.getByLabelText(/workspace name/i);
    const slugInput = screen.getByLabelText(/workspace slug/i);
    const submitBtn = screen.getByRole("button", { name: /^create workspace$/i });

    await user.type(nameInput, "Core Telemetry");
    expect(slugInput).toHaveValue("core-telemetry");

    await user.click(submitBtn);
    expect(onSubmit).toHaveBeenCalledWith({
      name: "Core Telemetry",
      slug: "core-telemetry",
    });
  });

  it("has 0 axe accessibility violations", async () => {
    const { container } = render(
      <CreateWorkspaceModal
        isOpen={true}
        onClose={() => {}}
        onSubmit={async () => {}}
      />
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
