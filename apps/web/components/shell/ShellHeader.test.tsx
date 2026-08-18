import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { ShellHeader } from "./ShellHeader";

describe("ShellHeader", () => {
  it("renders banner landmark with brand identity and slots", () => {
    render(<ShellHeader />);
    const header = screen.getByRole("banner");
    expect(header).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "W-014 Home" })).toBeInTheDocument();
    expect(screen.getAllByText("W-014").length).toBeGreaterThan(0);
    expect(screen.getByText("VS0")).toBeInTheDocument();
  });

  it("handles navigation toggle click", async () => {
    const onToggleNav = vi.fn();
    const user = userEvent.setup();
    render(<ShellHeader isNavOpen={false} onToggleNav={onToggleNav} />);

    const toggleBtn = screen.getByRole("button", {
      name: "Open navigation menu",
    });
    expect(toggleBtn).toHaveAttribute("aria-expanded", "false");

    await user.click(toggleBtn);
    expect(onToggleNav).toHaveBeenCalledTimes(1);
  });

  it("renders with isNavOpen=true", () => {
    render(<ShellHeader isNavOpen={true} />);
    const toggleBtn = screen.getByRole("button", {
      name: "Close navigation menu",
    });
    expect(toggleBtn).toHaveAttribute("aria-expanded", "true");
  });

  it("supports custom slots", () => {
    render(
      <ShellHeader
        breadcrumbs={<div data-testid="custom-breadcrumbs">Crumbs</div>}
        workspaceSlot={<div data-testid="custom-workspace">Workspace</div>}
        sessionSlot={<div data-testid="custom-session">Session</div>}
      />
    );
    expect(screen.getByTestId("custom-breadcrumbs")).toBeInTheDocument();
    expect(screen.getByTestId("custom-workspace")).toBeInTheDocument();
    expect(screen.getByTestId("custom-session")).toBeInTheDocument();
  });

  it("has no accessibility violations", async () => {
    const { container } = render(<ShellHeader />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
