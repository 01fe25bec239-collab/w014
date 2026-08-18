import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { PrimaryNav } from "./PrimaryNav";

describe("PrimaryNav", () => {
  it("renders navigation landmark with aria-label", () => {
    render(<PrimaryNav />);
    const nav = screen.getByRole("navigation", { name: "Primary Navigation" });
    expect(nav).toBeInTheDocument();
    expect(nav).toHaveAttribute("id", "primary-navigation");
  });

  it("marks current active page correctly", () => {
    render(<PrimaryNav />);
    const activeLink = screen.getByRole("link", { name: /presentation shell/i });
    expect(activeLink).toHaveAttribute("aria-current", "page");
    expect(activeLink).toHaveAttribute("href", "/");
  });

  it("renders future slices as disabled non-interactive items without dead links", () => {
    render(<PrimaryNav />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(1); // Only "/"

    expect(screen.getByText(/programs & workspaces/i)).toBeInTheDocument();
    expect(screen.getByText(/verification & preflight/i)).toBeInTheDocument();
    expect(screen.getByText(/compliance & cdrl/i)).toBeInTheDocument();
    expect(screen.getByText(/evidence & audit/i)).toBeInTheDocument();
  });

  it("applies nav-open class when isOpen is true", () => {
    const { container } = render(<PrimaryNav isOpen={true} />);
    const nav = container.querySelector(".primary-nav");
    expect(nav).toHaveClass("nav-open");
  });

  it("calls onClose when backdrop is clicked", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    const { container } = render(<PrimaryNav isOpen={true} onClose={onClose} />);
    const backdrop = container.querySelector(".nav-backdrop");
    expect(backdrop).toBeInTheDocument();
    if (backdrop) {
      await user.click(backdrop);
      expect(onClose).toHaveBeenCalledTimes(1);
    }
  });

  it("calls onClose when Escape key is pressed", () => {
    const onClose = vi.fn();
    render(<PrimaryNav isOpen={true} onClose={onClose} />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("has no accessibility violations", async () => {
    const { container } = render(<PrimaryNav />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
