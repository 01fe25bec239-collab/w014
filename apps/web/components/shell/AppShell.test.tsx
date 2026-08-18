import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppShell } from "./AppShell";

describe("AppShell", () => {
  it("renders core landmarks and children", () => {
    render(
      <AppShell>
        <div data-testid="test-content">Main Content Area</div>
      </AppShell>
    );

    // Skip link
    expect(
      screen.getByRole("link", { name: "Skip to main content" })
    ).toBeInTheDocument();

    // Data boundary banner
    expect(
      screen.getByLabelText("Portfolio data boundary notification")
    ).toBeInTheDocument();

    // Landmarks
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: "Primary Navigation" })
    ).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();

    // Children
    expect(screen.getByTestId("test-content")).toBeInTheDocument();
  });

  it("manages mobile navigation toggle state", async () => {
    const user = userEvent.setup();
    const { container } = render(
      <AppShell>
        <p>Content</p>
      </AppShell>
    );

    const toggleBtn = screen.getByRole("button", {
      name: "Open navigation menu",
    });
    const nav = screen.getByRole("navigation", { name: "Primary Navigation" });

    expect(toggleBtn).toHaveAttribute("aria-expanded", "false");
    expect(nav).not.toHaveClass("nav-open");

    // Open nav
    await user.click(toggleBtn);
    expect(toggleBtn).toHaveAttribute("aria-expanded", "true");
    expect(nav).toHaveClass("nav-open");

    // Click backdrop to close
    const backdrop = container.querySelector(".nav-backdrop");
    if (backdrop) {
      await user.click(backdrop);
      expect(toggleBtn).toHaveAttribute("aria-expanded", "false");
      expect(nav).not.toHaveClass("nav-open");
    }
  });

  it("has no accessibility violations", async () => {
    const { container } = render(
      <AppShell>
        <h1>Test Page Title</h1>
        <p>Test paragraph content for accessibility check.</p>
      </AppShell>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
