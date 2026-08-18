import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import Page from "./page";
import { DATA_BOUNDARY_TEXT } from "@/components/shell";

describe("W0 Presentation Shell Integration (WI-0006 Contract)", () => {
  // T-UX-WI0006-001 — shell renders
  it("T-UX-WI0006-001: renders the primary shell and landing page successfully", () => {
    const { container } = render(<Page />);
    expect(container).toBeInTheDocument();
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
  });

  // T-UX-WI0006-002 — semantic structure
  it("T-UX-WI0006-002: contains expected page heading and primary landmarks", () => {
    render(<Page />);

    // Single H1 for the page
    const headings = screen.getAllByRole("heading", { level: 1 });
    expect(headings).toHaveLength(1);
    expect(headings[0]).toHaveTextContent(
      "W-014 Systems Verification & Compliance"
    );

    // Primary landmarks
    expect(screen.getByRole("banner")).toBeInTheDocument();
    expect(
      screen.getByRole("navigation", { name: /primary navigation/i })
    ).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
  });

  // T-UX-WI0006-003 — data boundary
  it("T-UX-WI0006-003: visibly presents the public/synthetic/sanitized non-CUI boundary", () => {
    render(<Page />);

    // Boundary text must be present in the document
    const boundaryElements = screen.getAllByText(DATA_BOUNDARY_TEXT);
    expect(boundaryElements.length).toBeGreaterThan(0);

    // Verify non-CUI boundary text content
    const matchedElements = screen.getAllByText(
      /public \/ synthetic \/ sanitized non-CUI only/i
    );
    expect(matchedElements.length).toBeGreaterThan(0);
  });

  // T-UX-WI0006-004 — environment presentation
  it("T-UX-WI0006-004: safely renders the presentation environment and marks non-production", () => {
    render(<Page />);

    const envBadges = screen.getAllByRole("status", {
      name: /environment/i,
    });
    expect(envBadges.length).toBeGreaterThan(0);

    // Verify environment does not visually masquerade as production in default test env
    expect(
      screen.getAllByText(/\[NON-PROD\]/i).length
    ).toBeGreaterThan(0);
  });

  // T-UX-WI0006-005 — navigation accessibility
  it("T-UX-WI0006-005: operates navigation toggles semantically and exposes no dead workflow links", async () => {
    const user = userEvent.setup();
    render(<Page />);

    // Toggle button has valid ARIA attributes
    const toggleButton = screen.getByRole("button", {
      name: /navigation menu/i,
    });
    expect(toggleButton).toHaveAttribute("aria-expanded", "false");
    expect(toggleButton).toHaveAttribute("aria-controls", "primary-navigation");

    // Click toggle to open navigation
    await user.click(toggleButton);
    expect(toggleButton).toHaveAttribute("aria-expanded", "true");

    // Check navigation items: no broken/dead links to unbuilt routes
    const links = screen.getAllByRole("link");
    for (const link of links) {
      const href = link.getAttribute("href");
      expect(href).toBeDefined();
      // In W0, links should only point to "/" or hash anchors (like "#main-content")
      expect(href === "/" || href?.startsWith("#")).toBe(true);
    }
  });

  // T-UX-WI0006-006 — baseline accessibility smoke
  it("T-UX-WI0006-006: passes axe-compatible automated accessibility smoke test with 0 violations", async () => {
    const { container } = render(<Page />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
