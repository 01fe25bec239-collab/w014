import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { SkipToContent } from "./SkipToContent";

describe("SkipToContent", () => {
  it("renders with default targetId and label", () => {
    render(<SkipToContent />);
    const link = screen.getByRole("link", { name: "Skip to main content" });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "#main-content");
    expect(link).toHaveClass("skip-link");
  });

  it("supports custom targetId and label", () => {
    render(<SkipToContent targetId="custom-target" label="Skip to body" />);
    const link = screen.getByRole("link", { name: "Skip to body" });
    expect(link).toBeInTheDocument();
    expect(link).toHaveAttribute("href", "#custom-target");
  });

  it("has no accessibility violations", async () => {
    const { container } = render(<SkipToContent />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
