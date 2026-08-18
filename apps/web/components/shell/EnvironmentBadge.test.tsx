import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { EnvironmentBadge } from "./EnvironmentBadge";

describe("EnvironmentBadge", () => {
  it("renders with default environment", () => {
    render(<EnvironmentBadge />);
    const badge = screen.getByRole("status");
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveAttribute("data-env");
  });

  it("renders non-production badges with explicit non-prod indicator", () => {
    render(<EnvironmentBadge env="dev" />);
    const badge = screen.getByRole("status", { name: "Environment: DEV [NON-PROD]" });
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveAttribute("data-env", "dev");
    expect(screen.getByText(/DEV/)).toBeInTheDocument();
    expect(screen.getByText(/\[NON-PROD\]/)).toBeInTheDocument();
  });

  it("renders public-demo environment badge properly", () => {
    render(<EnvironmentBadge env="public-demo" />);
    const badge = screen.getByRole("status", {
      name: "Environment: PUBLIC-DEMO [NON-PROD]",
    });
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveAttribute("data-env", "public-demo");
  });

  it("renders production environment badge without non-prod tag", () => {
    render(<EnvironmentBadge env="production" />);
    const badge = screen.getByRole("status", { name: "Environment: PRODUCTION" });
    expect(badge).toBeInTheDocument();
    expect(badge).toHaveAttribute("data-env", "production");
    expect(screen.queryByText(/\[NON-PROD\]/)).not.toBeInTheDocument();
  });

  it("has no accessibility violations across all environment states", async () => {
    const { container } = render(
      <div>
        <EnvironmentBadge env="local" />
        <EnvironmentBadge env="dev" />
        <EnvironmentBadge env="demo" />
        <EnvironmentBadge env="staging" />
        <EnvironmentBadge env="public-demo" />
        <EnvironmentBadge env="production" />
      </div>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
