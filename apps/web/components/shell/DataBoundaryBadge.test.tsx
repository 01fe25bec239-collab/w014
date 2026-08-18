import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import {
  DataBoundaryBadge,
  DataBoundaryBanner,
  DATA_BOUNDARY_TEXT,
} from "./DataBoundaryBadge";

describe("DataBoundaryBadge and DataBoundaryBanner", () => {
  it("renders exact portfolio boundary text in DataBoundaryBadge", () => {
    render(<DataBoundaryBadge />);
    expect(screen.getByText(DATA_BOUNDARY_TEXT)).toBeInTheDocument();
    expect(
      screen.getByRole("status", { name: `Data Boundary: ${DATA_BOUNDARY_TEXT}` })
    ).toBeInTheDocument();
  });

  it("renders exact portfolio boundary text in DataBoundaryBanner", () => {
    render(<DataBoundaryBanner />);
    expect(screen.getByText(DATA_BOUNDARY_TEXT)).toBeInTheDocument();
    expect(
      screen.getByLabelText("Portfolio data boundary notification")
    ).toBeInTheDocument();
  });

  it("has no accessibility violations", async () => {
    const { container } = render(
      <div>
        <DataBoundaryBanner />
        <DataBoundaryBadge />
      </div>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
