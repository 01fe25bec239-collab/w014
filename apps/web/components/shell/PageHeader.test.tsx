import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { PageHeader } from "./PageHeader";

describe("PageHeader", () => {
  it("renders h1 heading and subtext", () => {
    render(
      <PageHeader
        title="Custom Page Title"
        subtext="Detailed description of the page purpose."
      />
    );
    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading).toHaveTextContent("Custom Page Title");
    expect(
      screen.getByText("Detailed description of the page purpose.")
    ).toBeInTheDocument();
  });

  it("renders optional badge and action slots", () => {
    render(
      <PageHeader
        title="Page with Slots"
        badge={<span data-testid="test-badge">Badge</span>}
        actions={<button type="button">Action</button>}
      />
    );
    expect(screen.getByTestId("test-badge")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Action" })).toBeInTheDocument();
  });

  it("has no accessibility violations", async () => {
    const { container } = render(
      <main>
        <PageHeader
          title="Accessible Page Title"
          subtext="Accessible subtext"
          badge={<span>Badge</span>}
        />
      </main>
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
