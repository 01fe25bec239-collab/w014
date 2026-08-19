import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { FilterBar } from "./FilterBar";

describe("FilterBar", () => {
  it("renders search input and triggers onChange", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();

    render(
      <FilterBar
        value=""
        onChange={onChange}
        placeholder="Filter records..."
        count={5}
        totalCount={10}
      />
    );

    const input = screen.getByRole("searchbox");
    expect(input).toBeInTheDocument();
    expect(screen.getByText("Showing 5 of 10")).toBeInTheDocument();

    await user.type(input, "avionics");
    expect(onChange).toHaveBeenCalled();
  });

  it("renders clear button when value is not empty and clears on click", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();

    render(
      <FilterBar
        value="test"
        onChange={onChange}
      />
    );

    const clearBtn = screen.getByRole("button", { name: /clear filter/i });
    expect(clearBtn).toBeInTheDocument();

    await user.click(clearBtn);
    expect(onChange).toHaveBeenCalledWith("");
  });

  it("has 0 axe accessibility violations", async () => {
    const { container } = render(
      <FilterBar
        value="active"
        onChange={() => {}}
        count={3}
      />
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
