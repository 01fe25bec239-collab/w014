import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { CursorPager } from "./CursorPager";

describe("CursorPager", () => {
  it("renders controls and handles next/prev clicks", async () => {
    const onNext = vi.fn();
    const onPrevious = vi.fn();
    const user = userEvent.setup();

    render(
      <CursorPager
        hasMore={true}
        hasPrevious={true}
        onNext={onNext}
        onPrevious={onPrevious}
      />
    );

    const prevBtn = screen.getByRole("button", { name: /previous/i });
    const nextBtn = screen.getByRole("button", { name: /next/i });

    expect(prevBtn).not.toBeDisabled();
    expect(nextBtn).not.toBeDisabled();

    await user.click(nextBtn);
    expect(onNext).toHaveBeenCalledTimes(1);

    await user.click(prevBtn);
    expect(onPrevious).toHaveBeenCalledTimes(1);
  });

  it("disables buttons appropriately", () => {
    render(
      <CursorPager
        hasMore={false}
        hasPrevious={false}
        onNext={() => {}}
        onPrevious={() => {}}
      />
    );

    const prevBtn = screen.getByRole("button", { name: /previous/i });
    const nextBtn = screen.getByRole("button", { name: /next/i });

    expect(prevBtn).toBeDisabled();
    expect(nextBtn).toBeDisabled();
  });

  it("has 0 axe accessibility violations", async () => {
    const { container } = render(
      <CursorPager
        hasMore={true}
        hasPrevious={true}
        onNext={() => {}}
        onPrevious={() => {}}
      />
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
