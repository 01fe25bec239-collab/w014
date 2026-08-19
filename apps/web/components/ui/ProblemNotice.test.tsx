import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { ProblemNotice } from "./ProblemNotice";
import type { ProblemDetails } from "@/lib/api-types";

describe("ProblemNotice", () => {
  it("renders nothing when problem is null or undefined", () => {
    const { container } = render(<ProblemNotice problem={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders RFC 9457 problem details attributes", () => {
    const problem: ProblemDetails = {
      type: "urn:w014:error:bad-request",
      title: "Bad Request",
      status: 400,
      detail: "The submitted slug contains invalid characters.",
      instance: "/api/v1/programs",
      code: "BAD_REQUEST",
      correlation_id: "corr-xyz-987",
    };

    render(<ProblemNotice problem={problem} />);

    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.getByText("Bad Request")).toBeInTheDocument();
    expect(screen.getByText("HTTP 400")).toBeInTheDocument();
    expect(screen.getByText("BAD_REQUEST")).toBeInTheDocument();
    expect(screen.getByText(/The submitted slug contains invalid characters/)).toBeInTheDocument();
    expect(screen.getByText("/api/v1/programs")).toBeInTheDocument();
    expect(screen.getByText("corr-xyz-987")).toBeInTheDocument();
  });

  it("renders and triggers onRetry callback when clicked", async () => {
    const onRetry = vi.fn();
    const problem: ProblemDetails = {
      type: "urn:w014:error:network-error",
      title: "Network Connection Error",
      status: 0,
      detail: "Failed to connect to server.",
    };

    const user = userEvent.setup();
    render(<ProblemNotice problem={problem} onRetry={onRetry} />);

    const retryBtn = screen.getByRole("button", { name: /retry/i });
    expect(retryBtn).toBeInTheDocument();

    await user.click(retryBtn);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("has 0 axe accessibility violations", async () => {
    const problem: ProblemDetails = {
      type: "urn:w014:error:forbidden",
      title: "Forbidden",
      status: 403,
      detail: "Insufficient capability grants for this operation.",
      instance: "/api/v1/programs",
      code: "FORBIDDEN",
      correlation_id: "corr-axe-test",
    };

    const { container } = render(<ProblemNotice problem={problem} onRetry={() => {}} />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
