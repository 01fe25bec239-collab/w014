import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DocumentPageView } from "./DocumentPageView";

describe("DocumentPageView", () => {
  it("renders page text and handles page navigation", async () => {
    const handlePageChange = vi.fn();
    const user = userEvent.setup();

    render(
      <DocumentPageView
        currentPage={1}
        totalPages={5}
        pageText="System telemetry data section."
        onPageChange={handlePageChange}
      />
    );

    expect(screen.getByTestId("page-text-content")).toHaveTextContent(
      "System telemetry data section."
    );
    expect(screen.getByTestId("prev-page-btn")).toBeDisabled();
    expect(screen.getByTestId("next-page-btn")).not.toBeDisabled();

    await user.click(screen.getByTestId("next-page-btn"));
    expect(handlePageChange).toHaveBeenCalledWith(2);
  });

  it("renders highlighted span range safely as text", () => {
    render(
      <DocumentPageView
        currentPage={1}
        totalPages={1}
        pageText="Hello world security test"
        onPageChange={() => {}}
        highlightRange={{ start: 6, end: 11 }}
      />
    );

    const mark = screen.getByTestId("highlighted-span-text");
    expect(mark).toHaveTextContent("world");
  });

  it("SEC-016: renders hostile script and HTML payloads strictly as inert text", () => {
    const hostilePayload = `<script>alert('XSS')</script><img src="x" onerror="alert(1)" /><svg><circle onload="alert('svg')" /></svg>`;

    render(
      <DocumentPageView
        currentPage={1}
        totalPages={1}
        pageText={hostilePayload}
        onPageChange={() => {}}
      />
    );

    const contentArea = screen.getByTestId("page-text-content");
    // Verify it is present as text content and NO script/img elements were created as DOM nodes
    expect(contentArea.textContent).toBe(hostilePayload);
    expect(document.querySelector("script")).toBeNull();
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("circle")).toBeNull();
  });
});
