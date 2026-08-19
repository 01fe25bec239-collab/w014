import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { DataTable, type ColumnDef } from "./DataTable";

interface TestItem {
  id: string;
  name: string;
  count: number;
}

describe("DataTable", () => {
  const columns: ColumnDef<TestItem>[] = [
    { key: "name", header: "Name" },
    { key: "count", header: "Count", render: (item) => `${item.count} items` },
  ];

  const items: TestItem[] = [
    { id: "1", name: "Alpha", count: 10 },
    { id: "2", name: "Beta", count: 20 },
  ];

  it("renders data table with accessible columns and rows", () => {
    render(
      <DataTable
        columns={columns}
        data={items}
        keyExtractor={(item) => item.id}
        caption="Test Table Caption"
      />
    );

    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.getByText("Alpha")).toBeInTheDocument();
    expect(screen.getByText("10 items")).toBeInTheDocument();
    expect(screen.getByText("Beta")).toBeInTheDocument();
    expect(screen.getByText("20 items")).toBeInTheDocument();
  });

  it("renders loading skeleton rows when isLoading is true", () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[]}
        keyExtractor={(item) => item.id}
        caption="Loading Table"
        isLoading={true}
      />
    );

    const skeletonRows = container.querySelectorAll(".data-table-loading-row");
    expect(skeletonRows.length).toBeGreaterThan(0);
  });

  it("renders truthful empty message when data is empty and not loading", () => {
    render(
      <DataTable
        columns={columns}
        data={[]}
        keyExtractor={(item) => item.id}
        caption="Empty Table"
        emptyMessage="No items found."
      />
    );

    expect(screen.getByText("No items found.")).toBeInTheDocument();
  });

  it("has 0 axe accessibility violations", async () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={items}
        keyExtractor={(item) => item.id}
        caption="Accessible Table"
      />
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
