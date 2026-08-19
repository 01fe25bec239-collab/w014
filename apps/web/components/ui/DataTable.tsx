import React, { type ReactNode } from "react";

export interface ColumnDef<T> {
  key: string;
  header: string;
  render?: (item: T) => ReactNode;
  className?: string;
  headerClassName?: string;
}

export interface DataTableProps<T> {
  columns: ColumnDef<T>[];
  data: T[];
  keyExtractor: (item: T) => string;
  caption: string;
  captionVisible?: boolean;
  isLoading?: boolean;
  emptyMessage?: string;
  className?: string;
  testId?: string;
}

/**
 * Accessible Data Table component meeting WCAG 2.2 AA standards.
 * Supports truthful loading skeleton and truthful empty states.
 */
export function DataTable<T>({
  columns,
  data,
  keyExtractor,
  caption,
  captionVisible = false,
  isLoading = false,
  emptyMessage = "No records found.",
  className = "",
  testId = "data-table",
}: DataTableProps<T>) {
  return (
    <div className={`data-table-wrapper ${className}`.trim()}>
      <table className="data-table" data-testid={testId}>
        <caption className={captionVisible ? "data-table-caption" : "sr-only"}>
          {caption}
        </caption>
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                scope="col"
                className={`data-table-th ${col.headerClassName || ""}`.trim()}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {isLoading ? (
            // Truthful loading skeleton rows
            Array.from({ length: 3 }).map((_, idx) => (
              <tr
                key={`loading-row-${idx}`}
                className="data-table-loading-row"
                aria-hidden="true"
              >
                {columns.map((col) => (
                  <td key={`loading-cell-${col.key}`} className="data-table-td">
                    <div className="skeleton-line" />
                  </td>
                ))}
              </tr>
            ))
          ) : data.length === 0 ? (
            // Truthful empty state only after successful response
            <tr className="data-table-empty-row">
              <td
                colSpan={columns.length}
                className="data-table-td data-table-empty-cell"
                data-testid="data-table-empty"
              >
                {emptyMessage}
              </td>
            </tr>
          ) : (
            // Populated rows
            data.map((item) => {
              const rowKey = keyExtractor(item);
              return (
                <tr
                  key={rowKey}
                  className="data-table-row"
                  data-testid={`data-table-row-${rowKey}`}
                >
                  {columns.map((col) => {
                    const content = col.render
                      ? col.render(item)
                      : (item as Record<string, unknown>)[col.key] !== undefined
                      ? String((item as Record<string, unknown>)[col.key])
                      : null;
                    return (
                      <td
                        key={`${rowKey}-${col.key}`}
                        className={`data-table-td ${col.className || ""}`.trim()}
                      >
                        {content}
                      </td>
                    );
                  })}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
