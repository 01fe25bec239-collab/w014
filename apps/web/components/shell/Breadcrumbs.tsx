import React from "react";

export interface BreadcrumbItem {
  label: string;
  href?: string;
  current?: boolean;
}

export interface BreadcrumbsProps {
  items?: BreadcrumbItem[];
  className?: string;
}

/**
 * Breadcrumbs provides structural route/hierarchy context.
 * In WI-0006 (W0), it does NOT invent domain or object truth.
 */
export function Breadcrumbs({
  items = [
    { label: "W-014" },
    { label: "Presentation Shell", current: true },
  ],
  className = "",
}: BreadcrumbsProps) {
  return (
    <nav
      aria-label="Breadcrumbs"
      className={`breadcrumbs-container ${className}`.trim()}
    >
      <ol
        style={{
          display: "flex",
          alignItems: "center",
          gap: "var(--space-2)",
          listStyle: "none",
          margin: 0,
          padding: 0,
        }}
      >
        {items.map((item, index) => {
          const isLast = index === items.length - 1 || item.current;
          return (
            <li
              key={`${item.label}-${index}`}
              style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}
            >
              {index > 0 && (
                <span
                  className="breadcrumbs-separator"
                  aria-hidden="true"
                  style={{ userSelect: "none" }}
                >
                  /
                </span>
              )}
              {isLast ? (
                <span
                  className="breadcrumbs-current"
                  aria-current="page"
                >
                  {item.label}
                </span>
              ) : (
                <span>{item.label}</span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
