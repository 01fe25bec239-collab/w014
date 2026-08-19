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
 * Breadcrumbs provides structural route and hierarchy context.
 */
export function Breadcrumbs({
  items = [
    { label: "W-014", href: "/" },
    { label: "Presentation Shell", current: true },
  ],
  className = "",
}: BreadcrumbsProps) {
  return (
    <nav
      aria-label="Breadcrumbs"
      className={`breadcrumbs-container ${className}`.trim()}
      data-testid="breadcrumbs"
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
                  data-testid="breadcrumb-current"
                >
                  {item.label}
                </span>
              ) : item.href ? (
                <a
                  href={item.href}
                  className="breadcrumb-link"
                  data-testid={`breadcrumb-link-${index}`}
                >
                  {item.label}
                </a>
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
