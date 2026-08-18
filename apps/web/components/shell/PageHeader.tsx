import React, { type ReactNode } from "react";

export interface PageHeaderProps {
  title: string;
  subtext?: string;
  badge?: ReactNode;
  actions?: ReactNode;
  className?: string;
}

/**
 * PageHeader renders the primary heading and scope introduction for a view.
 * Ensures an accessible, semantic single <h1> element for the main landmark.
 */
export function PageHeader({
  title,
  subtext,
  badge,
  actions,
  className = "",
}: PageHeaderProps) {
  return (
    <div className={`page-header ${className}`.trim()}>
      <div className="page-header-title-row">
        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)", flexWrap: "wrap" }}>
          <h1 className="page-header-title">{title}</h1>
          {badge}
        </div>
        {actions && <div className="page-header-actions">{actions}</div>}
      </div>
      {subtext && <p className="page-header-subtext">{subtext}</p>}
    </div>
  );
}
