import React from "react";

export const DATA_BOUNDARY_TEXT =
  "Portfolio demo: public / synthetic / sanitized non-CUI only.";

export interface DataBoundaryBadgeProps {
  className?: string;
}

/**
 * DataBoundaryBadge displays the persistent, non-authoritative boundary
 * statement required for all W-014 portfolio demonstrations.
 *
 * Explicitly DOES NOT claim CUI readiness, CMMC compliance, FedRAMP authorization,
 * ITAR production readiness, Government accreditation, or production-customer readiness.
 */
export function DataBoundaryBadge({ className = "" }: DataBoundaryBadgeProps) {
  return (
    <span
      className={`data-boundary-badge ${className}`.trim()}
      role="status"
      aria-label={`Data Boundary: ${DATA_BOUNDARY_TEXT}`}
    >
      <span aria-hidden="true">🔒</span>
      <span>{DATA_BOUNDARY_TEXT}</span>
    </span>
  );
}

export interface DataBoundaryBannerProps {
  className?: string;
}

/**
 * DataBoundaryBanner provides a persistent top banner across all views.
 */
export function DataBoundaryBanner({ className = "" }: DataBoundaryBannerProps) {
  return (
    <aside
      className={`data-boundary-banner ${className}`.trim()}
      aria-label="Portfolio data boundary notification"
    >
      <span aria-hidden="true">🔒</span>
      <span>{DATA_BOUNDARY_TEXT}</span>
    </aside>
  );
}
