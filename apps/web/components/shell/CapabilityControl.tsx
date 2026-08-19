import React from "react";

export interface CapabilityControlProps {
  label?: string;
  ariaLabel?: string;
  className?: string;
}

/**
 * CapabilityControl provides a structural slot indicating capability/tier.
 * In WI-0006 / WI-0106, it provides UX presentation only and is NOT authorization.
 */
export function CapabilityControl({
  label = "Presentation Shell Client",
  ariaLabel = "Capability tier",
  className = "",
}: CapabilityControlProps) {
  return (
    <div
      className={`structural-slot capability-slot ${className}`.trim()}
      role="region"
      aria-label={ariaLabel}
      data-testid="capability-control"
    >
      <span aria-hidden="true" style={{ fontSize: "0.75rem" }}>⚙</span>
      <span>{label}</span>
    </div>
  );
}
