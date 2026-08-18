import React from "react";

export interface CapabilityControlProps {
  className?: string;
}

/**
 * CapabilityControl provides a structural slot indicating capability/tier.
 * In WI-0006 (W0), it does NOT perform authorization, token checks, or permission logic.
 */
export function CapabilityControl({ className = "" }: CapabilityControlProps) {
  return (
    <div
      className={`structural-slot capability-slot ${className}`.trim()}
      role="region"
      aria-label="Capability tier"
    >
      <span aria-hidden="true" style={{ fontSize: "0.75rem" }}>⚙</span>
      <span>Presentation Shell Client</span>
    </div>
  );
}
