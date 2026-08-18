import React from "react";

export interface SessionMenuProps {
  className?: string;
}

/**
 * SessionMenu provides a structural slot for session indication.
 * In WI-0006 (W0), it does NOT invent login, user, or session state.
 */
export function SessionMenu({ className = "" }: SessionMenuProps) {
  return (
    <div
      className={`structural-slot session-slot ${className}`.trim()}
      role="region"
      aria-label="Session status"
    >
      <span aria-hidden="true" style={{ fontSize: "0.75rem" }}>👤</span>
      <span>Presentation Mode</span>
    </div>
  );
}
