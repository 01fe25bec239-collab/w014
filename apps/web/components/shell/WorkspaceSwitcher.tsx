import React from "react";

export interface WorkspaceSwitcherProps {
  className?: string;
}

/**
 * WorkspaceSwitcher provides a structural slot for workspace selection.
 * In WI-0006 (W0), it does NOT query, invent, or manage workspaces.
 */
export function WorkspaceSwitcher({ className = "" }: WorkspaceSwitcherProps) {
  return (
    <div
      className={`structural-slot workspace-slot ${className}`.trim()}
      role="region"
      aria-label="Workspace Scope"
    >
      <span aria-hidden="true" style={{ fontSize: "0.75rem" }}>📁</span>
      <span>Scope: Presentation Shell</span>
    </div>
  );
}
