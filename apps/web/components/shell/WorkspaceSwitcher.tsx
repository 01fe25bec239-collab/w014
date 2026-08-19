import React from "react";

export interface WorkspaceSwitcherProps {
  currentWorkspace?: {
    name: string;
    slug?: string;
    id?: string;
  };
  currentProgram?: {
    name: string;
    id?: string;
  };
  className?: string;
}

/**
 * WorkspaceSwitcher displays current workspace scope and navigation entrypoint.
 * Scoped to the currently authoritative active workspace context.
 */
export function WorkspaceSwitcher({
  currentWorkspace,
  currentProgram,
  className = "",
}: WorkspaceSwitcherProps) {
  if (currentWorkspace) {
    return (
      <div
        className={`structural-slot workspace-slot workspace-scoped ${className}`.trim()}
        role="region"
        aria-label="Workspace Scope"
        data-testid="workspace-switcher-scoped"
      >
        <span aria-hidden="true" style={{ fontSize: "0.75rem" }}>📁</span>
        <span className="workspace-scope-name">
          {currentWorkspace.name}
        </span>
        {currentProgram ? (
          <a
            href={`/programs/${encodeURIComponent(currentProgram.id || "")}/workspaces`}
            className="workspace-switch-action"
            aria-label="Switch workspace in program"
            data-testid="workspace-switch-btn"
          >
            Switch
          </a>
        ) : (
          <a
            href="/programs"
            className="workspace-switch-action"
            aria-label="Switch workspace"
            data-testid="workspace-switch-btn"
          >
            Switch
          </a>
        )}
      </div>
    );
  }

  return (
    <div
      className={`structural-slot workspace-slot ${className}`.trim()}
      role="region"
      aria-label="Workspace Scope"
      data-testid="workspace-switcher-default"
    >
      <span aria-hidden="true" style={{ fontSize: "0.75rem" }}>📁</span>
      <span>Scope: Presentation Shell</span>
    </div>
  );
}
