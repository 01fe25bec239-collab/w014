"use client";

import React, { type ReactNode } from "react";
import { EnvironmentBadge } from "./EnvironmentBadge";
import { WorkspaceSwitcher } from "./WorkspaceSwitcher";
import { Breadcrumbs } from "./Breadcrumbs";
import { SessionMenu } from "./SessionMenu";

export interface ShellHeaderProps {
  isNavOpen?: boolean;
  onToggleNav?: () => void;
  breadcrumbs?: ReactNode;
  workspaceSlot?: ReactNode;
  sessionSlot?: ReactNode;
  className?: string;
}

export function ShellHeader({
  isNavOpen = false,
  onToggleNav,
  breadcrumbs = <Breadcrumbs />,
  workspaceSlot = <WorkspaceSwitcher />,
  sessionSlot = <SessionMenu />,
  className = "",
}: ShellHeaderProps) {
  return (
    <header role="banner" className={`shell-header ${className}`.trim()}>
      <div className="shell-header-left">
        {/* Mobile Navigation Toggle Button */}
        <button
          type="button"
          className="nav-toggle-btn"
          onClick={onToggleNav}
          aria-expanded={isNavOpen ? "true" : "false"}
          aria-controls="primary-navigation"
          aria-label={isNavOpen ? "Close navigation menu" : "Open navigation menu"}
        >
          <span aria-hidden="true" style={{ fontSize: "1.25rem", lineHeight: 1 }}>
            {isNavOpen ? "✕" : "☰"}
          </span>
        </button>

        {/* Product Brand Identity */}
        <a href="/" className="brand-identity" aria-label="W-014 Home">
          <span>W-014</span>
          <span className="brand-tag">VS0</span>
        </a>

        {/* Breadcrumbs Slot */}
        {breadcrumbs}
      </div>

      <div className="shell-header-right">
        {/* Workspace Slot */}
        {workspaceSlot}

        {/* Environment Indicator */}
        <EnvironmentBadge />

        {/* Session Slot */}
        {sessionSlot}
      </div>
    </header>
  );
}
