"use client";

import React, { useState, type ReactNode } from "react";
import { SkipToContent } from "./SkipToContent";
import { DataBoundaryBanner } from "./DataBoundaryBadge";
import { ShellHeader } from "./ShellHeader";
import { PrimaryNav } from "./PrimaryNav";

export interface AppShellProps {
  children: ReactNode;
  breadcrumbs?: ReactNode;
  workspaceSlot?: ReactNode;
  sessionSlot?: ReactNode;
  enableW1Nav?: boolean;
  className?: string;
}

export function AppShell({
  children,
  breadcrumbs,
  workspaceSlot,
  sessionSlot,
  enableW1Nav = false,
  className = "",
}: AppShellProps) {
  const [isNavOpen, setIsNavOpen] = useState(false);

  const handleToggleNav = () => {
    setIsNavOpen((prev) => !prev);
  };

  const handleCloseNav = () => {
    setIsNavOpen(false);
  };

  return (
    <div className={`app-root ${className}`.trim()}>
      {/* Keyboard Accessibility Skip Link */}
      <SkipToContent />

      {/* Persistent Data Boundary Treatment */}
      <DataBoundaryBanner />

      {/* Primary Shell Header Landmark */}
      <ShellHeader
        isNavOpen={isNavOpen}
        onToggleNav={handleToggleNav}
        breadcrumbs={breadcrumbs}
        workspaceSlot={workspaceSlot}
        sessionSlot={sessionSlot}
      />

      {/* Main Shell Body */}
      <div className="shell-body">
        {/* Responsive Primary Navigation Sidebar */}
        <PrimaryNav
          isOpen={isNavOpen}
          onClose={handleCloseNav}
          enableW1Nav={enableW1Nav}
        />

        {/* Primary Content Landmark */}
        <main id="main-content" className="primary-content" tabIndex={-1}>
          <div className="content-container">{children}</div>
        </main>
      </div>

      {/* Persistent Accessible Footer Landmark (Top-level contentinfo) */}
      <footer className="shell-footer" role="contentinfo">
        <div className="shell-footer-left">
          <span>W-014 Defense &amp; Aerospace Systems Verification</span>
          <span aria-hidden="true">•</span>
          <span>Presentation Shell (VS0)</span>
        </div>
        <div className="shell-footer-right">
          <span>Rust Core Authority • Next.js Presentation Client</span>
        </div>
      </footer>
    </div>
  );
}
