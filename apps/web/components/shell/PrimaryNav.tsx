"use client";

import React, { useEffect } from "react";
import { CapabilityControl } from "./CapabilityControl";

export interface PrimaryNavProps {
  isOpen?: boolean;
  onClose?: () => void;
  className?: string;
}

export function PrimaryNav({
  isOpen = false,
  onClose,
  className = "",
}: PrimaryNavProps) {
  // Handle escape key to close mobile drawer
  useEffect(() => {
    if (!isOpen || !onClose) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  return (
    <>
      {/* Mobile backdrop overlay */}
      <div
        className={`nav-backdrop ${isOpen ? "nav-open" : ""}`}
        onClick={onClose}
        aria-hidden="true"
      />

      <nav
        id="primary-navigation"
        aria-label="Primary Navigation"
        className={`primary-nav ${isOpen ? "nav-open" : ""} ${className}`.trim()}
      >
        <div className="primary-nav-content">
          {/* Active W0 Foundation Section */}
          <div className="nav-section">
            <span className="nav-section-title">W0 Foundation</span>
            <a
              href="/"
              className="nav-item"
              aria-current="page"
            >
              <span>Presentation Shell</span>
              <span className="nav-item-badge">Active</span>
            </a>
          </div>

          {/* Future Slices (Non-clickable structural placeholders without dead links) */}
          <div className="nav-section">
            <span className="nav-section-title">Planned Slices (W1+)</span>
            <div
              className="nav-item disabled"
              aria-disabled="true"
              role="presentation"
            >
              <span>Programs & Workspaces</span>
              <span className="nav-item-badge">Slice 1</span>
            </div>
            <div
              className="nav-item disabled"
              aria-disabled="true"
              role="presentation"
            >
              <span>Verification & Preflight</span>
              <span className="nav-item-badge">Slice 2</span>
            </div>
            <div
              className="nav-item disabled"
              aria-disabled="true"
              role="presentation"
            >
              <span>Compliance & CDRL</span>
              <span className="nav-item-badge">Slice 3</span>
            </div>
            <div
              className="nav-item disabled"
              aria-disabled="true"
              role="presentation"
            >
              <span>Evidence & Audit</span>
              <span className="nav-item-badge">Slice 4</span>
            </div>
          </div>

          {/* Footer capability slot in nav */}
          <div style={{ marginTop: "auto", paddingTop: "var(--space-4)" }}>
            <CapabilityControl />
          </div>
        </div>
      </nav>
    </>
  );
}
