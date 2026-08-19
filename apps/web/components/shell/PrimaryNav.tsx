"use client";

import React, { useEffect, useState } from "react";
import { CapabilityControl } from "./CapabilityControl";

export interface PrimaryNavProps {
  isOpen?: boolean;
  onClose?: () => void;
  enableW1Nav?: boolean;
  activePath?: string;
  className?: string;
}

export function PrimaryNav({
  isOpen = false,
  onClose,
  enableW1Nav = false,
  activePath: propActivePath,
  className = "",
}: PrimaryNavProps) {
  const [currentPath, setCurrentPath] = useState<string>(propActivePath || "");

  useEffect(() => {
    if (propActivePath) {
      setCurrentPath(propActivePath);
    } else if (typeof window !== "undefined") {
      setCurrentPath(window.location.pathname);
    }
  }, [propActivePath]);

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

  const isCurrent = (path: string) => {
    if (path === "/" && (currentPath === "/" || currentPath === "")) return true;
    if (path !== "/" && currentPath.startsWith(path)) return true;
    return false;
  };

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
          {enableW1Nav ? (
            <>
              {/* Active W1 Navigation Section */}
              <div className="nav-section">
                <span className="nav-section-title">Navigation</span>
                <a
                  href="/"
                  className="nav-item"
                  aria-current={isCurrent("/") && currentPath === "/" ? "page" : undefined}
                  data-testid="nav-presentation-shell"
                >
                  <span>Presentation Shell</span>
                  <span className="nav-item-badge">VS0</span>
                </a>
                <a
                  href="/sign-in"
                  className="nav-item"
                  aria-current={isCurrent("/sign-in") ? "page" : undefined}
                  data-testid="nav-sign-in"
                >
                  <span>Sign In &amp; Session</span>
                  <span className="nav-item-badge">S01</span>
                </a>
              </div>

              {/* Active W1 Portfolio Section */}
              <div className="nav-section">
                <span className="nav-section-title">Portfolio &amp; Workspaces (W1)</span>
                <a
                  href="/programs"
                  className="nav-item"
                  aria-current={
                    isCurrent("/programs") || isCurrent("/workspaces")
                      ? "page"
                      : undefined
                  }
                  data-testid="nav-programs"
                >
                  <span>Programs &amp; Workspaces</span>
                  <span className="nav-item-badge">S02–S04</span>
                </a>
              </div>

              {/* Future Slices (W2+) */}
              <div className="nav-section">
                <span className="nav-section-title">Planned Slices (W2+)</span>
                <div
                  className="nav-item disabled"
                  aria-disabled="true"
                  role="presentation"
                >
                  <span>Verification &amp; Preflight</span>
                  <span className="nav-item-badge">Slice 2</span>
                </div>
                <div
                  className="nav-item disabled"
                  aria-disabled="true"
                  role="presentation"
                >
                  <span>Compliance &amp; CDRL</span>
                  <span className="nav-item-badge">Slice 3</span>
                </div>
                <div
                  className="nav-item disabled"
                  aria-disabled="true"
                  role="presentation"
                >
                  <span>Evidence &amp; Audit</span>
                  <span className="nav-item-badge">Slice 4</span>
                </div>
              </div>
            </>
          ) : (
            <>
              {/* Foundation Baseline (WI-0006) */}
              <div className="nav-section">
                <span className="nav-section-title">W0 Foundation</span>
                <a
                  href="/"
                  className="nav-item"
                  aria-current="page"
                  data-testid="nav-presentation-shell"
                >
                  <span>Presentation Shell</span>
                  <span className="nav-item-badge">Active</span>
                </a>
              </div>

              {/* Future Slices (W1+) */}
              <div className="nav-section">
                <span className="nav-section-title">Planned Slices (W1+)</span>
                <div
                  className="nav-item disabled"
                  aria-disabled="true"
                  role="presentation"
                >
                  <span>Programs &amp; Workspaces</span>
                  <span className="nav-item-badge">Slice 1</span>
                </div>
                <div
                  className="nav-item disabled"
                  aria-disabled="true"
                  role="presentation"
                >
                  <span>Verification &amp; Preflight</span>
                  <span className="nav-item-badge">Slice 2</span>
                </div>
                <div
                  className="nav-item disabled"
                  aria-disabled="true"
                  role="presentation"
                >
                  <span>Compliance &amp; CDRL</span>
                  <span className="nav-item-badge">Slice 3</span>
                </div>
                <div
                  className="nav-item disabled"
                  aria-disabled="true"
                  role="presentation"
                >
                  <span>Evidence &amp; Audit</span>
                  <span className="nav-item-badge">Slice 4</span>
                </div>
              </div>
            </>
          )}

          {/* Footer capability slot in nav */}
          <div style={{ marginTop: "auto", paddingTop: "var(--space-4)" }}>
            <CapabilityControl ariaLabel="Sidebar navigation capability tier" />
          </div>
        </div>
      </nav>
    </>
  );
}
