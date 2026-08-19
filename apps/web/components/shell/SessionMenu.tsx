"use client";

import React from "react";
import { useSession } from "@/lib/session-context";

export interface SessionMenuProps {
  className?: string;
}

/**
 * SessionMenu displays the current active session state from the authoritative Rust backend.
 * Provides live authentication status and session termination commands.
 */
export function SessionMenu({ className = "" }: SessionMenuProps) {
  let sessionCtx;
  try {
    sessionCtx = useSession();
  } catch {
    sessionCtx = null;
  }

  const session = sessionCtx?.session;
  const isLoading = sessionCtx?.isLoading ?? false;
  const logout = sessionCtx?.logout;

  if (isLoading) {
    return (
      <div
        className={`structural-slot session-slot ${className}`.trim()}
        role="region"
        aria-label="Session status"
        data-testid="session-menu-loading"
      >
        <span aria-hidden="true" style={{ fontSize: "0.75rem" }}>⏳</span>
        <span>Checking session...</span>
      </div>
    );
  }

  if (session) {
    return (
      <div
        className={`structural-slot session-slot session-active ${className}`.trim()}
        role="region"
        aria-label="Active session status"
        data-testid="session-menu-active"
      >
        <span className="session-active-dot" aria-hidden="true" />
        <span className="session-principal-label" title={session.principal_id}>
          {session.principal_id.length > 16
            ? `${session.principal_id.substring(0, 16)}...`
            : session.principal_id}
        </span>
        {logout && (
          <button
            type="button"
            className="session-logout-btn"
            onClick={() => logout()}
            aria-label="Sign out"
            data-testid="session-menu-logout-btn"
          >
            Sign Out
          </button>
        )}
      </div>
    );
  }

  return (
    <div
      className={`structural-slot session-slot ${className}`.trim()}
      role="region"
      aria-label="Session status"
      data-testid="session-menu-signed-out"
    >
      <span aria-hidden="true" style={{ fontSize: "0.75rem" }}>👤</span>
      <span data-testid="session-presentation-mode">Presentation Mode</span>
    </div>
  );
}
