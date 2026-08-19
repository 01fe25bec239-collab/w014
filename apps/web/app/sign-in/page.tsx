"use client";

import React, { useState } from "react";
import {
  AppShell,
  PageHeader,
  DataBoundaryBadge,
  Breadcrumbs,
  DATA_BOUNDARY_TEXT,
} from "@/components/shell";
import { ProblemNotice } from "@/components/ui/ProblemNotice";
import { useSession } from "@/lib/session-context";

export default function SignInPage() {
  const { session, isLoading, error, refreshSession, logout, initiateLogin } =
    useSession();
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const handleLoginClick = async () => {
    setIsLoggingIn(true);
    try {
      await initiateLogin();
    } finally {
      setIsLoggingIn(false);
    }
  };

  const breadcrumbs = (
    <Breadcrumbs
      items={[
        { label: "W-014", href: "/" },
        { label: "Sign In & Session", current: true },
      ]}
    />
  );

  return (
    <AppShell breadcrumbs={breadcrumbs} enableW1Nav={true}>
      <PageHeader
        title="Sign In &amp; Session Management"
        subtext="Authoritative OIDC authentication entrypoint and server-side session inspector (WI-0106 / S01)."
        badge={<DataBoundaryBadge />}
      />

      {error && (
        <ProblemNotice
          problem={error}
          onRetry={refreshSession}
          className="mb-4"
        />
      )}

      {isLoading ? (
        <div className="panel" data-testid="sign-in-loading">
          <div className="panel-header">
            <h2 className="panel-title">Session State</h2>
            <span className="nav-item-badge">Inspecting</span>
          </div>
          <div className="panel-body">
            <p>Verifying active session with authoritative Rust backend...</p>
            <div className="skeleton-line" style={{ height: "24px", width: "60%" }} />
            <div className="skeleton-line" style={{ height: "24px", width: "40%" }} />
          </div>
        </div>
      ) : session ? (
        <div className="panel-grid">
          {/* Active Session Summary Panel */}
          <section className="panel" aria-labelledby="heading-active-session" data-testid="session-active-panel">
            <div className="panel-header">
              <h2 id="heading-active-session" className="panel-title">
                Active Session Summary
              </h2>
              <span className="environment-badge" data-env="local" style={{ fontSize: "0.625rem" }}>
                {session.status.toUpperCase()}
              </span>
            </div>
            <div className="panel-body">
              <p>
                An authoritative server-side session is currently active for your principal.
              </p>
              <ul className="panel-item-list">
                <li className="panel-item">
                  <span className="panel-item-key">Principal ID:</span>
                  <span className="panel-item-value" data-testid="session-principal-id">
                    {session.principal_id}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Session ID:</span>
                  <span className="panel-item-value font-mono" data-testid="session-id">
                    {session.session_id}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Status:</span>
                  <span className="panel-item-value" data-testid="session-status">
                    {session.status}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Created:</span>
                  <span className="panel-item-value">
                    {new Date(session.created_at).toLocaleString()}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Idle Expires:</span>
                  <span className="panel-item-value">
                    {new Date(session.idle_expires_at).toLocaleString()}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">Absolute Expires:</span>
                  <span className="panel-item-value">
                    {new Date(session.absolute_expires_at).toLocaleString()}
                  </span>
                </li>
                <li className="panel-item">
                  <span className="panel-item-key">CSRF Protection:</span>
                  <span className="panel-item-value">
                    {session.csrf_token ? "Active (Origin + Header Bound)" : "None"}
                  </span>
                </li>
              </ul>

              <div style={{ display: "flex", gap: "var(--space-3)", marginTop: "var(--space-3)", flexWrap: "wrap" }}>
                <a
                  href="/programs"
                  className="btn btn-primary"
                  data-testid="enter-programs-btn"
                >
                  Enter Programs Portfolio →
                </a>
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={() => logout()}
                  data-testid="sign-out-btn"
                >
                  Sign Out / Revoke Session
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => refreshSession()}
                  data-testid="refresh-session-btn"
                >
                  Refresh Status
                </button>
              </div>
            </div>
          </section>

          {/* Data Boundary Panel */}
          <section className="panel" aria-labelledby="heading-session-boundary">
            <div className="panel-header">
              <h2 id="heading-session-boundary" className="panel-title">
                Session Authority Boundary
              </h2>
              <span className="nav-item-badge">Security</span>
            </div>
            <div className="panel-body">
              <p style={{ fontWeight: 500, color: "var(--boundary-text)" }}>
                {DATA_BOUNDARY_TEXT}
              </p>
              <p>
                Session authenticity is evaluated strictly by the Rust backend on every request.
                Bearer tokens are stored in HttpOnly server-side cookies. No bearer tokens or credentials
                are stored in browser storage.
              </p>
            </div>
          </section>
        </div>
      ) : (
        <div className="panel-grid">
          {/* Signed-out login initiation panel */}
          <section className="panel" aria-labelledby="heading-signed-out" data-testid="sign-in-signed-out">
            <div className="panel-header">
              <h2 id="heading-signed-out" className="panel-title">
                Sign In to Platform
              </h2>
              <span className="nav-item-badge">Unauthenticated</span>
            </div>
            <div className="panel-body">
              <p>
                Authentication uses the OpenID Connect (OIDC) Authorization Code flow with S256 PKCE.
                Initiating login requests an authoritative authorization challenge from the backend.
              </p>

              <div style={{ marginTop: "var(--space-4)", display: "flex", gap: "var(--space-3)", flexWrap: "wrap" }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleLoginClick}
                  disabled={isLoggingIn}
                  data-testid="initiate-login-btn"
                >
                  {isLoggingIn ? "Initiating Login..." : "Initiate OIDC Login"}
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => refreshSession()}
                  data-testid="check-session-btn"
                >
                  Check Active Session
                </button>
              </div>
            </div>
          </section>

          {/* Security & Boundary Notice */}
          <section className="panel" aria-labelledby="heading-auth-boundary">
            <div className="panel-header">
              <h2 id="heading-auth-boundary" className="panel-title">
                Authentication Truth
              </h2>
              <span className="nav-item-badge">Architecture</span>
            </div>
            <div className="panel-body">
              <p>
                Frontend client is not authoritative for identity truth.
                The Next.js client never verifies signatures, manages PKCE secrets, or fabricates logged-in states.
              </p>
              <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Notice: All access control and capability evaluations are enforced server-side.
              </p>
            </div>
          </section>
        </div>
      )}
    </AppShell>
  );
}
