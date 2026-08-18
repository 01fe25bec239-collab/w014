import React from "react";
import {
  AppShell,
  PageHeader,
  DataBoundaryBadge,
  DATA_BOUNDARY_TEXT,
} from "@/components/shell";
import { getAppEnvironment } from "@/lib/env";

export default function Page() {
  const envInfo = getAppEnvironment();

  return (
    <AppShell>
      {/* Page Heading Landmark */}
      <PageHeader
        title="W-014 Systems Verification & Compliance"
        subtext="Foundation presentation shell and test harness for the W-014 platform (Wave 0 / Vertical Slice 0)."
        badge={<DataBoundaryBadge />}
      />

      {/* Grid of Status & Boundary Panels */}
      <div className="panel-grid">
        {/* Panel 1: Shell Foundation Status */}
        <section className="panel" aria-labelledby="heading-shell-status">
          <div className="panel-header">
            <h2 id="heading-shell-status" className="panel-title">
              Shell Foundation Status
            </h2>
            <span
              className="environment-badge"
              data-env={envInfo.name}
              style={{ fontSize: "0.625rem" }}
            >
              {envInfo.name.toUpperCase()}
            </span>
          </div>
          <div className="panel-body">
            <p>
              The Next.js presentation shell is initialized as the presentation
              client for the W-014 platform.
            </p>
            <ul className="panel-item-list">
              <li className="panel-item">
                <span className="panel-item-key">Work Item:</span>
                <span className="panel-item-value">WI-0006 (W0 / VS0)</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Shell Layer:</span>
                <span className="panel-item-value">Presentation Shell</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Test Harness:</span>
                <span className="panel-item-value">Vitest + React Testing Library + Axe</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Environment:</span>
                <span className="panel-item-value">{envInfo.label}</span>
              </li>
            </ul>
          </div>
        </section>

        {/* Panel 2: Portfolio Data Boundary */}
        <section className="panel" aria-labelledby="heading-data-boundary">
          <div className="panel-header">
            <h2 id="heading-data-boundary" className="panel-title">
              Data &amp; Portfolio Boundary
            </h2>
            <span className="nav-item-badge">Boundary</span>
          </div>
          <div className="panel-body">
            <p style={{ fontWeight: 500, color: "var(--boundary-text)" }}>
              {DATA_BOUNDARY_TEXT}
            </p>
            <p>
              This environment operates strictly on synthetic, public, and
              sanitized test fixtures. No Controlled Unclassified Information
              (CUI) or classified defense articles are processed or stored in
              this presentation tier.
            </p>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Notice: No CUI readiness, CMMC compliance, FedRAMP authorization,
              ITAR production readiness, or Government accreditation is claimed
              or implied for this demonstration shell.
            </p>
          </div>
        </section>

        {/* Panel 3: Authority & Security Architecture */}
        <section className="panel" aria-labelledby="heading-authority-model">
          <div className="panel-header">
            <h2 id="heading-authority-model" className="panel-title">
              Authority &amp; Architectural Boundary
            </h2>
            <span className="nav-item-badge">Architecture</span>
          </div>
          <div className="panel-body">
            <p>
              In accordance with W-014 authority hierarchy (Prompts 10–14):
            </p>
            <ul className="panel-item-list">
              <li className="panel-item">
                <span className="panel-item-key">Rust Services:</span>
                <span className="panel-item-value">
                  Sole authority for verification, state machines, rules, and security.
                </span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Next.js Package:</span>
                <span className="panel-item-value">
                  Presentation and command client only. No client-side domain truth.
                </span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Data State:</span>
                <span className="panel-item-value">
                  No mock or fabricated business metrics rendered.
                </span>
              </li>
            </ul>
          </div>
        </section>

        {/* Panel 4: Vertical Slice Roadmap */}
        <section className="panel" aria-labelledby="heading-slice-roadmap">
          <div className="panel-header">
            <h2 id="heading-slice-roadmap" className="panel-title">
              Planned Domain Slices
            </h2>
            <span className="nav-item-badge">W1+ Arrival</span>
          </div>
          <div className="panel-body">
            <p>
              Domain workflows arrive through later authorized vertical slices:
            </p>
            <ul className="panel-item-list">
              <li className="panel-item">
                <span className="panel-item-key">Slice 1 (W1):</span>
                <span className="panel-item-value">Programs, Workspaces &amp; Auth integration</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Slice 2 (W2):</span>
                <span className="panel-item-value">Verification Engine &amp; Preflight checks</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Slice 3 (W3):</span>
                <span className="panel-item-value">Compliance Matrix &amp; CDRL management</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Slice 4 (W4):</span>
                <span className="panel-item-value">Evidence Tracking &amp; Tamper-evident audit</span>
              </li>
            </ul>
          </div>
        </section>
      </div>
    </AppShell>
  );
}
