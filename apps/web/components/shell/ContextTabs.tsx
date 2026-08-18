import React from "react";

export interface ContextTabItem {
  id: string;
  label: string;
  active?: boolean;
}

export interface ContextTabsProps {
  tabs?: ContextTabItem[];
  className?: string;
}

/**
 * ContextTabs provides a structural slot for view tabs.
 * In WI-0006 (W0), it provides non-authoritative structural layout only.
 */
export function ContextTabs({
  tabs = [{ id: "overview", label: "Overview", active: true }],
  className = "",
}: ContextTabsProps) {
  return (
    <div
      className={`context-tabs-container ${className}`.trim()}
      role="tablist"
      aria-label="View context tabs"
      style={{
        display: "flex",
        gap: "var(--space-2)",
        borderBottom: "1px solid var(--border-default)",
        paddingBottom: "var(--space-2)",
      }}
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={tab.active ? "true" : "false"}
          tabIndex={tab.active ? 0 : -1}
          style={{
            background: tab.active ? "var(--bg-surface-elevated)" : "transparent",
            color: tab.active ? "var(--text-primary)" : "var(--text-secondary)",
            border: "1px solid",
            borderColor: tab.active ? "var(--border-prominent)" : "transparent",
            padding: "var(--space-1) var(--space-3)",
            borderRadius: "4px",
            fontSize: "0.8125rem",
            fontWeight: tab.active ? 600 : 400,
            cursor: "default",
          }}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
