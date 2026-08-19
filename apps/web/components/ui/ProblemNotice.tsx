"use client";

import React, { type ReactNode } from "react";
import type { ProblemDetails } from "@/lib/api-types";

export interface ProblemNoticeProps {
  problem: ProblemDetails | null | undefined;
  onRetry?: () => void;
  action?: ReactNode;
  className?: string;
}

/**
 * RFC 9457 Problem Details presentation component.
 *
 * Provides a standardized, high-trust, privacy-safe error notice.
 * Never exposes raw stack traces or internal secrets.
 */
export function ProblemNotice({
  problem,
  onRetry,
  action,
  className = "",
}: ProblemNoticeProps) {
  if (!problem) return null;

  const isUnauthorized = problem.status === 401;
  const isForbidden = problem.status === 403;
  const isNotFound = problem.status === 404;
  const isConflict = problem.status === 409;

  let severityClass = "problem-notice-error";
  if (isUnauthorized || isForbidden) {
    severityClass = "problem-notice-warning";
  } else if (isNotFound) {
    severityClass = "problem-notice-info";
  } else if (isConflict) {
    severityClass = "problem-notice-warning";
  }

  return (
    <div
      role="alert"
      aria-live="assertive"
      className={`problem-notice ${severityClass} ${className}`.trim()}
      data-testid="problem-notice"
      data-status={problem.status}
    >
      <div className="problem-notice-header">
        <div className="problem-notice-title-wrap">
          <span className="problem-notice-icon" aria-hidden="true">
            {problem.status >= 500 ? "⚠️" : problem.status === 404 ? "🔍" : "⛔"}
          </span>
          <h3 className="problem-notice-title">
            {problem.title || "Operation Failed"}
          </h3>
          {problem.status > 0 && (
            <span className="problem-notice-status-badge">
              HTTP {problem.status}
            </span>
          )}
          {problem.code && (
            <span className="problem-notice-code-badge">{problem.code}</span>
          )}
        </div>
      </div>

      {problem.detail && (
        <div className="problem-notice-body">
          <p className="problem-notice-detail">{problem.detail}</p>
        </div>
      )}

      {(problem.instance || problem.correlation_id || onRetry || action) && (
        <div className="problem-notice-footer">
          <div className="problem-notice-metadata">
            {problem.instance && (
              <span className="problem-notice-meta-item">
                <span className="meta-key">Path:</span> {problem.instance}
              </span>
            )}
            {problem.correlation_id && (
              <span className="problem-notice-meta-item">
                <span className="meta-key">Correlation ID:</span>{" "}
                <code>{problem.correlation_id}</code>
              </span>
            )}
          </div>

          <div className="problem-notice-actions">
            {onRetry && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={onRetry}
                data-testid="problem-retry-btn"
              >
                Retry
              </button>
            )}
            {action}
          </div>
        </div>
      )}
    </div>
  );
}
