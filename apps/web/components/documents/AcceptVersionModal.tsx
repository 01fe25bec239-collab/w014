"use client";

import React, { useEffect, useRef } from "react";
import type { DocumentVersionDto } from "@/lib/api-types";

export interface AcceptVersionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
  version: DocumentVersionDto | null;
  rowVersion: number;
  isLoading?: boolean;
  serverError?: string | null;
}

export function AcceptVersionModal({
  isOpen,
  onClose,
  onConfirm,
  version,
  rowVersion,
  isLoading = false,
  serverError = null,
}: AcceptVersionModalProps) {
  const confirmBtnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => confirmBtnRef.current?.focus(), 50);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !version) return null;

  return (
    <div className="modal-backdrop" onClick={onClose} data-testid="modal-backdrop">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="accept-version-title"
        aria-describedby="accept-version-desc"
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        data-testid="accept-version-modal"
      >
        <div className="modal-header">
          <div>
            <h2 id="accept-version-title" className="modal-title">
              Promote to Current Version
            </h2>
            <p id="accept-version-desc" className="modal-description">
              Set authoritative current version pointer for this document.
            </p>
          </div>
          <button
            type="button"
            className="modal-close-btn"
            onClick={onClose}
            aria-label="Close dialog"
            data-testid="modal-close-btn"
          >
            ✕
          </button>
        </div>

        <div className="modal-form">
          {serverError && (
            <div
              className="form-error-banner"
              role="alert"
              data-testid="accept-version-server-error"
            >
              {serverError}
            </div>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
            <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)" }}>
              Are you sure you want to promote version <strong className="text-primary font-mono">v{version.version_number}</strong> ({version.original_filename}) as the current version?
            </p>

            <ul className="panel-item-list" style={{ fontSize: "0.8125rem" }}>
              <li className="panel-item">
                <span className="panel-item-key">Target Version:</span>
                <span className="panel-item-value font-mono">v{version.version_number} ({version.id})</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">SHA-256 Digest:</span>
                <span className="panel-item-value font-mono">{version.sha256_hash.slice(0, 16)}...</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Expected Row Version:</span>
                <span className="panel-item-value font-mono">{rowVersion}</span>
              </li>
              <li className="panel-item">
                <span className="panel-item-key">Precondition Guard:</span>
                <span className="panel-item-value font-mono">If-Match: &quot;{rowVersion}&quot;</span>
              </li>
            </ul>

            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Historical versions remain immutable. This action updates the authoritative pointer in the Rust core and enqueues dependency evaluation.
            </p>
          </div>

          <div className="modal-actions" style={{ marginTop: "var(--space-4)" }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
              disabled={isLoading}
              data-testid="cancel-accept-btn"
            >
              Cancel
            </button>
            <button
              ref={confirmBtnRef}
              type="button"
              className="btn btn-primary"
              onClick={onConfirm}
              disabled={isLoading}
              data-testid="confirm-accept-btn"
            >
              {isLoading ? "Promoting Version..." : "Confirm & Set as Current"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
