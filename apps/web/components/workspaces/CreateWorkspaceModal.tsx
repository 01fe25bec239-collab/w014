"use client";

import React, { useEffect, useRef, useState } from "react";
import type { CreateWorkspaceDto } from "@/lib/api-types";

export interface CreateWorkspaceModalProps {
  isOpen: boolean;
  programName?: string;
  onClose: () => void;
  onSubmit: (dto: CreateWorkspaceDto) => Promise<void>;
  isLoading?: boolean;
  serverError?: string | null;
}

export function CreateWorkspaceModal({
  isOpen,
  programName,
  onClose,
  onSubmit,
  isLoading = false,
  serverError = null,
}: CreateWorkspaceModalProps) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugManual, setSlugManual] = useState(false);
  const [errors, setErrors] = useState<{ name?: string; slug?: string }>({});

  const nameInputRef = useRef<HTMLInputElement>(null);

  const handleNameChange = (val: string) => {
    setName(val);
    if (!slugManual) {
      const generated = val
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "");
      setSlug(generated);
    }
  };

  const handleSlugChange = (val: string) => {
    setSlugManual(true);
    setSlug(val.toLowerCase().replace(/[^a-z0-9-]/g, ""));
  };

  const validate = (): boolean => {
    const nextErrors: { name?: string; slug?: string } = {};
    if (!name.trim()) {
      nextErrors.name = "Workspace name is required.";
    }
    if (!slug.trim()) {
      nextErrors.slug = "Workspace slug is required.";
    } else if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug)) {
      nextErrors.slug = "Slug must contain only lowercase alphanumeric characters and single hyphens.";
    }

    setErrors(nextErrors);
    return Object.keys(nextErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate() || isLoading) return;

    await onSubmit({
      name: name.trim(),
      slug: slug.trim(),
    });
  };

  useEffect(() => {
    if (isOpen) {
      setName("");
      setSlug("");
      setSlugManual(false);
      setErrors({});
      setTimeout(() => nameInputRef.current?.focus(), 50);
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

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose} data-testid="modal-backdrop">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="create-ws-title"
        aria-describedby="create-ws-desc"
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        data-testid="create-workspace-modal"
      >
        <div className="modal-header">
          <div>
            <h2 id="create-ws-title" className="modal-title">
              Create New Workspace
            </h2>
            <p id="create-ws-desc" className="modal-description">
              {programName
                ? `Initialize an operational workspace in program "${programName}".`
                : "Initialize an operational workspace within this program."}
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

        <form onSubmit={handleSubmit} className="modal-form" noValidate>
          {serverError && (
            <div
              className="form-error-banner"
              role="alert"
              data-testid="create-workspace-server-error"
            >
              {serverError}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="ws-name" className="form-label">
              Workspace Name <span className="required-star">*</span>
            </label>
            <input
              ref={nameInputRef}
              id="ws-name"
              type="text"
              className="form-input"
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              placeholder="e.g. Flight Control Core"
              required
              aria-required="true"
              aria-invalid={errors.name ? "true" : "false"}
              aria-describedby={errors.name ? "ws-name-error" : undefined}
              data-testid="ws-name-input"
            />
            {errors.name && (
              <span id="ws-name-error" className="form-error" role="alert">
                {errors.name}
              </span>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="ws-slug" className="form-label">
              Workspace Slug <span className="required-star">*</span>
            </label>
            <input
              id="ws-slug"
              type="text"
              className="form-input font-mono"
              value={slug}
              onChange={(e) => handleSlugChange(e.target.value)}
              placeholder="e.g. flight-control-core"
              required
              aria-required="true"
              aria-invalid={errors.slug ? "true" : "false"}
              aria-describedby={errors.slug ? "ws-slug-error" : "ws-slug-help"}
              data-testid="ws-slug-input"
            />
            <span id="ws-slug-help" className="form-help">
              Unique workspace slug within the parent program.
            </span>
            {errors.slug && (
              <span id="ws-slug-error" className="form-error" role="alert">
                {errors.slug}
              </span>
            )}
          </div>

          <div className="modal-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
              disabled={isLoading}
              data-testid="cancel-ws-btn"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isLoading}
              data-testid="submit-ws-btn"
            >
              {isLoading ? "Creating Workspace..." : "Create Workspace"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
