"use client";

import React, { useEffect, useRef, useState } from "react";
import type { CreateProgramDto } from "@/lib/api-types";

export interface CreateProgramModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (dto: CreateProgramDto) => Promise<void>;
  isLoading?: boolean;
  serverError?: string | null;
}

export function CreateProgramModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading = false,
  serverError = null,
}: CreateProgramModalProps) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [description, setDescription] = useState("");
  const [slugManual, setSlugManual] = useState(false);
  const [errors, setErrors] = useState<{ name?: string; slug?: string }>({});

  const nameInputRef = useRef<HTMLInputElement>(null);

  // Auto-slugify name if not manually edited
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
      nextErrors.name = "Program name is required.";
    }
    if (!slug.trim()) {
      nextErrors.slug = "Program slug is required.";
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
      description: description.trim() || undefined,
    });
  };

  // Reset and focus when opened
  useEffect(() => {
    if (isOpen) {
      setName("");
      setSlug("");
      setDescription("");
      setSlugManual(false);
      setErrors({});
      setTimeout(() => nameInputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Escape key handler
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
        aria-labelledby="create-program-title"
        aria-describedby="create-program-desc"
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        data-testid="create-program-modal"
      >
        <div className="modal-header">
          <div>
            <h2 id="create-program-title" className="modal-title">
              Create New Program
            </h2>
            <p id="create-program-desc" className="modal-description">
              Initialize a new organizational program boundary for workspaces.
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
              data-testid="create-program-server-error"
            >
              {serverError}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="program-name" className="form-label">
              Program Name <span className="required-star">*</span>
            </label>
            <input
              ref={nameInputRef}
              id="program-name"
              type="text"
              className="form-input"
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              placeholder="e.g. NextGen Avionics Platform"
              required
              aria-required="true"
              aria-invalid={errors.name ? "true" : "false"}
              aria-describedby={errors.name ? "program-name-error" : undefined}
              data-testid="program-name-input"
            />
            {errors.name && (
              <span id="program-name-error" className="form-error" role="alert">
                {errors.name}
              </span>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="program-slug" className="form-label">
              Program Slug <span className="required-star">*</span>
            </label>
            <input
              id="program-slug"
              type="text"
              className="form-input font-mono"
              value={slug}
              onChange={(e) => handleSlugChange(e.target.value)}
              placeholder="e.g. nextgen-avionics"
              required
              aria-required="true"
              aria-invalid={errors.slug ? "true" : "false"}
              aria-describedby={errors.slug ? "program-slug-error" : "program-slug-help"}
              data-testid="program-slug-input"
            />
            <span id="program-slug-help" className="form-help">
              Unique identifier within organization (lowercase letters, numbers, and hyphens).
            </span>
            {errors.slug && (
              <span id="program-slug-error" className="form-error" role="alert">
                {errors.slug}
              </span>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="program-desc" className="form-label">
              Description <span className="optional-tag">(Optional)</span>
            </label>
            <textarea
              id="program-desc"
              className="form-textarea"
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Scope, verification requirements, and architectural lineage."
              data-testid="program-desc-input"
            />
          </div>

          <div className="modal-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
              disabled={isLoading}
              data-testid="cancel-program-btn"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isLoading}
              data-testid="submit-program-btn"
            >
              {isLoading ? "Creating Program..." : "Create Program"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
