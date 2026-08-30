"use client";

import React, { useEffect, useRef, useState } from "react";
import type { CreateDocumentDto } from "@/lib/api-types";

export interface CreateDocumentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (dto: CreateDocumentDto) => Promise<void>;
  isLoading?: boolean;
  serverError?: string | null;
}

export function CreateDocumentModal({
  isOpen,
  onClose,
  onSubmit,
  isLoading = false,
  serverError = null,
}: CreateDocumentModalProps) {
  const [title, setTitle] = useState("");
  const [documentClass, setDocumentClass] = useState<string>("pdf");
  const [errors, setErrors] = useState<{ title?: string }>({});

  const titleInputRef = useRef<HTMLInputElement>(null);

  const validate = (): boolean => {
    const nextErrors: { title?: string } = {};
    const trimmed = title.trim();
    if (!trimmed) {
      nextErrors.title = "Document title is required.";
    } else if (trimmed.length > 512) {
      nextErrors.title = "Document title must not exceed 512 characters.";
    }

    setErrors(nextErrors);
    return Object.keys(nextErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate() || isLoading) return;

    await onSubmit({
      title: title.trim(),
      document_class: documentClass,
    });
  };

  useEffect(() => {
    if (isOpen) {
      setTitle("");
      setDocumentClass("pdf");
      setErrors({});
      setTimeout(() => titleInputRef.current?.focus(), 50);
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
        aria-labelledby="create-doc-title"
        aria-describedby="create-doc-desc"
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        data-testid="create-document-modal"
      >
        <div className="modal-header">
          <div>
            <h2 id="create-doc-title" className="modal-title">
              Create Logical Document
            </h2>
            <p id="create-doc-desc" className="modal-description">
              Create a new versioned document record inside this workspace.
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
              data-testid="create-document-server-error"
            >
              {serverError}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="doc-title" className="form-label">
              Document Title <span className="required-star">*</span>
            </label>
            <input
              ref={titleInputRef}
              id="doc-title"
              type="text"
              className="form-input"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Flight Control Subsystem Specification"
              required
              aria-required="true"
              aria-invalid={errors.title ? "true" : "false"}
              aria-describedby={errors.title ? "doc-title-error" : undefined}
              data-testid="document-title-input"
            />
            {errors.title && (
              <span id="doc-title-error" className="form-error" role="alert">
                {errors.title}
              </span>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="doc-class" className="form-label">
              Document Class <span className="required-star">*</span>
            </label>
            <select
              id="doc-class"
              className="form-input"
              value={documentClass}
              onChange={(e) => setDocumentClass(e.target.value)}
              data-testid="document-class-select"
            >
              <option value="pdf">PDF (Portable Document Format)</option>
              <option value="docx">DOCX (Office OpenXML Document)</option>
            </select>
            <span className="form-help">
              Frozen format support: PDF and DOCX only.
            </span>
          </div>

          <div className="modal-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
              disabled={isLoading}
              data-testid="cancel-document-btn"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isLoading}
              data-testid="submit-document-btn"
            >
              {isLoading ? "Creating Document..." : "Create Document"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
