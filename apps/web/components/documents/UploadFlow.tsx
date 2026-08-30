"use client";

import React, { useState, useRef, useEffect } from "react";
import { apiClient, ApiClientError } from "@/lib/api-client";
import type {
  CreateDocumentDto,
  DocumentDto,
  ProblemDetails,
  UploadFinalizeDto,
} from "@/lib/api-types";
import { ProblemNotice } from "@/components/ui/ProblemNotice";

export interface UploadFlowProps {
  workspaceId: string;
  initialDocumentId?: string;
  documents?: DocumentDto[];
  csrfToken?: string | null;
  onSuccess?: (result: UploadFinalizeDto) => void;
}

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MiB limit

export function UploadFlow({
  workspaceId,
  initialDocumentId,
  documents = [],
  csrfToken,
  onSuccess,
}: UploadFlowProps) {
  // Target Document Selection
  const [targetMode, setTargetMode] = useState<"new" | "existing">(
    initialDocumentId ? "existing" : "new"
  );
  const [selectedDocId, setSelectedDocId] = useState<string>(initialDocumentId || "");
  const [newTitle, setNewTitle] = useState<string>("");
  const [newDocClass, setNewDocClass] = useState<string>("pdf");

  // File Selection
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Attestation
  const [attestationChecked, setAttestationChecked] = useState(false);

  // Flow State
  const [step, setStep] = useState<"input" | "creating_doc" | "intent" | "transferring" | "finalizing" | "completed">("input");
  const [error, setError] = useState<ProblemDetails | null>(null);
  const [completedResult, setCompletedResult] = useState<UploadFinalizeDto | null>(null);

  useEffect(() => {
    if (initialDocumentId) {
      setTargetMode("existing");
      setSelectedDocId(initialDocumentId);
    }
  }, [initialDocumentId]);

  const handleFileSelect = (file: File) => {
    setFileError(null);
    setError(null);

    // Bounded local validation for presentation feedback
    if (file.size > MAX_FILE_SIZE) {
      setFileError(`File size (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds the 100 MiB maximum limit.`);
      setSelectedFile(null);
      return;
    }

    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext !== "pdf" && ext !== "docx") {
      setFileError("Unsupported format. Only PDF (.pdf) and Word DOCX (.docx) documents are permitted.");
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    if (!newTitle && targetMode === "new") {
      // Pre-fill title without extension
      const nameWithoutExt = file.name.replace(/\.[^/.]+$/, "");
      setNewTitle(nameWithoutExt);
      setNewDocClass(ext === "docx" ? "docx" : "pdf");
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleSubmitUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setFileError(null);

    if (!selectedFile) {
      setFileError("Please select a file to upload.");
      return;
    }

    if (!attestationChecked) {
      setFileError("Mandatory portfolio data boundary attestation is required.");
      return;
    }

    let targetDocId = selectedDocId;

    try {
      // Step A: Create logical document if needed
      if (targetMode === "new") {
        if (!newTitle.trim()) {
          setFileError("Document title is required.");
          return;
        }
        setStep("creating_doc");
        const docDto: CreateDocumentDto = {
          title: newTitle.trim(),
          document_class: newDocClass,
        };
        const idempKeyDoc = `doc_create_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
        const createdDoc = await apiClient.createDocument(
          workspaceId,
          docDto,
          csrfToken || undefined,
          idempKeyDoc
        );
        targetDocId = createdDoc.id;
      } else if (!targetDocId) {
        setFileError("Please select an existing document from the workspace.");
        return;
      }

      // Step B: Create Upload Intent
      setStep("intent");
      const mediaType = selectedFile.name.endsWith(".docx")
        ? "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        : "application/pdf";

      const idempKeyIntent = `intent_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
      const intentDto = await apiClient.createUploadIntent(
        workspaceId,
        targetDocId,
        {
          filename: selectedFile.name,
          media_type: mediaType,
          byte_length: selectedFile.size,
        },
        csrfToken || undefined,
        idempKeyIntent
      );

      // Step C: Direct storage byte transfer
      setStep("transferring");
      await apiClient.uploadFileToStorage(
        intentDto.presigned_put.upload_url,
        intentDto.presigned_put.method,
        intentDto.presigned_put.headers,
        selectedFile
      );

      // Step D: Finalize Upload Intent
      setStep("finalizing");
      const idempKeyFinalize = `fin_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
      const finalizeDto = await apiClient.finalizeUploadIntent(
        workspaceId,
        intentDto.id,
        csrfToken || undefined,
        idempKeyFinalize
      );

      setCompletedResult(finalizeDto);
      setStep("completed");
      if (onSuccess) {
        onSuccess(finalizeDto);
      }
    } catch (err: unknown) {
      setStep("input");
      if (err instanceof ApiClientError) {
        setError(err.problem);
      } else {
        const errorMsg = err instanceof Error ? err.message : "Upload execution failed.";
        setError({
          type: "urn:w014:error:upload-failed",
          title: "Upload Failed",
          status: 0,
          detail: errorMsg,
        });
      }
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setAttestationChecked(false);
    setCompletedResult(null);
    setStep("input");
    setError(null);
    setFileError(null);
    if (!initialDocumentId) {
      setNewTitle("");
    }
  };

  return (
    <div className="upload-flow-container" data-testid="upload-flow-container">
      {error && (
        <ProblemNotice
          problem={error}
          onRetry={() => {
            setError(null);
          }}
          className="mb-4"
        />
      )}

      {step === "completed" && completedResult ? (
        <div className="upload-card" data-testid="upload-completed-card">
          <div className="upload-card-title">
            <span style={{ color: "#22c55e" }}>✓</span>
            <h2>Upload Complete — Security Checks Pending</h2>
          </div>

          <div className="trust-callout trust-callout-pending" data-testid="quarantine-pending-callout">
            <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", fontWeight: 700 }}>
              <span aria-hidden="true">🔒</span>
              <span>Quarantined / Processing</span>
            </div>
            <p>
              Document bytes were successfully transferred and placed into isolated quarantine storage.
              Antivirus scan and sandboxed extraction jobs are enqueued in Rust core.
            </p>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "var(--space-1)" }}>
              Authoritative Trust Boundary: Transferring bytes to object storage does NOT grant trusted or ready status.
              Document validity will be determined only after security gates pass.
            </p>
          </div>

          <ul className="panel-item-list" style={{ fontSize: "0.8125rem" }}>
            <li className="panel-item">
              <span className="panel-item-key">Document ID:</span>
              <span className="panel-item-value font-mono" data-testid="completed-doc-id">
                {completedResult.document_id}
              </span>
            </li>
            <li className="panel-item">
              <span className="panel-item-key">Version Ordinal:</span>
              <span className="panel-item-value font-mono" data-testid="completed-version-number">
                v{completedResult.version_number}
              </span>
            </li>
            <li className="panel-item">
              <span className="panel-item-key">Version ID:</span>
              <span className="panel-item-value font-mono" data-testid="completed-version-id">
                {completedResult.document_version_id}
              </span>
            </li>
            <li className="panel-item">
              <span className="panel-item-key">Quarantine Record ID:</span>
              <span className="panel-item-value font-mono" data-testid="completed-quarantine-id">
                {completedResult.quarantine_record_id}
              </span>
            </li>
            <li className="panel-item">
              <span className="panel-item-key">Scan Job ID:</span>
              <span className="panel-item-value font-mono" data-testid="completed-job-id">
                {completedResult.scan_job_id}
              </span>
            </li>
            <li className="panel-item">
              <span className="panel-item-key">Initial Trust State:</span>
              <span className="trust-state-badge" data-state={completedResult.trust_state.toLowerCase()} data-testid="completed-trust-state">
                {completedResult.trust_state}
              </span>
            </li>
          </ul>

          <div style={{ display: "flex", gap: "var(--space-3)", marginTop: "var(--space-2)" }}>
            <a
              href={`/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(completedResult.document_id)}`}
              className="btn btn-primary"
              data-testid="view-document-btn"
            >
              View Document &amp; History
            </a>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleReset}
              data-testid="upload-another-btn"
            >
              Upload Another Document
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmitUpload} className="upload-card" noValidate data-testid="upload-form">
          <div className="upload-step-header">
            <span className="upload-step-number">1</span>
            <h2 className="upload-card-title">Target Logical Document</h2>
          </div>

          {!initialDocumentId && (
            <div style={{ display: "flex", gap: "var(--space-4)", marginBottom: "var(--space-2)" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", cursor: "pointer", fontSize: "0.875rem" }}>
                <input
                  type="radio"
                  name="targetMode"
                  value="new"
                  checked={targetMode === "new"}
                  onChange={() => setTargetMode("new")}
                  data-testid="target-mode-new"
                />
                <span>Create New Logical Document</span>
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", cursor: "pointer", fontSize: "0.875rem" }}>
                <input
                  type="radio"
                  name="targetMode"
                  value="existing"
                  checked={targetMode === "existing"}
                  onChange={() => setTargetMode("existing")}
                  data-testid="target-mode-existing"
                />
                <span>Add Version to Existing Document</span>
              </label>
            </div>
          )}

          {targetMode === "new" ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}>
              <div className="form-group">
                <label htmlFor="upload-doc-title" className="form-label">
                  Document Title <span className="required-star">*</span>
                </label>
                <input
                  id="upload-doc-title"
                  type="text"
                  className="form-input"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Avionics Software Architecture Specification"
                  required
                  data-testid="new-doc-title-input"
                />
              </div>

              <div className="form-group">
                <label htmlFor="upload-doc-class" className="form-label">
                  Document Class <span className="required-star">*</span>
                </label>
                <select
                  id="upload-doc-class"
                  className="form-input"
                  value={newDocClass}
                  onChange={(e) => setNewDocClass(e.target.value)}
                  data-testid="new-doc-class-select"
                >
                  <option value="pdf">PDF (Portable Document Format)</option>
                  <option value="docx">DOCX (Office OpenXML Document)</option>
                </select>
              </div>
            </div>
          ) : (
            <div className="form-group">
              <label htmlFor="existing-doc-select" className="form-label">
                Select Workspace Document <span className="required-star">*</span>
              </label>
              <select
                id="existing-doc-select"
                className="form-input"
                value={selectedDocId}
                onChange={(e) => setSelectedDocId(e.target.value)}
                data-testid="existing-doc-select"
              >
                <option value="">-- Choose an existing document --</option>
                {documents.map((doc) => (
                  <option key={doc.id} value={doc.id}>
                    {doc.title} ({doc.document_class.toUpperCase()})
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="upload-step-header" style={{ marginTop: "var(--space-3)" }}>
            <span className="upload-step-number">2</span>
            <h2 className="upload-card-title">Select Local File</h2>
          </div>

          <div
            className={`upload-dropzone ${isDragOver ? "dragover" : ""}`}
            onClick={() => fileInputRef.current?.click()}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            data-testid="upload-dropzone"
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                fileInputRef.current?.click();
              }
            }}
            aria-label="Click or drag and drop file to upload"
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pdf,.docx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
              className="upload-dropzone-input"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileSelect(e.target.files[0]);
                }
              }}
              data-testid="file-input"
            />
            <div style={{ fontSize: "2rem" }} aria-hidden="true">📁</div>
            {selectedFile ? (
              <div>
                <p className="font-semibold text-primary" data-testid="selected-file-name">
                  {selectedFile.name}
                </p>
                <p className="text-muted text-xs font-mono">
                  {(selectedFile.size / 1024).toFixed(1)} KB • {selectedFile.type || "application/octet-stream"}
                </p>
              </div>
            ) : (
              <div>
                <p className="font-semibold text-primary">
                  Click to browse or drop PDF / DOCX file here
                </p>
                <p className="text-muted text-xs">
                  Max file size: 100 MiB. Strict format enforcement.
                </p>
              </div>
            )}
          </div>

          {fileError && (
            <div className="form-error" role="alert" data-testid="file-validation-error">
              {fileError}
            </div>
          )}

          <div className="upload-step-header" style={{ marginTop: "var(--space-3)" }}>
            <span className="upload-step-number">3</span>
            <h2 className="upload-card-title">Portfolio Data Boundary Attestation</h2>
          </div>

          <div className="attestation-box" data-testid="attestation-card">
            <input
              id="attestation-check"
              type="checkbox"
              style={{ marginTop: "3px" }}
              checked={attestationChecked}
              onChange={(e) => setAttestationChecked(e.target.checked)}
              required
              data-testid="attestation-checkbox"
            />
            <label htmlFor="attestation-check">
              <strong>Mandatory Portfolio-Data Attestation:</strong> I confirm that this uploaded artifact contains solely public, synthetic, or sanitized non-CUI defense and aerospace engineering data, consistent with W-014 platform data governance.
            </label>
          </div>

          <div className="modal-actions" style={{ marginTop: "var(--space-4)" }}>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={!selectedFile || !attestationChecked || step !== "input"}
              data-testid="submit-upload-btn"
            >
              {step === "creating_doc" && "Creating Document..."}
              {step === "intent" && "Registering Upload Intent..."}
              {step === "transferring" && "Transferring Bytes to Storage..."}
              {step === "finalizing" && "Finalizing & Quarantine..."}
              {step === "input" && "Start Secure Upload"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
