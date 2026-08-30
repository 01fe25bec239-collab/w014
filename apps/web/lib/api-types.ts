/**
 * API Type Definitions for W-014 Foundation Platform.
 *
 * Directly mirrors the authoritative Rust/utoipa OpenAPI schemas:
 * - ProblemDetails (RFC 9457)
 * - SessionResponse (E03), LogoutResponse (E04), LoginResponse (E01)
 * - ProgramDto (E05/E06/E07), ProgramPage (E05)
 * - WorkspaceDto (E08/E09/E10), WorkspacePage (E08)
 *
 * Frontend remains PRESENTATION + COMMAND CLIENT ONLY.
 */

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  code?: string;
  correlation_id?: string;
}

export interface LoginResponse {
  authorization_url: string;
  state: string;
  expires_at: string;
}

export interface CallbackResponse {
  session_id: string;
  principal_id: string;
  status: string;
  idle_expires_at: string;
  absolute_expires_at: string;
}

export interface SessionResponse {
  session_id: string;
  principal_id: string;
  status: string;
  created_at: string;
  last_seen_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  rotation_counter: number;
  csrf_token?: string;
}

export interface LogoutResponse {
  status: string;
}

export interface CreateProgramDto {
  name: string;
  slug: string;
  description?: string;
}

export interface ProgramDto {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface ProgramPage {
  items: ProgramDto[];
  next_cursor?: string;
  has_more: boolean;
}

export interface CreateWorkspaceDto {
  name: string;
  slug: string;
}

export interface WorkspaceDto {
  id: string;
  program_id: string;
  organization_id: string;
  name: string;
  slug: string;
  current_source_state_id?: string;
  created_at: string;
  updated_at: string;
}

export interface WorkspacePage {
  items: WorkspaceDto[];
  next_cursor?: string;
  has_more: boolean;
}

export interface CreateDocumentDto {
  title: string;
  document_class: string;
}

export interface DocumentDto {
  id: string;
  workspace_id: string;
  title: string;
  document_class: string;
  status: string;
  current_version_id?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
  row_version: number;
}

export interface DocumentPage {
  items: DocumentDto[];
  next_cursor?: string;
  has_more: boolean;
}

export interface DocumentVersionDto {
  id: string;
  document_id: string;
  workspace_id: string;
  version_number: number;
  object_artifact_id: string;
  byte_size: number;
  sha256_hash: string;
  content_type: string;
  original_filename: string;
  trust_state: string;
  submitted_by?: string;
  created_at: string;
}

export interface DocumentVersionPage {
  items: DocumentVersionDto[];
  next_cursor?: string;
  has_more: boolean;
}

export interface CreateUploadIntentDto {
  filename: string;
  media_type: string;
  byte_length: number;
  sha256_b64?: string;
}

export interface PresignedPutDto {
  upload_url: string;
  method: string;
  expires_at: string;
  headers: Record<string, string>;
}

export interface UploadIntentDto {
  id: string;
  workspace_id: string;
  document_id?: string;
  filename: string;
  expected_media_type: string;
  expected_length: number;
  expected_sha256_b64?: string;
  opaque_object_key: string;
  status: string;
  expires_at: string;
  created_at: string;
  presigned_put: PresignedPutDto;
}

export interface UploadFinalizeDto {
  upload_intent_id: string;
  document_id: string;
  document_version_id: string;
  version_number: number;
  object_artifact_id: string;
  quarantine_record_id: string;
  scan_job_id: string;
  status: string;
  trust_state: string;
}

export interface DownloadDto {
  download_url: string;
  expires_at: string;
  content_type: string;
  byte_size: number;
  sha256_hash: string;
  original_filename: string;
}
