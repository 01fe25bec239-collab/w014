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
