import type {
  CreateDocumentDto,
  CreateProgramDto,
  CreateUploadIntentDto,
  CreateWorkspaceDto,
  DocumentDto,
  DocumentPage,
  DocumentVersionDto,
  DocumentVersionPage,
  DownloadDto,
  LoginResponse,
  LogoutResponse,
  ProblemDetails,
  ProgramDto,
  ProgramPage,
  SessionResponse,
  UploadFinalizeDto,
  UploadIntentDto,
  WorkspaceDto,
  WorkspacePage,
} from "./api-types";

/**
 * Standard API error wrapper around RFC 9457 ProblemDetails.
 */
export class ApiClientError extends Error {
  readonly problem: ProblemDetails;
  readonly status: number;

  constructor(problem: ProblemDetails) {
    super(problem.detail || problem.title || `API error (${problem.status})`);
    this.name = "ApiClientError";
    this.problem = problem;
    this.status = problem.status;
  }
}

/**
 * Fallback ProblemDetails generator when backend response cannot be parsed as JSON.
 */
function createFallbackProblem(status: number, statusText: string, path: string): ProblemDetails {
  let typeUri = "urn:w014:error:internal-error";
  let title = "Internal Server Error";
  let code = "INTERNAL_SERVER_ERROR";

  if (status === 401) {
    typeUri = "urn:w014:error:unauthorized";
    title = "Unauthorized";
    code = "UNAUTHORIZED";
  } else if (status === 403) {
    typeUri = "urn:w014:error:forbidden";
    title = "Forbidden";
    code = "FORBIDDEN";
  } else if (status === 404) {
    typeUri = "urn:w014:error:not-found";
    title = "Not Found";
    code = "NOT_FOUND";
  } else if (status === 409) {
    typeUri = "urn:w014:error:conflict";
    title = "Conflict";
    code = "CONFLICT";
  } else if (status >= 400 && status < 500) {
    typeUri = "urn:w014:error:bad-request";
    title = statusText || "Bad Request";
    code = "BAD_REQUEST";
  }

  return {
    type: typeUri,
    title,
    status,
    detail: statusText || `Request to ${path} failed with HTTP status ${status}.`,
    instance: path,
    code,
  };
}

/**
 * Executes an HTTP fetch request against the platform backend, parsing JSON / ProblemDetails.
 */
async function request<T>(
  path: string,
  options: RequestInit & {
    csrfToken?: string;
    idempotencyKey?: string;
  } = {}
): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json, application/problem+json");

  if (options.csrfToken) {
    headers.set("X-W014-CSRF", options.csrfToken);
  }

  if (options.idempotencyKey) {
    headers.set("Idempotency-Key", options.idempotencyKey);
  }

  if (options.body && typeof options.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const fetchOptions: RequestInit = {
    ...options,
    headers,
    credentials: options.credentials || "include",
  };

  let response: Response;
  try {
    response = await fetch(path, fetchOptions);
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : "Network error";
    const networkProblem: ProblemDetails = {
      type: "urn:w014:error:network-error",
      title: "Network Connection Error",
      status: 0,
      detail: `Failed to connect to server: ${errorMsg}`,
      instance: path,
      code: "NETWORK_ERROR",
    };
    throw new ApiClientError(networkProblem);
  }

  if (!response.ok) {
    let problem: ProblemDetails;
    try {
      const json = await response.json();
      if (json && typeof json === "object" && typeof json.status === "number") {
        problem = json as ProblemDetails;
      } else {
        problem = createFallbackProblem(response.status, response.statusText, path);
      }
    } catch {
      problem = createFallbackProblem(response.status, response.statusText, path);
    }
    throw new ApiClientError(problem);
  }

  // If response is 204 No Content or empty
  if (response.status === 204) {
    return {} as T;
  }

  return (await response.json()) as T;
}

/**
 * Authoritative API client for W-014 foundation endpoints (E01, E03-E10).
 * Frontend remains presentation and command client only.
 */
export const apiClient = {
  /**
   * E01: GET /api/v1/auth/login
   */
  async getAuthLogin(format = "json"): Promise<LoginResponse> {
    const query = format ? `?format=${encodeURIComponent(format)}` : "";
    return request<LoginResponse>(`/api/v1/auth/login${query}`);
  },

  /**
   * E03: GET /api/v1/session
   */
  async getSession(): Promise<SessionResponse> {
    return request<SessionResponse>("/api/v1/session");
  },

  /**
   * E04: POST /api/v1/session/logout
   */
  async postLogout(csrfToken?: string): Promise<LogoutResponse> {
    return request<LogoutResponse>("/api/v1/session/logout", {
      method: "POST",
      csrfToken,
    });
  },

  /**
   * E05: GET /api/v1/programs
   */
  async listPrograms(cursor?: string, limit?: number): Promise<ProgramPage> {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit !== undefined) params.set("limit", String(limit));
    const qs = params.toString();
    return request<ProgramPage>(`/api/v1/programs${qs ? `?${qs}` : ""}`);
  },

  /**
   * E06: POST /api/v1/programs
   */
  async createProgram(
    dto: CreateProgramDto,
    csrfToken?: string,
    idempotencyKey?: string
  ): Promise<ProgramDto> {
    return request<ProgramDto>("/api/v1/programs", {
      method: "POST",
      body: JSON.stringify(dto),
      csrfToken,
      idempotencyKey,
    });
  },

  /**
   * E07: GET /api/v1/programs/{program_id}
   */
  async getProgram(programId: string): Promise<ProgramDto> {
    return request<ProgramDto>(`/api/v1/programs/${encodeURIComponent(programId)}`);
  },

  /**
   * E08: GET /api/v1/programs/{program_id}/workspaces
   */
  async listWorkspaces(
    programId: string,
    cursor?: string,
    limit?: number
  ): Promise<WorkspacePage> {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit !== undefined) params.set("limit", String(limit));
    const qs = params.toString();
    return request<WorkspacePage>(
      `/api/v1/programs/${encodeURIComponent(programId)}/workspaces${qs ? `?${qs}` : ""}`
    );
  },

  /**
   * E09: POST /api/v1/programs/{program_id}/workspaces
   */
  async createWorkspace(
    programId: string,
    dto: CreateWorkspaceDto,
    csrfToken?: string,
    idempotencyKey?: string
  ): Promise<WorkspaceDto> {
    return request<WorkspaceDto>(
      `/api/v1/programs/${encodeURIComponent(programId)}/workspaces`,
      {
        method: "POST",
        body: JSON.stringify(dto),
        csrfToken,
        idempotencyKey,
      }
    );
  },

  /**
   * E10: GET /api/v1/workspaces/{workspace_id}
   */
  async getWorkspace(workspaceId: string): Promise<WorkspaceDto> {
    return request<WorkspaceDto>(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}`);
  },

  /**
   * E16: GET /api/v1/workspaces/{workspace_id}/documents
   */
  async listDocuments(
    workspaceId: string,
    cursor?: string,
    limit?: number
  ): Promise<DocumentPage> {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit !== undefined) params.set("limit", String(limit));
    const qs = params.toString();
    return request<DocumentPage>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/documents${qs ? `?${qs}` : ""}`
    );
  },

  /**
   * E17: POST /api/v1/workspaces/{workspace_id}/documents
   */
  async createDocument(
    workspaceId: string,
    dto: CreateDocumentDto,
    csrfToken?: string,
    idempotencyKey?: string
  ): Promise<DocumentDto> {
    return request<DocumentDto>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/documents`,
      {
        method: "POST",
        body: JSON.stringify(dto),
        csrfToken,
        idempotencyKey,
      }
    );
  },

  /**
   * E18: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}
   */
  async getDocument(
    workspaceId: string,
    documentId: string
  ): Promise<DocumentDto> {
    return request<DocumentDto>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(documentId)}`
    );
  },

  /**
   * E19: GET /api/v1/workspaces/{workspace_id}/documents/{document_id}/versions
   */
  async listDocumentVersions(
    workspaceId: string,
    documentId: string,
    cursor?: string,
    limit?: number
  ): Promise<DocumentVersionPage> {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit !== undefined) params.set("limit", String(limit));
    const qs = params.toString();
    return request<DocumentVersionPage>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(documentId)}/versions${qs ? `?${qs}` : ""}`
    );
  },

  /**
   * E20: POST /api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents
   */
  async createUploadIntent(
    workspaceId: string,
    documentId: string,
    dto: CreateUploadIntentDto,
    csrfToken?: string,
    idempotencyKey?: string
  ): Promise<UploadIntentDto> {
    return request<UploadIntentDto>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/documents/${encodeURIComponent(documentId)}/upload-intents`,
      {
        method: "POST",
        body: JSON.stringify(dto),
        csrfToken,
        idempotencyKey,
      }
    );
  },

  /**
   * E21: POST /api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize
   */
  async finalizeUploadIntent(
    workspaceId: string,
    intentId: string,
    csrfToken?: string,
    idempotencyKey?: string
  ): Promise<UploadFinalizeDto> {
    return request<UploadFinalizeDto>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/upload-intents/${encodeURIComponent(intentId)}/finalize`,
      {
        method: "POST",
        csrfToken,
        idempotencyKey,
      }
    );
  },

  /**
   * E22: GET /api/v1/workspaces/{workspace_id}/document-versions/{version_id}
   */
  async getDocumentVersion(
    workspaceId: string,
    versionId: string
  ): Promise<DocumentVersionDto> {
    return request<DocumentVersionDto>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/document-versions/${encodeURIComponent(versionId)}`
    );
  },

  /**
   * E23: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept
   */
  async acceptVersion(
    workspaceId: string,
    versionId: string,
    rowVersion: number,
    csrfToken?: string,
    idempotencyKey?: string
  ): Promise<DocumentDto> {
    const headers: Record<string, string> = {
      "If-Match": `"${rowVersion}"`,
    };
    return request<DocumentDto>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/document-versions/${encodeURIComponent(versionId)}/accept`,
      {
        method: "POST",
        headers,
        csrfToken,
        idempotencyKey,
      }
    );
  },

  /**
   * E24: POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download
   */
  async downloadVersion(
    workspaceId: string,
    versionId: string,
    csrfToken?: string
  ): Promise<DownloadDto> {
    return request<DownloadDto>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/document-versions/${encodeURIComponent(versionId)}/download`,
      {
        method: "POST",
        csrfToken,
      }
    );
  },

  /**
   * Helper for direct object-storage bytes upload using presigned contract.
   * Client-side byte transfer only. Does NOT imply document trust.
   */
  async uploadFileToStorage(
    uploadUrl: string,
    method: string,
    headers: Record<string, string>,
    body: BodyInit | Blob | File | ArrayBuffer
  ): Promise<void> {
    const reqHeaders = new Headers(headers);
    const response = await fetch(uploadUrl, {
      method: method || "PUT",
      headers: reqHeaders,
      body,
    });
    if (!response.ok) {
      throw new Error(`Direct storage upload failed with HTTP status ${response.status}`);
    }
  },
};
