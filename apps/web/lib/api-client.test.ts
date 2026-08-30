import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiClient, ApiClientError } from "./api-client";
import type { CreateProgramDto, CreateWorkspaceDto } from "./api-types";

describe("apiClient", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("E01: getAuthLogin sends correct request and query params", async () => {
    const mockResponse = {
      authorization_url: "https://auth.example.com/oauth2/auth",
      state: "state_123",
      expires_at: "2026-08-19T20:00:00Z",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockResponse,
    } as unknown as Response);

    const res = await apiClient.getAuthLogin("json");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/auth/login?format=json",
      expect.objectContaining({
        credentials: "include",
      })
    );
    expect(res).toEqual(mockResponse);
  });

  it("E03: getSession sends GET /api/v1/session", async () => {
    const mockSession = {
      session_id: "sess_1",
      principal_id: "princ_1",
      status: "active",
      created_at: "2026-08-19T10:00:00Z",
      last_seen_at: "2026-08-19T10:05:00Z",
      idle_expires_at: "2026-08-19T11:00:00Z",
      absolute_expires_at: "2026-08-19T18:00:00Z",
      rotation_counter: 1,
      csrf_token: "csrf_token_abc",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockSession,
    } as unknown as Response);

    const res = await apiClient.getSession();
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/session",
      expect.objectContaining({
        credentials: "include",
      })
    );
    expect(res).toEqual(mockSession);
  });

  it("E04: postLogout sends POST /api/v1/session/logout with X-W014-CSRF", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: "logged_out" }),
    } as unknown as Response);

    const res = await apiClient.postLogout("csrf_xyz");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/session/logout",
      expect.objectContaining({
        method: "POST",
        headers: expect.any(Headers),
      })
    );

    const callHeaders = (vi.mocked(global.fetch).mock.calls[0][1]?.headers) as Headers;
    expect(callHeaders.get("X-W014-CSRF")).toBe("csrf_xyz");
    expect(res).toEqual({ status: "logged_out" });
  });

  it("E05: listPrograms passes pagination parameters", async () => {
    const mockPage = {
      items: [],
      next_cursor: "cursor_1",
      has_more: true,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockPage,
    } as unknown as Response);

    const res = await apiClient.listPrograms("cursor_0", 25);
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/programs?cursor=cursor_0&limit=25",
      expect.any(Object)
    );
    expect(res).toEqual(mockPage);
  });

  it("E06: createProgram sends POST /api/v1/programs with CSRF and idempotency key", async () => {
    const dto: CreateProgramDto = {
      name: "Avionics Core",
      slug: "avionics-core",
      description: "Flight control systems",
    };

    const mockProgram = {
      id: "prog_1",
      organization_id: "org_1",
      name: dto.name,
      slug: dto.slug,
      description: dto.description,
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => mockProgram,
    } as unknown as Response);

    const res = await apiClient.createProgram(dto, "csrf_123", "idemp_abc");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/programs",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(dto),
      })
    );

    const callHeaders = (vi.mocked(global.fetch).mock.calls[0][1]?.headers) as Headers;
    expect(callHeaders.get("X-W014-CSRF")).toBe("csrf_123");
    expect(callHeaders.get("Idempotency-Key")).toBe("idemp_abc");
    expect(callHeaders.get("Content-Type")).toBe("application/json");
    expect(res).toEqual(mockProgram);
  });

  it("E07: getProgram sends GET /api/v1/programs/{program_id}", async () => {
    const mockProgram = {
      id: "prog_1",
      organization_id: "org_1",
      name: "Avionics Core",
      slug: "avionics-core",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockProgram,
    } as unknown as Response);

    const res = await apiClient.getProgram("prog_1");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/programs/prog_1",
      expect.any(Object)
    );
    expect(res).toEqual(mockProgram);
  });

  it("E08: listWorkspaces sends GET /api/v1/programs/{program_id}/workspaces", async () => {
    const mockPage = {
      items: [],
      has_more: false,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockPage,
    } as unknown as Response);

    const res = await apiClient.listWorkspaces("prog_1");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/programs/prog_1/workspaces",
      expect.any(Object)
    );
    expect(res).toEqual(mockPage);
  });

  it("E09: createWorkspace sends POST /api/v1/programs/{program_id}/workspaces", async () => {
    const dto: CreateWorkspaceDto = {
      name: "Flight Control",
      slug: "flight-control",
    };

    const mockWs = {
      id: "ws_1",
      program_id: "prog_1",
      organization_id: "org_1",
      name: dto.name,
      slug: dto.slug,
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => mockWs,
    } as unknown as Response);

    const res = await apiClient.createWorkspace("prog_1", dto, "csrf_ws");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/programs/prog_1/workspaces",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(dto),
      })
    );
    expect(res).toEqual(mockWs);
  });

  it("E10: getWorkspace sends GET /api/v1/workspaces/{workspace_id}", async () => {
    const mockWs = {
      id: "ws_1",
      program_id: "prog_1",
      organization_id: "org_1",
      name: "Flight Control",
      slug: "flight-control",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockWs,
    } as unknown as Response);

    const res = await apiClient.getWorkspace("ws_1");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1",
      expect.any(Object)
    );
    expect(res).toEqual(mockWs);
  });

  it("parses ProblemDetails on 400 Bad Request error", async () => {
    const problemPayload = {
      type: "urn:w014:error:bad-request",
      title: "Bad Request",
      status: 400,
      detail: "Invalid slug format",
      instance: "/api/v1/programs",
      code: "BAD_REQUEST",
      correlation_id: "corr_123",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      json: async () => problemPayload,
    } as unknown as Response);

    try {
      await apiClient.createProgram({ name: "Bad", slug: "INVALID!" });
      expect.fail("Expected ApiClientError to be thrown");
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(ApiClientError);
      const apiErr = err as ApiClientError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.problem).toEqual(problemPayload);
      expect(apiErr.message).toBe("Invalid slug format");
    }
  });

  it("generates fallback ProblemDetails when non-JSON error returned", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => {
        throw new Error("HTML body");
      },
    } as unknown as Response);

    try {
      await apiClient.getWorkspace("non_existent");
      expect.fail("Expected ApiClientError");
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(ApiClientError);
      const apiErr = err as ApiClientError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.problem.title).toBe("Not Found");
      expect(apiErr.problem.code).toBe("NOT_FOUND");
    }
  });

  it("handles network failure gracefully", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Connection refused"));

    try {
      await apiClient.getSession();
      expect.fail("Expected ApiClientError");
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(ApiClientError);
      const apiErr = err as ApiClientError;
      expect(apiErr.status).toBe(0);
      expect(apiErr.problem.code).toBe("NETWORK_ERROR");
      expect(apiErr.problem.detail).toContain("Connection refused");
    }
  });

  it("E16: listDocuments sends GET /api/v1/workspaces/{workspace_id}/documents with cursor and limit", async () => {
    const mockPage = {
      items: [
        {
          id: "doc_1",
          workspace_id: "ws_1",
          title: "Architecture Spec",
          document_class: "pdf",
          status: "active",
          created_at: "2026-08-30T10:00:00Z",
          updated_at: "2026-08-30T10:00:00Z",
          row_version: 1,
        },
      ],
      next_cursor: "cur_2",
      has_more: true,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockPage,
    } as unknown as Response);

    const res = await apiClient.listDocuments("ws_1", "cur_1", 20);
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/documents?cursor=cur_1&limit=20",
      expect.any(Object)
    );
    expect(res).toEqual(mockPage);
  });

  it("E17: createDocument sends POST /api/v1/workspaces/{workspace_id}/documents with CSRF and Idempotency-Key", async () => {
    const mockDoc = {
      id: "doc_1",
      workspace_id: "ws_1",
      title: "Requirements Doc",
      document_class: "docx",
      status: "active",
      created_at: "2026-08-30T10:00:00Z",
      updated_at: "2026-08-30T10:00:00Z",
      row_version: 1,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => mockDoc,
    } as unknown as Response);

    const res = await apiClient.createDocument(
      "ws_1",
      { title: "Requirements Doc", document_class: "docx" },
      "csrf_token",
      "idemp_key_1"
    );
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/documents",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ title: "Requirements Doc", document_class: "docx" }),
      })
    );
    const headers = vi.mocked(global.fetch).mock.calls[0][1]?.headers as Headers;
    expect(headers.get("X-W014-CSRF")).toBe("csrf_token");
    expect(headers.get("Idempotency-Key")).toBe("idemp_key_1");
    expect(res).toEqual(mockDoc);
  });

  it("E18: getDocument sends GET /api/v1/workspaces/{workspace_id}/documents/{document_id}", async () => {
    const mockDoc = {
      id: "doc_1",
      workspace_id: "ws_1",
      title: "System Spec",
      document_class: "pdf",
      status: "active",
      created_at: "2026-08-30T10:00:00Z",
      updated_at: "2026-08-30T10:00:00Z",
      row_version: 1,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockDoc,
    } as unknown as Response);

    const res = await apiClient.getDocument("ws_1", "doc_1");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/documents/doc_1",
      expect.any(Object)
    );
    expect(res).toEqual(mockDoc);
  });

  it("E19: listDocumentVersions sends GET /api/v1/workspaces/{workspace_id}/documents/{document_id}/versions", async () => {
    const mockPage = {
      items: [
        {
          id: "ver_1",
          document_id: "doc_1",
          workspace_id: "ws_1",
          version_number: 1,
          object_artifact_id: "art_1",
          byte_size: 1024,
          sha256_hash: "abcd",
          content_type: "application/pdf",
          original_filename: "doc.pdf",
          trust_state: "pending",
          created_at: "2026-08-30T10:00:00Z",
        },
      ],
      has_more: false,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockPage,
    } as unknown as Response);

    const res = await apiClient.listDocumentVersions("ws_1", "doc_1");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/documents/doc_1/versions",
      expect.any(Object)
    );
    expect(res).toEqual(mockPage);
  });

  it("E20: createUploadIntent sends POST /api/v1/workspaces/{workspace_id}/documents/{document_id}/upload-intents", async () => {
    const mockIntent = {
      id: "intent_1",
      workspace_id: "ws_1",
      document_id: "doc_1",
      filename: "doc.pdf",
      expected_media_type: "application/pdf",
      expected_length: 2048,
      opaque_object_key: "k1",
      status: "pending",
      expires_at: "2026-08-30T10:10:00Z",
      created_at: "2026-08-30T10:00:00Z",
      presigned_put: {
        upload_url: "https://storage.example.com/put",
        method: "PUT",
        expires_at: "2026-08-30T10:10:00Z",
        headers: { "Content-Type": "application/pdf" },
      },
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => mockIntent,
    } as unknown as Response);

    const res = await apiClient.createUploadIntent(
      "ws_1",
      "doc_1",
      { filename: "doc.pdf", media_type: "application/pdf", byte_length: 2048 },
      "csrf_token",
      "idemp_intent"
    );
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/documents/doc_1/upload-intents",
      expect.objectContaining({
        method: "POST",
      })
    );
    expect(res).toEqual(mockIntent);
  });

  it("E21: finalizeUploadIntent sends POST /api/v1/workspaces/{workspace_id}/upload-intents/{intent_id}/finalize", async () => {
    const mockFinalize = {
      upload_intent_id: "intent_1",
      document_id: "doc_1",
      document_version_id: "ver_1",
      version_number: 1,
      object_artifact_id: "art_1",
      quarantine_record_id: "q_1",
      scan_job_id: "job_1",
      status: "quarantined_processing",
      trust_state: "pending",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 202,
      json: async () => mockFinalize,
    } as unknown as Response);

    const res = await apiClient.finalizeUploadIntent("ws_1", "intent_1", "csrf_token", "idemp_fin");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/upload-intents/intent_1/finalize",
      expect.objectContaining({
        method: "POST",
      })
    );
    expect(res).toEqual(mockFinalize);
  });

  it("E22: getDocumentVersion sends GET /api/v1/workspaces/{workspace_id}/document-versions/{version_id}", async () => {
    const mockVersion = {
      id: "ver_1",
      document_id: "doc_1",
      workspace_id: "ws_1",
      version_number: 1,
      object_artifact_id: "art_1",
      byte_size: 1024,
      sha256_hash: "hash123",
      content_type: "application/pdf",
      original_filename: "test.pdf",
      trust_state: "pending",
      created_at: "2026-08-30T10:00:00Z",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockVersion,
    } as unknown as Response);

    const res = await apiClient.getDocumentVersion("ws_1", "ver_1");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/document-versions/ver_1",
      expect.any(Object)
    );
    expect(res).toEqual(mockVersion);
  });

  it("E23: acceptVersion sends POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/accept with If-Match", async () => {
    const mockDoc = {
      id: "doc_1",
      workspace_id: "ws_1",
      title: "System Spec",
      document_class: "pdf",
      status: "active",
      current_version_id: "ver_1",
      created_at: "2026-08-30T10:00:00Z",
      updated_at: "2026-08-30T10:05:00Z",
      row_version: 2,
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockDoc,
    } as unknown as Response);

    const res = await apiClient.acceptVersion("ws_1", "ver_1", 1, "csrf_token", "idemp_acc");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/document-versions/ver_1/accept",
      expect.objectContaining({
        method: "POST",
      })
    );
    const headers = vi.mocked(global.fetch).mock.calls[0][1]?.headers as Headers;
    expect(headers.get("If-Match")).toBe('"1"');
    expect(headers.get("X-W014-CSRF")).toBe("csrf_token");
    expect(headers.get("Idempotency-Key")).toBe("idemp_acc");
    expect(res).toEqual(mockDoc);
  });

  it("E24: downloadVersion sends POST /api/v1/workspaces/{workspace_id}/document-versions/{version_id}/download", async () => {
    const mockDownload = {
      download_url: "https://storage.example.com/get/file.pdf?sig=xyz",
      expires_at: "2026-08-30T10:05:00Z",
      content_type: "application/pdf",
      byte_size: 1024,
      sha256_hash: "hash_abc",
      original_filename: "file.pdf",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockDownload,
    } as unknown as Response);

    const res = await apiClient.downloadVersion("ws_1", "ver_1", "csrf_token");
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/workspaces/ws_1/document-versions/ver_1/download",
      expect.objectContaining({
        method: "POST",
      })
    );
    const headers = vi.mocked(global.fetch).mock.calls[0][1]?.headers as Headers;
    expect(headers.get("X-W014-CSRF")).toBe("csrf_token");
    expect(res).toEqual(mockDownload);
  });

  it("uploadFileToStorage executes direct storage PUT with headers", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
    } as unknown as Response);

    const blob = new Blob(["hello"], { type: "application/pdf" });
    await apiClient.uploadFileToStorage(
      "https://s3.example.com/upload",
      "PUT",
      { "Content-Type": "application/pdf" },
      blob
    );

    expect(global.fetch).toHaveBeenCalledWith(
      "https://s3.example.com/upload",
      expect.objectContaining({
        method: "PUT",
        body: blob,
      })
    );
  });
});
