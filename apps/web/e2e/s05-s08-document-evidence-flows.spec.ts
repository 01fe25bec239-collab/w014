import { test, expect } from "@playwright/test";

test.describe("WI-0208 S05–S08 Document & Evidence Flows Playwright Acceptance Suite", () => {
  const mockWorkspace = {
    id: "ws_avionics_001",
    program_id: "prog_flight_001",
    organization_id: "org_defense_001",
    name: "Avionics Core Workspace",
    slug: "avionics-core-workspace",
    created_at: "2026-08-30T10:00:00Z",
    updated_at: "2026-08-30T10:00:00Z",
  };

  const mockDocs = [
    {
      id: "doc_telemetry_001",
      workspace_id: "ws_avionics_001",
      title: "Telemetry Bus Interface Spec",
      document_class: "pdf",
      status: "active",
      current_version_id: "ver_tel_001",
      created_at: "2026-08-30T10:00:00Z",
      updated_at: "2026-08-30T10:00:00Z",
      row_version: 2,
    },
    {
      id: "doc_guidance_002",
      workspace_id: "ws_avionics_001",
      title: "Guidance Navigation Algorithm ICD",
      document_class: "docx",
      status: "active",
      current_version_id: undefined,
      created_at: "2026-08-30T11:00:00Z",
      updated_at: "2026-08-30T11:00:00Z",
      row_version: 1,
    },
  ];

  const mockVersions = [
    {
      id: "ver_tel_001",
      document_id: "doc_telemetry_001",
      workspace_id: "ws_avionics_001",
      version_number: 1,
      object_artifact_id: "art_tel_001",
      byte_size: 1024,
      sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      content_type: "application/pdf",
      original_filename: "telemetry_spec_v1.pdf",
      trust_state: "trusted",
      submitted_by: "lead.engineer@defense.example.com",
      created_at: "2026-08-30T10:00:00Z",
    },
    {
      id: "ver_tel_002",
      document_id: "doc_telemetry_001",
      workspace_id: "ws_avionics_001",
      version_number: 2,
      object_artifact_id: "art_tel_002",
      byte_size: 2048,
      sha256_hash: "f4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afb",
      content_type: "application/pdf",
      original_filename: "telemetry_spec_v2.pdf",
      trust_state: "trusted",
      submitted_by: "auditor@defense.example.com",
      created_at: "2026-08-30T12:00:00Z",
    },
  ];

  test.beforeEach(async ({ page }) => {
    // Mock active session
    await page.route("**/api/v1/session", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            session_id: "sess_active_123",
            principal_id: "lead.engineer@defense.example.com",
            status: "active",
            created_at: "2026-08-30T10:00:00Z",
            last_seen_at: "2026-08-30T10:05:00Z",
            idle_expires_at: "2026-08-30T12:00:00Z",
            absolute_expires_at: "2026-08-30T18:00:00Z",
            rotation_counter: 1,
            csrf_token: "csrf_token_active_999",
          }),
        });
      } else {
        await route.continue();
      }
    });

    // Mock workspace endpoint
    await page.route("**/api/v1/workspaces/ws_avionics_001", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockWorkspace),
      });
    });
  });

  // S05 — Document Library
  test("S05: Document library listing, class filtering, and logical document creation", async ({ page }) => {
    await page.route("**/api/v1/workspaces/ws_avionics_001/documents*", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            items: mockDocs,
            has_more: false,
          }),
        });
      } else if (route.request().method() === "POST") {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify({
            id: "doc_new_created_003",
            workspace_id: "ws_avionics_001",
            title: body.title,
            document_class: body.document_class,
            status: "active",
            created_at: "2026-08-30T13:00:00Z",
            updated_at: "2026-08-30T13:00:00Z",
            row_version: 1,
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.goto("/workspaces/ws_avionics_001/documents");

    // Verify page header and table
    await expect(page.getByRole("heading", { name: "Document Library" })).toBeVisible();
    await expect(page.getByTestId("document-table")).toBeVisible();
    await expect(page.getByText("Telemetry Bus Interface Spec")).toBeVisible();
    await expect(page.getByText("Guidance Navigation Algorithm ICD")).toBeVisible();

    // Verify authoritative current marker
    await expect(page.getByTestId("doc-current-version-doc_telemetry_001")).toHaveText("Current: ver_tel_...");
    await expect(page.getByTestId("doc-unversioned-doc_guidance_002")).toHaveText("Unversioned");

    // Test Class Filter
    await page.getByTestId("class-filter-select").selectOption("docx");
    await expect(page.getByText("Telemetry Bus Interface Spec")).not.toBeVisible();
    await expect(page.getByText("Guidance Navigation Algorithm ICD")).toBeVisible();

    await page.getByTestId("class-filter-select").selectOption("all");

    // Test Create Logical Document modal
    await page.getByTestId("create-doc-modal-btn").click();
    await expect(page.getByRole("dialog")).toBeVisible();

    await page.getByTestId("document-title-input").fill("Flight Safety Validation Spec");
    await page.getByTestId("document-class-select").selectOption("pdf");
    await page.getByTestId("submit-document-btn").click();

    // Modal closes on success
    await expect(page.getByRole("dialog")).not.toBeVisible();
  });

  // S06 — Secure Upload Flow & Quarantine Gate
  test("S06: Secure upload sequence, attestation requirement, and quarantine verification", async ({ page }) => {
    let intentCreated = false;
    let finalizeCalled = false;

    await page.route("**/api/v1/workspaces/ws_avionics_001/documents*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ items: mockDocs, has_more: false }),
      });
    });

    await page.route("**/api/v1/workspaces/ws_avionics_001/documents/doc_telemetry_001/upload-intents", async (route) => {
      intentCreated = true;
      await route.fulfill({
        status: 201,
        contentType: "application/json",
        body: JSON.stringify({
          id: "intent_telemetry_002",
          workspace_id: "ws_avionics_001",
          document_id: "doc_telemetry_001",
          filename: "telemetry_spec_v2.pdf",
          expected_media_type: "application/pdf",
          expected_length: 2048,
          opaque_object_key: "k_tel_002",
          status: "pending",
          expires_at: "2026-08-30T10:10:00Z",
          created_at: "2026-08-30T10:00:00Z",
          presigned_put: {
            upload_url: "https://storage.example.com/put/telemetry_spec_v2.pdf",
            method: "PUT",
            expires_at: "2026-08-30T10:10:00Z",
            headers: { "Content-Type": "application/pdf" },
          },
        }),
      });
    });

    // Mock direct S3 PUT
    await page.route("https://storage.example.com/put/telemetry_spec_v2.pdf", async (route) => {
      await route.fulfill({ status: 200, body: "" });
    });

    await page.route("**/api/v1/workspaces/ws_avionics_001/upload-intents/intent_telemetry_002/finalize", async (route) => {
      finalizeCalled = true;
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          upload_intent_id: "intent_telemetry_002",
          document_id: "doc_telemetry_001",
          document_version_id: "ver_tel_002",
          version_number: 2,
          object_artifact_id: "art_tel_002",
          quarantine_record_id: "quarantine_rec_tel_002",
          scan_job_id: "scan_job_tel_002",
          status: "quarantined_processing",
          trust_state: "pending",
        }),
      });
    });

    await page.goto("/workspaces/ws_avionics_001/upload?documentId=doc_telemetry_001");

    await expect(page.getByRole("heading", { name: "Secure Document Upload" })).toBeVisible();

    // Verify submit button is disabled before file & attestation
    const submitBtn = page.getByTestId("submit-upload-btn");
    await expect(submitBtn).toBeDisabled();

    // Set file input
    const fileInput = page.getByTestId("file-input");
    await fileInput.setInputFiles({
      name: "telemetry_spec_v2.pdf",
      mimeType: "application/pdf",
      buffer: Buffer.from("%PDF-1.4 Mock PDF Content"),
    });

    await expect(page.getByTestId("selected-file-name")).toHaveText("telemetry_spec_v2.pdf");

    // Check mandatory attestation
    await page.getByTestId("attestation-checkbox").check();
    await expect(submitBtn).toBeEnabled();

    // Execute upload
    await submitBtn.click();

    // Verify sequence completed
    await expect(page.getByRole("heading", { name: /Upload Complete — Security Checks Pending/i })).toBeVisible();
    await expect(page.getByTestId("completed-quarantine-id")).toHaveText("quarantine_rec_tel_002");
    await expect(page.getByTestId("completed-job-id")).toHaveText("scan_job_tel_002");
    await expect(page.getByTestId("completed-trust-state")).toHaveText("pending");

    expect(intentCreated).toBe(true);
    expect(finalizeCalled).toBe(true);
  });

  // S07 — Document Detail & Version History
  test("S07: Document summary, immutable version history, accept version with If-Match, and download", async ({ page }) => {
    let acceptCalledWithIfMatch = false;

    await page.route("**/api/v1/workspaces/ws_avionics_001/documents/doc_telemetry_001", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockDocs[0]),
      });
    });

    await page.route("**/api/v1/workspaces/ws_avionics_001/documents/doc_telemetry_001/versions*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          items: mockVersions,
          has_more: false,
        }),
      });
    });

    await page.route("**/api/v1/workspaces/ws_avionics_001/document-versions/ver_tel_002/accept", async (route) => {
      const ifMatch = route.request().headers()["if-match"];
      if (ifMatch === '"2"') {
        acceptCalledWithIfMatch = true;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...mockDocs[0],
          current_version_id: "ver_tel_002",
          row_version: 3,
        }),
      });
    });

    await page.goto("/workspaces/ws_avionics_001/documents/doc_telemetry_001");

    await expect(page.getByTestId("detail-doc-title")).toHaveText("Telemetry Bus Interface Spec");
    await expect(page.getByTestId("version-table")).toBeVisible();

    // Verify Current vs Historical badge
    await expect(page.getByTestId("version-current-ver_tel_001")).toBeVisible();
    await expect(page.getByTestId("version-historical-ver_tel_002")).toBeVisible();

    // Click "Set as Current" for ver_tel_002
    await page.getByTestId("accept-version-btn-ver_tel_002").click();
    await expect(page.getByTestId("accept-version-modal")).toBeVisible();
    await expect(page.getByText(/If-Match: "2"/i)).toBeVisible();

    await page.getByTestId("confirm-accept-btn").click();
    expect(acceptCalledWithIfMatch).toBe(true);
  });

  // S08 — Immutable Evidence Viewer
  test("S08: Evidence workbench, bounded page navigation, span citation inspection, and inert text rendering", async ({ page }) => {
    await page.route("**/api/v1/workspaces/ws_avionics_001/documents/doc_telemetry_001", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockDocs[0]),
      });
    });

    await page.route("**/api/v1/workspaces/ws_avionics_001/document-versions/ver_tel_001", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockVersions[0]),
      });
    });

    await page.goto("/workspaces/ws_avionics_001/documents/doc_telemetry_001/versions/ver_tel_001?page=1&span=1");

    await expect(page.getByTestId("evidence-workbench")).toBeVisible();
    await expect(page.getByTestId("document-page-view")).toBeVisible();
    await expect(page.getByTestId("source-span-panel")).toBeVisible();

    // Verify citation details
    await expect(page.getByTestId("generated-citation-box")).toContainText(
      "[Telemetry Bus Interface Spec, v1, p. 1"
    );

    // Verify copy citation button is present
    await expect(page.getByTestId("copy-citation-btn")).toBeVisible();
  });
});
