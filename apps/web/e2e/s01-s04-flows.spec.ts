import { test, expect } from "@playwright/test";

test.describe("WI-0106 S01–S04 Playwright Acceptance Suite", () => {
  // S01 — Sign In & Session Lifecycle Flow
  test("S01: Sign-in, session inspection, and logout lifecycle", async ({ page }) => {
    // 1. Mock unauthenticated state
    await page.route("**/api/v1/session", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 401,
          contentType: "application/problem+json",
          body: JSON.stringify({
            type: "urn:w014:error:unauthorized",
            title: "Unauthorized",
            status: 401,
            detail: "Unauthenticated caller.",
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.route("**/api/v1/auth/login*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          authorization_url: "https://idp.example.com/oauth2/auth?state=syn_state_123",
          state: "syn_state_123",
          expires_at: "2026-08-19T22:00:00Z",
        }),
      });
    });

    await page.goto("/sign-in");

    // Verify unauthenticated presentation
    await expect(page.getByRole("heading", { name: "Sign In & Session Management" })).toBeVisible();
    await expect(page.getByTestId("sign-in-signed-out")).toBeVisible();
    await expect(page.getByTestId("initiate-login-btn")).toBeVisible();

    // Verify data boundary banner is visible
    await expect(page.locator(".data-boundary-banner")).toContainText(
      "Portfolio demo: public / synthetic / sanitized non-CUI only."
    );

    // 2. Mock active session state
    await page.unroute("**/api/v1/session");
    await page.route("**/api/v1/session", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            session_id: "sess_syn_12345",
            principal_id: "synthetic.auditor@defense.example.com",
            status: "active",
            created_at: "2026-08-19T18:00:00Z",
            last_seen_at: "2026-08-19T18:05:00Z",
            idle_expires_at: "2026-08-19T19:00:00Z",
            absolute_expires_at: "2026-08-20T02:00:00Z",
            rotation_counter: 1,
            csrf_token: "csrf_active_token_999",
          }),
        });
      } else {
        await route.continue();
      }
    });

    let logoutCalledWithCsrf = false;
    await page.route("**/api/v1/session/logout", async (route) => {
      const csrfHeader = route.request().headers()["x-w014-csrf"];
      if (csrfHeader === "csrf_active_token_999") {
        logoutCalledWithCsrf = true;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ status: "logged_out" }),
      });
    });

    // Refresh session on page
    await page.getByTestId("check-session-btn").click();

    // Verify active session summary
    await expect(page.getByTestId("session-active-panel")).toBeVisible();
    await expect(page.getByTestId("session-principal-id")).toHaveText(
      "synthetic.auditor@defense.example.com"
    );
    await expect(page.getByTestId("session-id")).toHaveText("sess_syn_12345");
    await expect(page.getByTestId("session-status")).toHaveText("active");

    // Verify header session menu displays active principal
    await expect(page.getByTestId("session-menu-active")).toBeVisible();

    // Execute logout command
    await page.getByTestId("sign-out-btn").click();

    // Verify logout request included CSRF token
    expect(logoutCalledWithCsrf).toBe(true);

    // Verify transition back to signed-out state
    await expect(page.getByTestId("sign-in-signed-out")).toBeVisible();
  });

  // S02 — Programs Portfolio Flow
  test("S02: Authorized programs portfolio list, filtering, and creation", async ({ page }) => {
    const mockPrograms = [
      {
        id: "prog_avionics_001",
        organization_id: "org_synth_01",
        name: "Avionics Core Platform",
        slug: "avionics-core-platform",
        description: "Primary flight avionics and embedded telemetry",
        created_at: "2026-08-19T10:00:00Z",
        updated_at: "2026-08-19T10:00:00Z",
      },
      {
        id: "prog_satellite_002",
        organization_id: "org_synth_01",
        name: "Orbital Guidance Bus",
        slug: "orbital-guidance-bus",
        description: "Orbital station keeping and attitude control",
        created_at: "2026-08-19T11:00:00Z",
        updated_at: "2026-08-19T11:00:00Z",
      },
    ];

    await page.route("**/api/v1/session", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          session_id: "sess_active",
          principal_id: "lead.engineer@defense.example.com",
          status: "active",
          created_at: "2026-08-19T10:00:00Z",
          last_seen_at: "2026-08-19T10:05:00Z",
          idle_expires_at: "2026-08-19T11:00:00Z",
          absolute_expires_at: "2026-08-19T18:00:00Z",
          rotation_counter: 1,
          csrf_token: "csrf_prog_e2e",
        }),
      });
    });

    await page.route("**/api/v1/programs*", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            items: mockPrograms,
            has_more: false,
          }),
        });
      } else if (route.request().method() === "POST") {
        const body = route.request().postDataJSON();
        const createdProg = {
          id: "prog_radar_003",
          organization_id: "org_synth_01",
          name: body.name,
          slug: body.slug,
          description: body.description,
          created_at: "2026-08-19T12:00:00Z",
          updated_at: "2026-08-19T12:00:00Z",
        };
        mockPrograms.push(createdProg);
        await route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(createdProg),
        });
      }
    });

    await page.goto("/programs");

    // Verify page header and table
    await expect(page.getByRole("heading", { name: "Programs Portfolio" })).toBeVisible();
    await expect(page.getByText("Avionics Core Platform")).toBeVisible();
    await expect(page.getByText("Orbital Guidance Bus")).toBeVisible();

    // Test client-side filter
    await page.getByTestId("filter-input").fill("orbital");
    await expect(page.getByText("Avionics Core Platform")).not.toBeVisible();
    await expect(page.getByText("Orbital Guidance Bus")).toBeVisible();
    await page.getByTestId("filter-clear-btn").click();
    await expect(page.getByText("Avionics Core Platform")).toBeVisible();

    // Test program creation command UX
    await page.getByTestId("create-program-btn").click();
    await expect(page.getByTestId("create-program-modal")).toBeVisible();

    await page.getByTestId("program-name-input").fill("Radar Subsystem");
    await expect(page.getByTestId("program-slug-input")).toHaveValue("radar-subsystem");

    await page.getByTestId("submit-program-btn").click();

    // Modal closes and new program is visible
    await expect(page.getByTestId("create-program-modal")).not.toBeVisible();
    await expect(page.getByText("Radar Subsystem")).toBeVisible();
  });

  // S03 — Program-scoped Workspaces Flow
  test("S03: Scoped workspace list, workspace creation, and navigation", async ({ page }) => {
    const mockProgram = {
      id: "prog_avionics_001",
      organization_id: "org_synth_01",
      name: "Avionics Core Platform",
      slug: "avionics-core-platform",
      description: "Primary flight avionics and embedded telemetry",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    const mockWorkspaces = [
      {
        id: "ws_flight_primary",
        program_id: "prog_avionics_001",
        organization_id: "org_synth_01",
        name: "Flight Control Primary",
        slug: "flight-control-primary",
        created_at: "2026-08-19T10:00:00Z",
        updated_at: "2026-08-19T10:00:00Z",
      },
    ];

    await page.route("**/api/v1/session", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          session_id: "sess_active",
          principal_id: "lead.engineer@defense.example.com",
          status: "active",
          created_at: "2026-08-19T10:00:00Z",
          last_seen_at: "2026-08-19T10:05:00Z",
          idle_expires_at: "2026-08-19T11:00:00Z",
          absolute_expires_at: "2026-08-19T18:00:00Z",
          rotation_counter: 1,
          csrf_token: "csrf_ws_e2e",
        }),
      });
    });

    await page.route("**/api/v1/programs/prog_avionics_001", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockProgram),
      });
    });

    await page.route("**/api/v1/programs/prog_avionics_001/workspaces*", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            items: mockWorkspaces,
            has_more: false,
          }),
        });
      } else if (route.request().method() === "POST") {
        const body = route.request().postDataJSON();
        const createdWs = {
          id: "ws_telemetry_subsystem",
          program_id: "prog_avionics_001",
          organization_id: "org_synth_01",
          name: body.name,
          slug: body.slug,
          created_at: "2026-08-19T12:00:00Z",
          updated_at: "2026-08-19T12:00:00Z",
        };
        mockWorkspaces.push(createdWs);
        await route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(createdWs),
        });
      }
    });

    await page.goto("/programs/prog_avionics_001/workspaces");

    // Verify program heading and breadcrumbs
    await expect(page.getByRole("heading", { name: "Avionics Core Platform Workspaces" })).toBeVisible();
    await expect(page.getByText("Flight Control Primary")).toBeVisible();

    // Create a new workspace
    await page.getByTestId("create-workspace-btn").click();
    await expect(page.getByTestId("create-workspace-modal")).toBeVisible();

    await page.getByTestId("ws-name-input").fill("Telemetry Subsystem");
    await expect(page.getByTestId("ws-slug-input")).toHaveValue("telemetry-subsystem");

    await page.getByTestId("submit-ws-btn").click();

    // Verify workspace is created and listed
    await expect(page.getByTestId("create-workspace-modal")).not.toBeVisible();
    await expect(page.getByText("Telemetry Subsystem")).toBeVisible();
  });

  // S04 — W1 Workspace Shell Overview & Hard E11 Prohibition
  test("S04: Workspace shell overview, deferred W2-W4 presentation, and Hard E11 Prohibition", async ({ page }) => {
    const mockWorkspace = {
      id: "ws_flight_primary",
      program_id: "prog_avionics_001",
      organization_id: "org_synth_01",
      name: "Flight Control Primary",
      slug: "flight-control-primary",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    let e11Queried = false;

    await page.route("**/api/v1/session", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          session_id: "sess_active",
          principal_id: "lead.engineer@defense.example.com",
          status: "active",
          created_at: "2026-08-19T10:00:00Z",
          last_seen_at: "2026-08-19T10:05:00Z",
          idle_expires_at: "2026-08-19T11:00:00Z",
          absolute_expires_at: "2026-08-19T18:00:00Z",
          rotation_counter: 1,
          csrf_token: "csrf_ws_e2e",
        }),
      });
    });

    await page.route("**/api/v1/workspaces/ws_flight_primary", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockWorkspace),
      });
    });

    // Monitor for any unauthorized E11 calls
    await page.route("**/source-state*", async (route) => {
      e11Queried = true;
      await route.abort();
    });

    await page.goto("/workspaces/ws_flight_primary");

    // 1. Verify authoritative workspace metadata
    await expect(page.getByTestId("ws-identity-panel")).toBeVisible();
    await expect(page.getByTestId("ws-meta-name")).toHaveText("Flight Control Primary");
    await expect(page.getByTestId("ws-meta-slug")).toHaveText("flight-control-primary");
    await expect(page.getByTestId("ws-meta-id")).toHaveText("ws_flight_primary");
    await expect(page.getByTestId("ws-meta-program-id")).toHaveText("prog_avionics_001");

    // 2. Verify truthful deferred/prerequisite presentation for unarrived waves
    await expect(page.getByTestId("deferred-w2-panel")).toBeVisible();
    await expect(page.getByTestId("deferred-w3-panel")).toBeVisible();
    await expect(page.getByTestId("deferred-w4-panel")).toBeVisible();

    // 3. Verify HARD E11 PROHIBITION: E11 endpoint was never requested
    expect(e11Queried).toBe(false);

    // 4. Verify NO fabricated READY or BLOCKED status badges
    await expect(page.getByText(/^READY$/i)).toHaveCount(0);
    await expect(page.getByText(/^BLOCKED$/i)).toHaveCount(0);
  });

  // State Transition & Negative Evidence: Cross-Workspace Data Isolation
  test("NEGATIVE: Workspace switch purges Workspace A authoritative data when transitioning to Workspace B", async ({ page }) => {
    const wsA = {
      id: "ws-secret-guidance-001",
      program_id: "prog-classified",
      organization_id: "org_synth_01",
      name: "Secret Guidance Compartment",
      slug: "secret-guidance-compartment",
      created_at: "2026-08-19T10:00:00Z",
      updated_at: "2026-08-19T10:00:00Z",
    };

    const wsB = {
      id: "ws-public-weather-002",
      program_id: "prog-unclass",
      organization_id: "org_synth_01",
      name: "Civilian Weather Sensor",
      slug: "civilian-weather-sensor",
      created_at: "2026-08-19T11:00:00Z",
      updated_at: "2026-08-19T11:00:00Z",
    };

    await page.route("**/api/v1/session", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          session_id: "sess_active",
          principal_id: "auditor@defense.example.com",
          status: "active",
          created_at: "2026-08-19T10:00:00Z",
          last_seen_at: "2026-08-19T10:05:00Z",
          idle_expires_at: "2026-08-19T11:00:00Z",
          absolute_expires_at: "2026-08-19T18:00:00Z",
          rotation_counter: 1,
        }),
      });
    });

    await page.route("**/api/v1/workspaces/ws-secret-guidance-001", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(wsA),
      });
    });

    await page.route("**/api/v1/workspaces/ws-public-weather-002", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(wsB),
      });
    });

    // 1. Visit Workspace A
    await page.goto("/workspaces/ws-secret-guidance-001");
    await expect(page.getByTestId("ws-meta-name")).toHaveText("Secret Guidance Compartment");
    await expect(page.getByTestId("ws-meta-slug")).toHaveText("secret-guidance-compartment");

    // 2. Navigate to Workspace B
    await page.goto("/workspaces/ws-public-weather-002");

    // Verify Workspace B content loads
    await expect(page.getByTestId("ws-meta-name")).toHaveText("Civilian Weather Sensor");
    await expect(page.getByTestId("ws-meta-slug")).toHaveText("civilian-weather-sensor");

    // Critical Negative Assertion: NO Workspace A data is present or visible in Workspace B!
    await expect(page.getByText("Secret Guidance Compartment")).toHaveCount(0);
    await expect(page.getByText("secret-guidance-compartment")).toHaveCount(0);
  });

  // Privacy-safe 404 / 403 error presentation
  test("NEGATIVE: Privacy-safe 404/403 problem notice on unmembered/unauthorized workspace", async ({ page }) => {
    await page.route("**/api/v1/session", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          session_id: "sess_active",
          principal_id: "user@defense.example.com",
          status: "active",
          created_at: "2026-08-19T10:00:00Z",
          last_seen_at: "2026-08-19T10:05:00Z",
          idle_expires_at: "2026-08-19T11:00:00Z",
          absolute_expires_at: "2026-08-19T18:00:00Z",
          rotation_counter: 1,
        }),
      });
    });

    await page.route("**/api/v1/workspaces/ws-forbidden-000", async (route) => {
      await route.fulfill({
        status: 404,
        contentType: "application/problem+json",
        body: JSON.stringify({
          type: "urn:w014:error:not-found",
          title: "Not Found",
          status: 404,
          detail: "Workspace 'ws-forbidden-000' was not found",
          instance: "/api/v1/workspaces/ws-forbidden-000",
          code: "NOT_FOUND",
          correlation_id: "corr-e2e-priv-safe",
        }),
      });
    });

    await page.goto("/workspaces/ws-forbidden-000");

    // Verify privacy-safe RFC 9457 notice
    await expect(page.getByTestId("problem-notice")).toBeVisible();
    await expect(page.getByText("Workspace 'ws-forbidden-000' was not found")).toBeVisible();
    await expect(page.getByText("corr-e2e-priv-safe")).toBeVisible();

    // Verify workspace metadata panel is NOT rendered
    await expect(page.getByTestId("workspace-shell-content")).toHaveCount(0);
  });
});
