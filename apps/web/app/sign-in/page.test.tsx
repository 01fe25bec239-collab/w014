import React from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import SignInPage from "./page";
import { apiClient, ApiClientError } from "@/lib/api-client";
import { SessionProvider } from "@/lib/session-context";
import { DATA_BOUNDARY_TEXT } from "@/components/shell";

function renderWithSessionProvider() {
  return render(
    <SessionProvider>
      <SignInPage />
    </SessionProvider>
  );
}

describe("S01: Sign In & Session Page", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders signed-out state when unauthenticated (401)", async () => {
    vi.spyOn(apiClient, "getSession").mockRejectedValue(
      new ApiClientError({
        type: "urn:w014:error:unauthorized",
        title: "Unauthorized",
        status: 401,
        detail: "Unauthenticated",
      })
    );

    renderWithSessionProvider();

    expect(screen.getByText("Sign In & Session Management")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId("sign-in-signed-out")).toBeInTheDocument();
    });

    expect(screen.getByTestId("initiate-login-btn")).toBeInTheDocument();
    expect(screen.getAllByText(DATA_BOUNDARY_TEXT).length).toBeGreaterThan(0);
  });

  it("initiates OIDC login when login button clicked", async () => {
    vi.spyOn(apiClient, "getSession").mockRejectedValue(
      new ApiClientError({
        type: "urn:w014:error:unauthorized",
        title: "Unauthorized",
        status: 401,
      })
    );

    const loginSpy = vi.spyOn(apiClient, "getAuthLogin").mockResolvedValue({
      authorization_url: "https://idp.example.com/auth?state=xyz",
      state: "xyz",
      expires_at: "2026-08-19T20:00:00Z",
    });

    const user = userEvent.setup();
    renderWithSessionProvider();

    await waitFor(() => {
      expect(screen.getByTestId("initiate-login-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("initiate-login-btn"));
    expect(loginSpy).toHaveBeenCalledWith("json");
  });

  it("renders active session details when authenticated", async () => {
    const mockSession = {
      session_id: "sess-uuid-1234",
      principal_id: "user@defense.example.com",
      status: "active",
      created_at: "2026-08-19T10:00:00Z",
      last_seen_at: "2026-08-19T10:05:00Z",
      idle_expires_at: "2026-08-19T11:00:00Z",
      absolute_expires_at: "2026-08-19T18:00:00Z",
      rotation_counter: 1,
      csrf_token: "csrf_token_active",
    };

    vi.spyOn(apiClient, "getSession").mockResolvedValue(mockSession);

    renderWithSessionProvider();

    await waitFor(() => {
      expect(screen.getByTestId("session-active-panel")).toBeInTheDocument();
    });

    expect(screen.getByTestId("session-principal-id")).toHaveTextContent(
      "user@defense.example.com"
    );
    expect(screen.getByTestId("session-id")).toHaveTextContent("sess-uuid-1234");
    expect(screen.getByTestId("session-status")).toHaveTextContent("active");
    expect(screen.getByTestId("enter-programs-btn")).toBeInTheDocument();
    expect(screen.getByTestId("sign-out-btn")).toBeInTheDocument();
  });

  it("triggers logout command with CSRF token", async () => {
    const mockSession = {
      session_id: "sess-uuid-1234",
      principal_id: "user@defense.example.com",
      status: "active",
      created_at: "2026-08-19T10:00:00Z",
      last_seen_at: "2026-08-19T10:05:00Z",
      idle_expires_at: "2026-08-19T11:00:00Z",
      absolute_expires_at: "2026-08-19T18:00:00Z",
      rotation_counter: 1,
      csrf_token: "csrf_token_active",
    };

    vi.spyOn(apiClient, "getSession").mockResolvedValue(mockSession);
    const logoutSpy = vi
      .spyOn(apiClient, "postLogout")
      .mockResolvedValue({ status: "logged_out" });

    const user = userEvent.setup();
    renderWithSessionProvider();

    await waitFor(() => {
      expect(screen.getByTestId("sign-out-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("sign-out-btn"));
    expect(logoutSpy).toHaveBeenCalledWith("csrf_token_active");

    await waitFor(() => {
      expect(screen.getByTestId("sign-in-signed-out")).toBeInTheDocument();
    });
  });

  it("has 0 axe accessibility violations", async () => {
    vi.spyOn(apiClient, "getSession").mockResolvedValue({
      session_id: "sess-axe",
      principal_id: "principal-axe@example.com",
      status: "active",
      created_at: "2026-08-19T10:00:00Z",
      last_seen_at: "2026-08-19T10:05:00Z",
      idle_expires_at: "2026-08-19T11:00:00Z",
      absolute_expires_at: "2026-08-19T18:00:00Z",
      rotation_counter: 1,
      csrf_token: "csrf_axe",
    });

    const { container } = renderWithSessionProvider();
    await waitFor(() => {
      expect(screen.getByTestId("session-active-panel")).toBeInTheDocument();
    });

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
