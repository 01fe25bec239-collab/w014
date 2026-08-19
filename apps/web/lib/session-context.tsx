"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import type { ProblemDetails, SessionResponse } from "./api-types";
import { apiClient, ApiClientError } from "./api-client";

export interface SessionContextValue {
  session: SessionResponse | null;
  isLoading: boolean;
  error: ProblemDetails | null;
  csrfToken: string | null;
  refreshSession: () => Promise<void>;
  logout: () => Promise<void>;
  initiateLogin: () => Promise<string | void>;
}

const SessionContext = createContext<SessionContextValue | undefined>(undefined);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ProblemDetails | null>(null);
  const [csrfToken, setCsrfToken] = useState<string | null>(null);

  const refreshSession = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiClient.getSession();
      setSession(data);
      setCsrfToken(data.csrf_token || null);
      setError(null);
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        if (err.status === 401) {
          // Normal unauthenticated / signed-out state
          setSession(null);
          setCsrfToken(null);
          setError(null);
        } else {
          setSession(null);
          setCsrfToken(null);
          setError(err.problem);
        }
      } else {
        setSession(null);
        setCsrfToken(null);
        setError({
          type: "urn:w014:error:session-error",
          title: "Session Error",
          status: 0,
          detail: "Unable to inspect session.",
        });
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    setIsLoading(true);
    try {
      await apiClient.postLogout(csrfToken || undefined);
    } catch (err: unknown) {
      // Even if logout request fails on server, clear local presentation state
      if (err instanceof ApiClientError && err.status !== 401) {
        setError(err.problem);
      }
    } finally {
      setSession(null);
      setCsrfToken(null);
      setIsLoading(false);
    }
  }, [csrfToken]);

  const initiateLogin = useCallback(async () => {
    try {
      const loginResp = await apiClient.getAuthLogin("json");
      if (loginResp?.authorization_url && typeof window !== "undefined") {
        window.location.href = loginResp.authorization_url;
        return loginResp.authorization_url;
      }
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setError(err.problem);
      }
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  return (
    <SessionContext.Provider
      value={{
        session,
        isLoading,
        error,
        csrfToken,
        refreshSession,
        logout,
        initiateLogin,
      }}
    >
      {children}
    </SessionContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  const context = useContext(SessionContext);
  if (!context) {
    throw new Error("useSession must be used within a SessionProvider");
  }
  return context;
}
