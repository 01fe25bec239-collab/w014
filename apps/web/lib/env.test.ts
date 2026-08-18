import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { getAppEnvironment } from "./env";

describe("env helper", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("defaults to local environment when unspecified", () => {
    delete (process.env as Record<string, string | undefined>).NEXT_PUBLIC_APP_ENV;
    delete (process.env as Record<string, string | undefined>).NODE_ENV;
    const envInfo = getAppEnvironment();
    expect(envInfo.name).toBe("local");
    expect(envInfo.isProduction).toBe(false);
    expect(envInfo.label).toContain("LOCAL [NON-PROD]");
  });

  it("parses dev environment correctly", () => {
    process.env.NEXT_PUBLIC_APP_ENV = "dev";
    const envInfo = getAppEnvironment();
    expect(envInfo.name).toBe("dev");
    expect(envInfo.isProduction).toBe(false);
    expect(envInfo.label).toBe("DEV [NON-PROD]");
  });

  it("parses demo environment correctly", () => {
    process.env.NEXT_PUBLIC_APP_ENV = "demo";
    const envInfo = getAppEnvironment();
    expect(envInfo.name).toBe("demo");
    expect(envInfo.isProduction).toBe(false);
    expect(envInfo.label).toBe("DEMO [NON-PROD]");
  });

  it("parses staging environment correctly", () => {
    process.env.NEXT_PUBLIC_APP_ENV = "staging";
    const envInfo = getAppEnvironment();
    expect(envInfo.name).toBe("staging");
    expect(envInfo.isProduction).toBe(false);
    expect(envInfo.label).toBe("STAGING [NON-PROD]");
  });

  it("parses public-demo environment correctly", () => {
    process.env.NEXT_PUBLIC_APP_ENV = "public-demo";
    const envInfo = getAppEnvironment();
    expect(envInfo.name).toBe("public-demo");
    expect(envInfo.isProduction).toBe(false);
    expect(envInfo.label).toBe("PUBLIC DEMO [NON-PROD]");
  });

  it("identifies production environment correctly", () => {
    process.env.NEXT_PUBLIC_APP_ENV = "production";
    const envInfo = getAppEnvironment();
    expect(envInfo.name).toBe("production");
    expect(envInfo.isProduction).toBe(true);
    expect(envInfo.label).toBe("PRODUCTION");
  });

  it("falls back safely to local on unrecognized values", () => {
    process.env.NEXT_PUBLIC_APP_ENV = "unknown-value";
    const envInfo = getAppEnvironment();
    expect(envInfo.name).toBe("local");
    expect(envInfo.isProduction).toBe(false);
  });
});
