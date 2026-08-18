export type AppEnvironment =
  | "local"
  | "dev"
  | "demo"
  | "staging"
  | "public-demo"
  | "production";

export interface EnvironmentInfo {
  name: AppEnvironment;
  label: string;
  isProduction: boolean;
}

const VALID_ENVIRONMENTS: readonly AppEnvironment[] = [
  "local",
  "dev",
  "demo",
  "staging",
  "public-demo",
  "production",
];

/**
 * Returns the current presentation environment configuration.
 * Next.js presentation-only helper. Does not expose secrets or backend authority.
 */
export function getAppEnvironment(): EnvironmentInfo {
  const rawEnv = (
    process.env.NEXT_PUBLIC_APP_ENV ||
    process.env.NODE_ENV ||
    "local"
  ).toLowerCase().trim();

  const name: AppEnvironment = VALID_ENVIRONMENTS.includes(
    rawEnv as AppEnvironment
  )
    ? (rawEnv as AppEnvironment)
    : "local";

  const isProduction = name === "production";

  const labelMap: Record<AppEnvironment, string> = {
    local: "LOCAL [NON-PROD]",
    dev: "DEV [NON-PROD]",
    demo: "DEMO [NON-PROD]",
    staging: "STAGING [NON-PROD]",
    "public-demo": "PUBLIC DEMO [NON-PROD]",
    production: "PRODUCTION",
  };

  return {
    name,
    label: labelMap[name],
    isProduction,
  };
}
