import React from "react";
import { getAppEnvironment, type AppEnvironment } from "@/lib/env";

export interface EnvironmentBadgeProps {
  env?: AppEnvironment;
  className?: string;
}

/**
 * EnvironmentBadge provides bounded presentation of the runtime environment.
 * Non-production environments visually and textually indicate their non-production status.
 */
export function EnvironmentBadge({ env, className = "" }: EnvironmentBadgeProps) {
  const currentEnv = env ? {
    name: env,
    label: env === "production" ? "PRODUCTION" : `${env.toUpperCase()} [NON-PROD]`,
    isProduction: env === "production"
  } : getAppEnvironment();

  return (
    <span
      className={`environment-badge ${className}`.trim()}
      data-env={currentEnv.name}
      role="status"
      aria-label={`Environment: ${currentEnv.label}`}
    >
      <span aria-hidden="true" style={{ fontSize: "0.625rem" }}>●</span>
      <span>ENV: {currentEnv.name.toUpperCase()}</span>
      {!currentEnv.isProduction && (
        <span aria-hidden="true" style={{ opacity: 0.8 }}>[NON-PROD]</span>
      )}
    </span>
  );
}
