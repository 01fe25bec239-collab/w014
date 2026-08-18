import React from "react";

export interface SkipToContentProps {
  targetId?: string;
  label?: string;
}

/**
 * SkipToContent provides an accessible skip link for keyboard users
 * to bypass persistent header and navigation landmarks.
 */
export function SkipToContent({
  targetId = "main-content",
  label = "Skip to main content",
}: SkipToContentProps) {
  return (
    <a href={`#${targetId}`} className="skip-link">
      {label}
    </a>
  );
}
