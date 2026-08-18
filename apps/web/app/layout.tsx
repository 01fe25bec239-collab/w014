import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "W-014 | Systems Verification & Compliance Platform",
  description:
    "W-014 Defense & Aerospace Systems Verification & Compliance Platform — Presentation Shell (VS0 / W0)",
};

export default function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
