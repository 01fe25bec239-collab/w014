import type { Metadata } from "next";
import type { ReactNode } from "react";
import { SessionProvider } from "@/lib/session-context";
import "./globals.css";

export const metadata: Metadata = {
  title: "W-014 | Systems Verification & Compliance Platform",
  description:
    "W-014 Defense & Aerospace Systems Verification & Compliance Platform — Presentation Shell",
};

export default function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <SessionProvider>{children}</SessionProvider>
      </body>
    </html>
  );
}
