import type { ReactNode } from "react";

export const metadata = {
  title: "W-014",
  description: "W-014 Foundation Web Bootstrap",
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
