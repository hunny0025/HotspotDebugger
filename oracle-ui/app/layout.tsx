import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ORACLE | Android Network Forensics",
  description: "Cryptographically audited extraction, correlation, and reporting of network activity evidence from Android devices.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
