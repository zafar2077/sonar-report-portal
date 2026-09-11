import type { Metadata } from "next";
import { Raleway } from "next/font/google";
import "./globals.css";
import "./accounts.css";

const raleway = Raleway({
  subsets: ["latin"],
  variable: "--font-raleway",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Codebase Technologies - Code Quality Portal",
  description: "You code, We correct",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${raleway.variable} antialiased`}>
        {children}
      </body>
    </html>
  );
}
