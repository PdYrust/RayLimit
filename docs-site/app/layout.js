import "./globals.css";
import { withBasePath } from "../lib/base-path";

export const metadata = {
  metadataBase: new URL("https://pdyrust.github.io/RayLimit/"),
  title: {
    default: "RayLimit Documentation",
    template: "%s · RayLimit",
  },
  description:
    "Documentation for RayLimit, a Linux CLI for discovering Xray runtimes and applying guarded speed limiters.",
  openGraph: {
    type: "website",
    url: "https://pdyrust.github.io/RayLimit/",
    siteName: "RayLimit",
    title: "RayLimit Documentation",
    description:
      "Documentation for RayLimit, a Linux CLI for discovering Xray runtimes and applying guarded speed limiters.",
    images: [
      {
        url: "og-preview.png",
        width: 1200,
        height: 630,
        alt: "RayLimit documentation preview",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "RayLimit Documentation",
    description:
      "Documentation for RayLimit, a Linux CLI for discovering Xray runtimes and applying guarded speed limiters.",
    images: ["og-preview.png"],
  },
  icons: {
    icon: [
      { url: withBasePath("/raylimit-icon.png"), type: "image/png" },
      { url: withBasePath("/raylimit-icon.svg"), type: "image/svg+xml" },
    ],
    apple: [{ url: withBasePath("/raylimit-icon.png"), type: "image/png" }],
    shortcut: [withBasePath("/raylimit-icon.png")],
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
