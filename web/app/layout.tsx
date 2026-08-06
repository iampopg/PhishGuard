import "./globals.css";
import { AuthProvider } from "@/components/AuthProvider";

export const metadata = { title: "PhishGuard · Detection Engine", description: "Open-source email phishing detection & analysis console" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
