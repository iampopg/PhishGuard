import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0a0e16", bg2: "#0e1320", surface: "#141b2b", surface2: "#1a2233",
        border: "#222c40", border2: "#2c3852",
        text: "#e7edf6", muted: "#90a0b8", muted2: "#5f7088",
        accent: "#3b82f6", accent2: "#06b6d4",
        safe: "#10b981", suspicious: "#f59e0b", phishing: "#f97316", malicious: "#ef4444",
      },
      fontFamily: { mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"] },
    },
  },
  plugins: [],
};
export default config;
