/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: "#060913",
          card: "#0f1524",
          border: "#1f293d",
          accent: "#00f0ff",
          purple: "#9d4edd",
          danger: "#ff0055",
          success: "#00e676",
          warn: "#f59e0b",
          glow: "rgba(0, 240, 255, 0.15)",
        },
        stage: {
          normal: "#22c55e",
          recon: "#38bdf8",
          access: "#f59e0b",
          lateral: "#f97316",
          c2: "#ef4444",
          exfil: "#ff0055",
        },
      },
      fontFamily: {
        mono: ["'Share Tech Mono'", "monospace"],
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      animation: {
        "pulse-glow": "pulseGlow 2s ease-in-out infinite",
        "scan-line": "scanLine 3s linear infinite",
        "fade-in": "fadeIn 0.5s ease-out",
        "slide-up": "slideUp 0.4s ease-out",
        "slide-right": "slideRight 0.3s ease-out",
        "dash": "dash 1s linear infinite",
      },
      keyframes: {
        pulseGlow: {
          "0%, 100%": { boxShadow: "0 0 0 0px rgba(0, 240, 255, 0.4)" },
          "50%": { boxShadow: "0 0 0 6px rgba(0, 240, 255, 0)" },
        },
        scanLine: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(20px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        slideRight: {
          "0%": { opacity: "0", transform: "translateX(-10px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        dash: {
          "0%": { strokeDashoffset: "8" },
          "100%": { strokeDashoffset: "0" },
        },
      },
    },
  },
  plugins: [],
}
