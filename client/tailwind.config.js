/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: "#0B0F14",
        surface: "#141A22",
        "surface-2": "#1B2430",
        border: "#262E3A",
        blue: "#22386E",
        "blue-hi": "#3E63C7",
        gold: "#CBA135",
        "gold-hi": "#E0C36A",
        text: "#F3F1EA",
        "text-muted": "#9BA6B4",
        white: "#FFFFFF",
        cyber: {
          dark: "#0B0F14",
          card: "#141A22",
          border: "#262E3A",
          accent: "#CBA135",
          purple: "#22386E",
          danger: "#CBA135",
          success: "#262E3A",
          warn: "#CBA135",
          glow: "transparent",
        },
        stage: {
          normal: "#262E3A",
          recon: "#3E63C7",
          access: "#3E63C7",
          lateral: "#CBA135",
          c2: "#CBA135",
          exfil: "#E0C36A",
        },
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "-apple-system", "Arial", "sans-serif"],
        mono: ["'JetBrains Mono'", "'Share Tech Mono'", "monospace"],
      },
      animation: {
        "scan-line": "scanLine 3s linear infinite",
        "fade-in": "fadeIn 0.5s ease-out",
        "slide-up": "slideUp 0.4s ease-out",
        "slide-right": "slideRight 0.3s ease-out",
        "dash": "dash 1s linear infinite",
      },
      keyframes: {
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
