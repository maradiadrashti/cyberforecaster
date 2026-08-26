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
          dark: "#080b11",
          card: "#0f1524",
          border: "#1f293d",
          accent: "#00f0ff",
          purple: "#9d4edd",
          danger: "#ff0055",
          success: "#00e676"
        }
      }
    },
  },
  plugins: [],
}
