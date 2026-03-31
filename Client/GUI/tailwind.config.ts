import type { Config } from "tailwindcss";
import { nextui } from "@nextui-org/theme";

export default {
  content: [
    "./src/renderer/**/*.{ts,tsx,html}",
    "./node_modules/@nextui-org/theme/dist/**/*.{js,ts,jsx,tsx}"
  ],
  theme: {
    extend: {
      fontFamily: {
        display: ["Space Grotesk", "ui-sans-serif", "system-ui"],
        body: ["Manrope", "ui-sans-serif", "system-ui"]
      },
      colors: {
        surface: "rgb(var(--color-surface) / <alpha-value>)",
        base: "rgb(var(--color-base) / <alpha-value>)",
        muted: "rgb(var(--color-muted) / <alpha-value>)",
        accent: "rgb(var(--color-accent) / <alpha-value>)",
        accentSoft: "rgb(var(--color-accent-soft) / <alpha-value>)",
        success: "rgb(var(--color-success) / <alpha-value>)",
        warning: "rgb(var(--color-warning) / <alpha-value>)",
        danger: "rgb(var(--color-danger) / <alpha-value>)"
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(90, 130, 255, 0.25), 0 12px 40px rgba(0, 0, 0, 0.35)",
        soft: "0 10px 30px rgba(12, 24, 38, 0.55)"
      },
      backgroundImage: {
        "radial-top": "radial-gradient(1200px 600px at 20% -10%, rgba(56, 104, 255, 0.28), transparent)",
        "radial-right": "radial-gradient(900px 600px at 110% 20%, rgba(120, 155, 255, 0.22), transparent)",
        "grid": "linear-gradient(to right, rgba(255,255,255,0.04) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.04) 1px, transparent 1px)"
      },
      animation: {
        "fade-in": "fadeIn 0.4s ease-out",
        "slide-up": "slideUp 0.5s ease-out",
        "pulse-soft": "pulseSoft 2.5s ease-in-out infinite"
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" }
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" }
        },
        pulseSoft: {
          "0%": { opacity: "0.6" },
          "50%": { opacity: "1" },
          "100%": { opacity: "0.6" }
        }
      }
    }
  },
  darkMode: "class",
  plugins: [nextui()]
} satisfies Config;
