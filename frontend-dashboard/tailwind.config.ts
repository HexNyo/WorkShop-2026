import type { Config } from "tailwindcss";

// Les couleurs sont des jetons CSS (src/index.css) : clair/sombre basculent en un seul endroit.
const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "media",
  theme: {
    extend: {
      colors: {
        page: token("page"),
        surface: token("surface"),
        "surface-2": token("surface-2"),
        ink: token("ink"),
        "ink-2": token("ink-2"),
        muted: token("muted"),
        line: token("line"),
        accent: token("accent"),
        "accent-ink": token("accent-ink"),
        good: token("good"),
        warning: token("warning"),
        serious: token("serious"),
        critical: token("critical"),
        neutral: token("neutral"),
      },
      fontFamily: {
        sans: ["system-ui", "-apple-system", '"Segoe UI"', "sans-serif"],
        mono: ["ui-monospace", '"Cascadia Code"', "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
} satisfies Config;
