import "./index.css";
import "./theme-editorial.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { App } from "./App";
import { AuthProvider } from "./auth/AuthProvider";

// Thème éditorial expérimental : ?theme=editorial l'active, ?theme=default revient, mémorisé dans le navigateur.
const requested = new URLSearchParams(location.search).get("theme");
try {
  if (requested) localStorage.setItem("ra.theme", requested);
  if ((requested ?? localStorage.getItem("ra.theme")) === "editorial") {
    document.documentElement.classList.add("editorial");
    // jour/nuit : choix mémorisé (bouton du panneau), sinon réglage du système
    const mode = localStorage.getItem("ra.theme.mode") ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.classList.toggle("ed-dark", mode === "dark");
    // shortcut: polices Google bloquées par la CSP de la passerelle (repli Georgia/Consolas), à auto-héberger si le thème est adopté
    const fonts = document.createElement("link");
    fonts.rel = "stylesheet";
    fonts.href = "https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,300..900;1,9..144,300..900&family=JetBrains+Mono:wght@400;600&display=swap";
    document.head.append(fonts);
  }
} catch {
  // stockage indisponible : thème par défaut
}

const root = document.getElementById("root");
if (!root) throw new Error("#root element missing");

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
