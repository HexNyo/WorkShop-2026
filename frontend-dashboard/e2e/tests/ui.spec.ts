import { expect, test, type Page } from "@playwright/test";

const SHOTS = process.env.SHOTS_DIR ?? "artifacts/screenshots";

function secret(username: string): string {
  const value = process.env[`AUTH_BOOTSTRAP_${username.toUpperCase().replaceAll("-", "_")}_SECRET`];
  if (!value) throw new Error(`secret for ${username} missing`);
  return value;
}

async function login(page: Page, username: string): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Identifiant").fill(username);
  await page.getByLabel("Mot de passe").fill(secret(username));
  await page.getByRole("button", { name: "Se connecter" }).click();
  await expect(page.getByRole("button", { name: "Se déconnecter" })).toBeVisible();
}

test.describe.configure({ mode: "serial" });

test.afterEach(async ({ page }, info) => {
  if (info.status !== info.expectedStatus) {
    await page.screenshot({ path: `${SHOTS}/echec-${info.title.slice(0, 40).replace(/[^a-z0-9]+/gi, "-")}.png`, fullPage: true });
  }
});

test("la page de connexion refuse un mauvais mot de passe sans divulguer d'information", async ({ page }) => {
  const csp: string[] = [];
  page.on("console", (message) => message.text().includes("Content Security Policy") && csp.push(message.text()));
  await page.goto("/login");
  await page.getByLabel("Identifiant").fill("alice");
  await page.getByLabel("Mot de passe").fill("certainement-faux");
  await page.getByRole("button", { name: "Se connecter" }).click();
  await expect(page.getByRole("alert")).toContainText("Identifiant ou mot de passe incorrect");
  expect(csp, "no CSP violation").toEqual([]);
});

test("portail métier : paiement exécuté et visible en temps réel, session restaurée au rechargement", async ({ page }) => {
  await login(page, "alice");
  await expect(page).toHaveURL(/\/payments$/);
  await expect(page.getByTestId("balance-RA-1000-0001")).toBeVisible();
  await expect(page.getByTestId("stream-status")).toHaveAttribute("data-status", "open");

  await page.getByLabel("Compte bénéficiaire").fill("RA-1000-0003");
  await page.getByLabel(/Montant/).fill("0.42");
  await page.getByLabel("Libellé (facultatif)").fill("test interface");
  await page.getByRole("button", { name: "Envoyer le paiement" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Exécutée" })).toBeVisible();
  // La ligne arrive par le flux SSE (transaction.created puis transaction.updated).
  await expect(page.getByTestId("transaction-row").first()).toHaveAttribute("data-status", "EXECUTED");
  await page.screenshot({ path: `${SHOTS}/01-portail-metier.png`, fullPage: true });

  await page.getByTestId("transaction-row").first().click();
  await expect(page.getByRole("dialog")).toContainText("Historique");
  await expect(page.getByRole("dialog")).toContainText("Exécutée");
  await page.keyboard.press("Escape");

  await page.reload();
  await expect(page.getByRole("button", { name: "Se déconnecter" })).toBeVisible();
  await expect(page.getByTestId("balance-RA-1000-0001")).toBeVisible();

  await page.goto("/supervision");
  await expect(page.getByText("Accès non autorisé")).toBeVisible();
});

test("console NOC/SOC : état nominal, santé des services et chronologie", async ({ page }) => {
  await login(page, "noc-operator");
  await expect(page).toHaveURL(/\/supervision$/);
  await expect(page.getByTestId("phase-banner")).toBeVisible();
  await expect(page.getByTestId("service-payment-api")).toBeVisible();
  await expect(page.getByTestId("phase-timeline")).toBeVisible();
  await expect(page.getByTestId("stream-status")).toHaveAttribute("data-status", "open");
  await expect(page.getByTestId("chaos-lab")).toHaveCount(0); // réservé à chaos.operator
  await page.getByRole("button", { name: "Vue tableau" }).click();
  await expect(page.getByText("Durée", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Vue frise" }).click();
  await page.screenshot({ path: `${SHOTS}/02-supervision.png`, fullPage: true });
});

test("assistant : dégradation explicite quand l'agent documentaire est absent", async ({ page }) => {
  await login(page, "noc-operator");
  await page.getByRole("link", { name: "Assistant opérateur" }).click();
  await page.getByRole("button", { name: /PB-INTEGRITY-RESTORE/ }).click();
  const messages = page.getByTestId("chat-messages");
  await expect(messages.locator('[data-role="operator"]')).toHaveCount(1);
  await expect(messages.locator('[data-role="system"]').last()).toContainText(/indisponible|playbook/i);
  await page.screenshot({ path: `${SHOTS}/03-assistant.png`, fullPage: true });
});

test("boucle complète : attaque → détection autonome → remédiation → vérification → rétabli", async ({ page }) => {
  test.skip(process.env.CHAOS_LAB_ENABLED !== "true", "laboratoire désactivé");
  test.setTimeout(330_000);
  await login(page, "admin");
  await page.goto("/supervision");
  const banner = page.getByTestId("phase-banner");
  await expect(page.getByTestId("chaos-lab")).toBeVisible();

  // Attaque : altération directe d'un solde. Aucune alerte n'est envoyée par l'interface.
  await page.getByTestId("chaos-tamper").click();
  await expect(page.getByText(/Panne injectée \(BALANCE_TAMPER\)/)).toBeVisible();

  // PENDANT : détection par la transaction synthétique planifiée (≤ 60 s) puis remédiation.
  await expect
    .poll(async () => banner.getAttribute("data-phase"), { timeout: 150_000, intervals: [1000] })
    .toMatch(/CRITICAL|DEGRADED|RECOVERING/);
  await expect(page.getByTestId("incident-panel")).toBeVisible();
  await expect
    .poll(async () => page.getByTestId("remediation-step").count(), { timeout: 60_000, intervals: [500] })
    .toBeGreaterThan(0);
  await page.screenshot({ path: `${SHOTS}/04-pendant-remediation.png`, fullPage: true });

  // APRÈS : clôture uniquement après la vérification synthétique V1→V9.
  await expect(page.getByTestId("incident-panel")).toHaveAttribute("data-status", "RESOLVED", { timeout: 150_000 });
  await expect(page.getByTestId("verification-checklist")).toHaveAttribute("data-status", "PASSED");
  await expect(banner).toHaveAttribute("data-phase", "RESTORED", { timeout: 30_000 });
  await expect(page.getByTestId("remediation-step").filter({ hasText: "repair balances" })).toHaveAttribute("data-status", "SUCCEEDED");
  await page.screenshot({ path: `${SHOTS}/05-apres-retabli.png`, fullPage: true });
});
