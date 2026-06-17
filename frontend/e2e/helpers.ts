import { expect, type APIRequestContext, type Page } from "@playwright/test";

/** Génère un email unique par exécution (la base de dev n'est pas purgée). */
export function uniqueEmail(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@e2e.example`;
}

export const E2E_PASSWORD = "mot-de-passe-e2e-123!";

/** Crée un compte via l'UI et attend l'arrivée sur le profil. */
export async function registerViaUi(
  page: Page,
  email: string,
  displayName?: string,
): Promise<void> {
  await page.goto("/register");
  await page.getByLabel("Adresse email").fill(email);
  if (displayName !== undefined) {
    await page.getByLabel(/Nom d'affichage/).fill(displayName);
  }
  await page.getByLabel("Mot de passe").fill(E2E_PASSWORD);
  await page.getByRole("button", { name: "Créer mon compte" }).click();
  await expect(page).toHaveURL(/\/profile$/);
}

/**
 * Crée un compte directement via l'API backend (1 seul appel /auth/*).
 * À préférer quand l'inscription n'est pas l'objet du test : limite la
 * pression sur le rate limiting par IP du backend (2 req/s, burst 10).
 */
export async function registerViaApi(
  request: APIRequestContext,
  email: string,
): Promise<void> {
  const apiBase = process.env.API_BASE_URL ?? "http://localhost:8080";
  const res = await request.post(`${apiBase}/api/v1/auth/register`, {
    data: { email, password: E2E_PASSWORD },
  });
  expect(res.status()).toBe(201);
}

/** Connexion via l'UI (sans présupposer la destination). */
export async function loginViaUi(
  page: Page,
  email: string,
  password: string = E2E_PASSWORD,
): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Adresse email").fill(email);
  await page.getByLabel("Mot de passe").fill(password);
  await page.getByRole("button", { name: "Se connecter" }).click();
}
