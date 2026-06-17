import { expect, test } from "@playwright/test";

import {
  E2E_PASSWORD,
  loginViaUi,
  registerViaApi,
  registerViaUi,
  uniqueEmail,
} from "./helpers";

/** Parcours nominaux : inscription, profil, édition, logout, login + retour. */

test("inscription -> profil -> édition -> logout -> login avec retour post-auth", async ({
  page,
}) => {
  const email = uniqueEmail("nominal");

  // Inscription : arrivée sur le profil, email visible.
  await registerViaUi(page, email, "Alice E2E");
  await expect(page.getByText(email)).toBeVisible();
  await expect(page.getByText("Alice E2E")).toBeVisible();

  // Édition du profil.
  await page.getByLabel("Nom d'affichage").fill("Alice Renommée");
  await page.getByRole("button", { name: "Enregistrer" }).click();
  await expect(page.getByText("Profil mis à jour.")).toBeVisible();
  await page.goto("/profile");
  await expect(page.getByText("Alice Renommée")).toBeVisible();

  // Logout : retour login, plus d'accès au profil.
  await page.getByRole("button", { name: "Se déconnecter" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/profile");
  await expect(page).toHaveURL(/\/login\?next=%2Fprofile/);

  // Login avec retour post-auth vers la page initialement demandée.
  await page.getByLabel("Adresse email").fill(email);
  await page.getByLabel("Mot de passe").fill(E2E_PASSWORD);
  await page.getByRole("button", { name: "Se connecter" }).click();
  await expect(page).toHaveURL(/\/profile$/);
});

test("login avec mauvais mot de passe -> message générique, pas d'oracle", async ({
  page,
  request,
}) => {
  const email = uniqueEmail("wrongpw");
  await registerViaApi(request, email);

  await loginViaUi(page, email, "mauvais-mot-de-passe-123");
  await expect(page.getByText("Email ou mot de passe incorrect.")).toBeVisible();

  // Même message pour un compte inexistant (anti-énumération).
  await loginViaUi(page, uniqueEmail("ghost"), "mauvais-mot-de-passe-123");
  await expect(page.getByText("Email ou mot de passe incorrect.")).toBeVisible();
});

test("validation client : mot de passe trop court signalé sans appel serveur", async ({
  page,
}) => {
  await page.goto("/register");
  await page.getByLabel("Adresse email").fill(uniqueEmail("shortpw"));
  await page.getByLabel("Mot de passe").fill("court");
  await page.getByRole("button", { name: "Créer mon compte" }).click();
  await expect(
    page.getByText("Le mot de passe doit faire au moins 12 caractères."),
  ).toBeVisible();
  await expect(page).toHaveURL(/\/register/);
});

/**
 * Listing admin : nécessite un compte promu admin (UPDATE SQL hors API).
 * Fournir E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD (cf. README et CI).
 */
test("un admin voit le listing paginé des utilisateurs", async ({ page }) => {
  const adminEmail = process.env.E2E_ADMIN_EMAIL;
  const adminPassword = process.env.E2E_ADMIN_PASSWORD;
  test.skip(!adminEmail || !adminPassword, "identifiants admin non fournis");

  await loginViaUi(page, adminEmail as string, adminPassword as string);
  await expect(page).toHaveURL(/\/profile$/);

  await page.goto("/admin/users");
  await expect(page.getByRole("heading", { name: "Utilisateurs" })).toBeVisible();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.getByText(adminEmail as string).first()).toBeVisible();

  // Un numéro de page hostile est neutralisé (zod -> page 1).
  await page.goto("/admin/users?page=--1%20OR%201=1");
  await expect(page.getByText(/Page 1 sur/)).toBeVisible();
});
