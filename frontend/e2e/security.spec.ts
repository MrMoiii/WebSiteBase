import { expect, test } from "@playwright/test";

import {
  loginViaUi,
  registerViaApi,
  registerViaUi,
  uniqueEmail,
} from "./helpers";

/**
 * Cas d'ATTAQUE (exigence qualité) : routes protégées sans session, open
 * redirect, XSS, session expirée en cours d'action, cookie falsifié,
 * en-têtes de sécurité.
 */

test.describe("protection des routes", () => {
  test("accès direct à /profile sans session -> redirection login avec retour", async ({
    page,
  }) => {
    await page.goto("/profile");
    await expect(page).toHaveURL(/\/login\?next=%2Fprofile/);
    await expect(page.getByRole("heading", { name: "Connexion" })).toBeVisible();
  });

  test("accès direct à /admin/users sans session -> redirection login", async ({
    page,
  }) => {
    await page.goto("/admin/users");
    await expect(page).toHaveURL(/\/login\?next=%2Fadmin%2Fusers/);
  });

  test("un utilisateur non-admin reçoit un 404 générique sur /admin/users", async ({
    page,
  }) => {
    await registerViaUi(page, uniqueEmail("nonadmin"));
    const response = await page.goto("/admin/users");
    expect(response?.status()).toBe(404);
    await expect(
      page.getByRole("heading", { name: "Page introuvable" }),
    ).toBeVisible();
    // Aucun indice sur l'existence de la zone admin.
    await expect(page.locator("body")).not.toContainText(/non autorisé|admin/i);
  });

  test("cookie de session falsifié -> traité comme non authentifié", async ({
    page,
    context,
  }) => {
    await context.addCookies([
      {
        name: "wsb_session",
        value: "Zm9yZ2VkLXNlc3Npb24tdmFsdWU", // valeur forgée, signature invalide
        url: "http://localhost:3000",
      },
    ]);
    await page.goto("/profile");
    // Le middleware voit un cookie, mais le déchiffrement échoue côté layout.
    await expect(page).toHaveURL(/\/login\?next=%2Fprofile/);
  });
});

test.describe("open redirect", () => {
  // Compte créé directement via l'API backend (un seul appel /auth/*).
  const email = uniqueEmail("redirect");

  test.beforeAll(async ({ request }) => {
    await registerViaApi(request, email);
  });

  const evilTargets = [
    "https://evil.example/phishing",
    "//evil.example",
    "/%2F%2Fevil.example",
    "/\\evil.example",
    "javascript:alert(1)",
  ];

  test("toute cible de redirection externe retombe sur la destination par défaut", async ({
    page,
  }) => {
    // UN SEUL login (évite d'épuiser le rate limiting par IP du backend —
    // 2 req/s, burst 10 — qui rendait la suite instable). Une fois
    // authentifié, la page /login redirige IMMÉDIATEMENT vers
    // safeNextPath(next) côté serveur : on teste donc exactement la même
    // validation anti open-redirect, sans appel /auth/* supplémentaire.
    await loginViaUi(page, email);
    await expect(page).toHaveURL(/^http:\/\/localhost:3000\/profile$/);

    for (const evil of evilTargets) {
      await page.goto(`/login?next=${encodeURIComponent(evil)}`);
      // Jamais vers un domaine externe : retour interne par défaut.
      await expect(page).toHaveURL(/^http:\/\/localhost:3000\/profile$/);
    }
  });
});

test.describe("XSS", () => {
  test("un payload XSS dans le nom d'affichage est rendu inerte", async ({ page }) => {
    const payload = `<img src=x onerror="document.title='XSSED'"><script>document.title='XSSED'</script>`;
    let dialogSeen = false;
    page.on("dialog", async (d) => {
      dialogSeen = true;
      await d.dismiss();
    });

    await registerViaUi(page, uniqueEmail("xss"));
    await page.getByLabel("Nom d'affichage").fill(payload);
    await page.getByRole("button", { name: "Enregistrer" }).click();
    // Confirmation applicative de la sauvegarde. Timeout élargi : sous charge
    // CI, le round-trip de la Server Action peut dépasser les 5 s par défaut
    // (la sauvegarde elle-même ne fait aucun appel /auth/* rate-limité).
    await expect(page.getByText("Profil mis à jour.")).toBeVisible({
      timeout: 15000,
    });

    await page.goto("/profile");
    // Le payload s'affiche LITTÉRALEMENT (échappé par React)…
    await expect(page.locator("dd", { hasText: "onerror" })).toBeVisible();
    // …et ne s'exécute jamais : pas de balise injectée, pas d'effet de bord.
    expect(await page.locator("dl img[src='x']").count()).toBe(0);
    expect(await page.locator("dl script").count()).toBe(0);
    await expect(page).not.toHaveTitle(/XSSED/);
    expect(dialogSeen).toBe(false);
  });
});

test.describe("session expirée en cours d'action", () => {
  test("soumission d'un formulaire après perte de session -> retour login propre", async ({
    page,
    context,
  }) => {
    await registerViaUi(page, uniqueEmail("expired"));

    // La session disparaît PENDANT que le formulaire est ouvert.
    await page.getByLabel("Nom d'affichage").fill("Nouveau nom");
    await context.clearCookies();
    await page.getByRole("button", { name: "Enregistrer" }).click();

    // La Server Action détecte la session absente et redirige proprement.
    await expect(page).toHaveURL(/\/login\?next=%2Fprofile/);
    await expect(
      page.getByText("Votre session a expiré. Veuillez vous reconnecter."),
    ).toBeVisible();
  });
});

test.describe("en-têtes de sécurité", () => {
  test("CSP stricte et en-têtes présents sur les pages", async ({ request }) => {
    const res = await request.get("/");
    const headers = res.headers();

    const csp = headers["content-security-policy"] ?? "";
    expect(csp).toContain("script-src 'self' 'nonce-");
    expect(csp).toContain("'strict-dynamic'");
    expect(csp).not.toContain("unsafe-eval"); // build de production
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("form-action 'self'");

    expect(headers["strict-transport-security"]).toContain("preload");
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers["permissions-policy"]).toContain("camera=()");
    expect(headers["x-frame-options"]).toBe("DENY");
    expect(headers["x-request-id"]).toBeTruthy();
    expect(headers["x-powered-by"]).toBeUndefined();
  });

  test("le cookie de session est HttpOnly et invisible au JavaScript", async ({
    page,
  }) => {
    await registerViaUi(page, uniqueEmail("cookie"));
    const cookies = await page.context().cookies();
    const session = cookies.find((c) => c.name.includes("wsb_session"));
    expect(session).toBeDefined();
    expect(session?.httpOnly).toBe(true);
    expect(session?.sameSite).toBe("Lax");
    // Aucun token accessible côté client : ni cookie lisible, ni storage.
    expect(await page.evaluate(() => document.cookie)).toBe("");
    expect(await page.evaluate(() => window.localStorage.length)).toBe(0);
    expect(await page.evaluate(() => window.sessionStorage.length)).toBe(0);
  });
});
