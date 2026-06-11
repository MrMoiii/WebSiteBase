import { defineConfig, devices } from "@playwright/test";

/**
 * E2E contre le build de PRODUCTION (`next start`) : on teste l'application
 * telle que déployée, CSP stricte comprise. Prérequis :
 *  - `npm run build` exécuté au préalable ;
 *  - le backend Axum + sa base accessibles via API_BASE_URL (cf. README,
 *    `docker compose up` dans backend/ suffit) ;
 * Les tests admin sont ignorés si E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD ne
 * sont pas fournis (la promotion admin se fait en SQL, hors API).
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false, // le rate limiting backend sur /auth/* n'aime pas les rafales
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "list" : "html",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "npm run start",
    url: "http://localhost:3000/api/health",
    reuseExistingServer: !process.env.CI,
    env: {
      API_BASE_URL: process.env.API_BASE_URL ?? "http://localhost:8080",
      SESSION_SECRET:
        process.env.SESSION_SECRET ?? "e2e_session_secret_at_least_32_chars!",
      COOKIE_SECURE: "false", // E2E en HTTP local
      APP_ALLOWED_ORIGINS: "",
    },
  },
});
