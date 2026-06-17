import { describe, expect, it } from "vitest";

import { parseEnv } from "@/lib/env";

const VALID = {
  NODE_ENV: "production",
  API_BASE_URL: "http://api:8080",
  SESSION_SECRET: "0123456789abcdef0123456789abcdef",
  COOKIE_SECURE: "true",
};

/** Fail-fast : une configuration invalide doit empêcher le démarrage (#5). */
describe("parseEnv", () => {
  it("accepte une configuration complète", () => {
    const env = parseEnv(VALID);
    expect(env.API_BASE_URL).toBe("http://api:8080");
    expect(env.COOKIE_SECURE).toBe(true);
  });

  it("échoue si une variable obligatoire manque", () => {
    expect(() => parseEnv({ ...VALID, API_BASE_URL: undefined })).toThrow(
      /API_BASE_URL/,
    );
    expect(() => parseEnv({ ...VALID, SESSION_SECRET: undefined })).toThrow(
      /SESSION_SECRET/,
    );
  });

  it("refuse un SESSION_SECRET trop court", () => {
    expect(() => parseEnv({ ...VALID, SESSION_SECRET: "court" })).toThrow(
      /SESSION_SECRET/,
    );
  });

  it("ne divulgue jamais la valeur du secret dans l'erreur", () => {
    try {
      parseEnv({ ...VALID, SESSION_SECRET: "secret-trop-court" });
      expect.unreachable();
    } catch (err) {
      expect((err as Error).message).not.toContain("secret-trop-court");
    }
  });

  it("refuse une API_BASE_URL invalide ou non http(s)", () => {
    expect(() => parseEnv({ ...VALID, API_BASE_URL: "pas-une-url" })).toThrow();
    expect(() => parseEnv({ ...VALID, API_BASE_URL: "ftp://api:21" })).toThrow();
    expect(() =>
      parseEnv({ ...VALID, API_BASE_URL: "http://api:8080/" }),
    ).toThrow(/finir par/);
  });

  it("COOKIE_SECURE vaut true par défaut (sécurisé par défaut)", () => {
    const withoutCookieSecure: Record<string, string | undefined> = {
      ...VALID,
      COOKIE_SECURE: undefined,
    };
    expect(parseEnv(withoutCookieSecure).COOKIE_SECURE).toBe(true);
  });

  it("refuse une valeur COOKIE_SECURE hors true/false", () => {
    expect(() => parseEnv({ ...VALID, COOKIE_SECURE: "yes" })).toThrow();
  });
});
