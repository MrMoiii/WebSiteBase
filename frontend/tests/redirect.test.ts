import { describe, expect, it } from "vitest";

import { DEFAULT_AFTER_LOGIN, safeNextPath } from "@/lib/redirect";

/**
 * Anti open-redirect : tout candidat hors liste blanche retombe sur la
 * destination par défaut (exigence sécurité #4).
 */
describe("safeNextPath", () => {
  it("accepte les chemins de la liste blanche", () => {
    expect(safeNextPath("/profile")).toBe("/profile");
    expect(safeNextPath("/admin")).toBe("/admin");
    expect(safeNextPath("/admin/users")).toBe("/admin/users");
    expect(safeNextPath("/")).toBe("/");
  });

  it("ignore query et fragment mais garde le chemin", () => {
    expect(safeNextPath("/admin/users?page=2")).toBe("/admin/users");
    expect(safeNextPath("/profile#section")).toBe("/profile");
  });

  it("rejette les URL absolues externes", () => {
    expect(safeNextPath("https://evil.example")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("http://evil.example/profile")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("javascript:alert(1)")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("mailto:a@b.c")).toBe(DEFAULT_AFTER_LOGIN);
  });

  it("rejette les URL scheme-relative et variantes backslash", () => {
    expect(safeNextPath("//evil.example")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("//evil.example/profile")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/\\evil.example")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("\\/evil.example")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/profile\\..\\admin")).toBe(DEFAULT_AFTER_LOGIN);
  });

  it("rejette les encodages dangereux et caractères de contrôle", () => {
    expect(safeNextPath("/%2F%2Fevil.example")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/%2f%2fevil.example")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/%5Cevil.example")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/profile%00")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/profile\r\nSet-Cookie: x=y")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/profile\nlocation: https://evil")).toBe(DEFAULT_AFTER_LOGIN);
  });

  it("rejette la traversée de chemin", () => {
    expect(safeNextPath("/admin/../profile")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/./profile")).toBe(DEFAULT_AFTER_LOGIN);
  });

  it("rejette les chemins internes hors liste blanche", () => {
    expect(safeNextPath("/api/health")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/login")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/profilesque")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("/adminx")).toBe(DEFAULT_AFTER_LOGIN);
  });

  it("rejette les entrées non-chaîne, vides ou démesurées", () => {
    expect(safeNextPath(undefined)).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath(null)).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath(["/profile"])).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("")).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath(`/${"a".repeat(600)}`)).toBe(DEFAULT_AFTER_LOGIN);
    expect(safeNextPath("profile")).toBe(DEFAULT_AFTER_LOGIN);
  });
});
