import { describe, expect, it } from "vitest";

import {
  HONEYPOT_FIELD,
  isHoneypotTriggered,
  loginSchema,
  profileSchema,
  registerSchema,
} from "@/lib/schemas";

/** Validation des formulaires : bornes alignées sur les DTO du backend (#7). */
describe("loginSchema", () => {
  it("accepte des identifiants valides", () => {
    expect(
      loginSchema.safeParse({ email: "a@b.fr", password: "x".repeat(20) })
        .success,
    ).toBe(true);
  });

  it("rejette un email invalide ou trop long", () => {
    expect(loginSchema.safeParse({ email: "nope", password: "x" }).success).toBe(false);
    expect(
      loginSchema.safeParse({
        email: `${"a".repeat(320)}@b.fr`,
        password: "x",
      }).success,
    ).toBe(false);
  });

  it("rejette un mot de passe vide ou démesuré (anti-DoS)", () => {
    expect(loginSchema.safeParse({ email: "a@b.fr", password: "" }).success).toBe(false);
    expect(
      loginSchema.safeParse({ email: "a@b.fr", password: "x".repeat(129) })
        .success,
    ).toBe(false);
  });
});

describe("registerSchema", () => {
  it("exige 12 caractères minimum pour le mot de passe", () => {
    expect(
      registerSchema.safeParse({ email: "a@b.fr", password: "court" }).success,
    ).toBe(false);
    expect(
      registerSchema.safeParse({
        email: "a@b.fr",
        password: "mot-de-passe-long-123",
      }).success,
    ).toBe(true);
  });

  it("transforme un nom d'affichage vide en champ omis", () => {
    const parsed = registerSchema.parse({
      email: "a@b.fr",
      password: "mot-de-passe-long-123",
      displayName: "   ",
    });
    expect(parsed.displayName).toBeUndefined();
  });

  it("borne le nom d'affichage à 100 caractères", () => {
    expect(
      registerSchema.safeParse({
        email: "a@b.fr",
        password: "mot-de-passe-long-123",
        displayName: "x".repeat(101),
      }).success,
    ).toBe(false);
  });
});

describe("profileSchema", () => {
  it("transforme un champ vide en null (suppression du nom)", () => {
    expect(profileSchema.parse({ displayName: "" }).displayName).toBeNull();
    expect(profileSchema.parse({ displayName: "  " }).displayName).toBeNull();
  });

  it("conserve un nom valide (trim)", () => {
    expect(profileSchema.parse({ displayName: " Alice " }).displayName).toBe("Alice");
  });
});

describe("honeypot", () => {
  it("détecte un champ honeypot rempli (bot)", () => {
    const fd = new FormData();
    fd.set(HONEYPOT_FIELD, "http://spam.example");
    expect(isHoneypotTriggered(fd)).toBe(true);
  });

  it("laisse passer un formulaire humain (champ vide ou absent)", () => {
    const empty = new FormData();
    expect(isHoneypotTriggered(empty)).toBe(false);
    empty.set(HONEYPOT_FIELD, "");
    expect(isHoneypotTriggered(empty)).toBe(false);
  });
});
