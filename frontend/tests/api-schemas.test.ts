import { describe, expect, it } from "vitest";

import {
  authResponseSchema,
  paginatedUsersSchema,
  refreshTokenFromSetCookie,
  searchResultsSchema,
  userProfileSchema,
} from "@/lib/api-schemas";

const PROFILE = {
  id: "9f1f2c3d-0000-4000-8000-000000000001",
  email: "alice@example.com",
  display_name: "Alice",
  role: "user",
  created_at: "2026-06-11T10:00:00Z",
  updated_at: "2026-06-11T10:00:00Z",
};

/**
 * On ne fait pas confiance au backend : toute réponse hors contrat est
 * rejetée avant d'atteindre le rendu.
 */
describe("schémas de réponse API", () => {
  it("accepte un profil conforme", () => {
    expect(userProfileSchema.safeParse(PROFILE).success).toBe(true);
  });

  it("rejette un id non-UUID ou un rôle inconnu", () => {
    expect(userProfileSchema.safeParse({ ...PROFILE, id: "1" }).success).toBe(false);
    expect(
      userProfileSchema.safeParse({ ...PROFILE, role: "superadmin" }).success,
    ).toBe(false);
  });

  it("accepte une réponse d'auth conforme et rejette les anomalies", () => {
    const ok = {
      access_token: "jwt",
      token_type: "Bearer",
      expires_in: 900,
      user: PROFILE,
    };
    expect(authResponseSchema.safeParse(ok).success).toBe(true);
    expect(
      authResponseSchema.safeParse({ ...ok, access_token: "" }).success,
    ).toBe(false);
    expect(
      authResponseSchema.safeParse({ ...ok, token_type: "Basic" }).success,
    ).toBe(false);
    expect(
      authResponseSchema.safeParse({ ...ok, expires_in: -1 }).success,
    ).toBe(false);
  });

  it("valide l'enveloppe paginée et ses bornes", () => {
    const ok = { items: [PROFILE], page: 1, page_size: 20, total: 1 };
    expect(paginatedUsersSchema.safeParse(ok).success).toBe(true);
    expect(
      paginatedUsersSchema.safeParse({ ...ok, page_size: 1000 }).success,
    ).toBe(false);
    expect(paginatedUsersSchema.safeParse({ ...ok, total: -1 }).success).toBe(false);
  });
});

describe("schéma de résultats de recherche", () => {
  const HIT = {
    id: "doc-1",
    score: 1.5,
    title: "Bonjour",
    tags: ["news", "fr"],
    created_at: 1_700_000_000,
  };

  it("accepte une enveloppe de recherche conforme (user)", () => {
    const ok = { items: [HIT], total: 1, page: 1, page_size: 10 };
    expect(searchResultsSchema.safeParse(ok).success).toBe(true);
  });

  it("accepte un score null et un hit admin avec body", () => {
    const ok = {
      items: [{ ...HIT, score: null, body: "contenu" }],
      total: 1,
      page: 1,
      page_size: 10,
    };
    expect(searchResultsSchema.safeParse(ok).success).toBe(true);
  });

  it("rejette un total négatif ou une page nulle", () => {
    const base = { items: [], total: 0, page: 1, page_size: 10 };
    expect(searchResultsSchema.safeParse({ ...base, total: -1 }).success).toBe(
      false,
    );
    expect(searchResultsSchema.safeParse({ ...base, page: 0 }).success).toBe(
      false,
    );
  });
});

describe("refreshTokenFromSetCookie", () => {
  it("extrait le refresh token du Set-Cookie backend", () => {
    expect(
      refreshTokenFromSetCookie([
        "refresh_token=abc123; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth; Max-Age=1209600",
      ]),
    ).toBe("abc123");
  });

  it("ignore les autres cookies et le cookie de suppression (valeur vide)", () => {
    expect(refreshTokenFromSetCookie(["other=1; HttpOnly"])).toBeUndefined();
    expect(
      refreshTokenFromSetCookie(["refresh_token=; Max-Age=0; Path=/api/v1/auth"]),
    ).toBeUndefined();
    expect(refreshTokenFromSetCookie([])).toBeUndefined();
  });

  it("trouve le bon cookie parmi plusieurs en-têtes", () => {
    expect(
      refreshTokenFromSetCookie([
        "trace=xyz; Path=/",
        "refresh_token=tok-2; HttpOnly; Path=/api/v1/auth",
      ]),
    ).toBe("tok-2");
  });
});
