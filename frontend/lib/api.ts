import "server-only";

import { z } from "zod";

import {
  apiErrorBodySchema,
  authResponseSchema,
  paginatedUsersSchema,
  refreshTokenFromSetCookie,
  searchResultsSchema,
  userProfileSchema,
  type ApiAuthResponse,
  type ApiPaginatedUsers,
  type ApiSearchResults,
  type ApiUserProfile,
} from "./api-schemas";
import { env } from "./env";
import { logger } from "./logger";

/**
 * Client typé de l'API Axum — exécuté EXCLUSIVEMENT côté serveur
 * (`server-only` fait échouer la compilation si ce module atteint un
 * composant client). C'est la seule porte vers le backend : le navigateur
 * ne connaît ni l'URL de l'API ni les tokens (pattern BFF).
 *
 * Chaque réponse est validée par zod avant usage (exigence : ne pas faire
 * confiance au backend), chaque appel propage le correlation id via
 * X-Request-Id (exigence #6).
 */

/** Codes d'erreur stables exposés par le backend, plus nos codes locaux. */
export type ApiErrorCode =
  | "validation_error"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "too_many_requests"
  | "payload_too_large"
  | "bad_request"
  | "internal_error"
  | "unreachable" // l'API ne répond pas (réseau, panne)
  | "invalid_response"; // réponse hors contrat (rejetée par zod)

/**
 * Erreur d'appel API. `code` et `status` sont sûrs à exposer au client ;
 * tout détail technique est loggé côté serveur uniquement.
 */
export class ApiClientError extends Error {
  constructor(
    readonly status: number,
    readonly code: ApiErrorCode,
  ) {
    super(`api error: ${status} ${code}`);
    this.name = "ApiClientError";
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH";
  /** Corps JSON (objets construits par nos soins, jamais du JSON brut client). */
  body?: Record<string, unknown>;
  /** JWT d'accès -> en-tête Authorization: Bearer. */
  accessToken?: string;
  /** Refresh token -> cookie attendu par /auth/refresh et /auth/logout. */
  refreshToken?: string;
  /** Correlation id propagé au backend (en-tête X-Request-Id). */
  requestId: string;
}

/** Timeout local : ne pas rester suspendu si l'API ne répond plus. */
const API_TIMEOUT_MS = 10_000;

async function apiFetch(path: string, opts: RequestOptions): Promise<Response> {
  // URL construite à partir de chemins CONSTANTS définis dans ce module ;
  // aucune donnée utilisateur n'est concaténée dans l'URL (les paramètres
  // dynamiques passent par URLSearchParams, cf. listUsers).
  const url = `${env().API_BASE_URL}${path}`;

  const headers = new Headers({
    accept: "application/json",
    "x-request-id": opts.requestId,
  });
  if (opts.body !== undefined) {
    headers.set("content-type", "application/json");
  }
  if (opts.accessToken !== undefined) {
    headers.set("authorization", `Bearer ${opts.accessToken}`);
  }
  if (opts.refreshToken !== undefined) {
    // Le BFF joue le rôle du navigateur vis-à-vis de l'API : il présente le
    // refresh token via le cookie attendu par le backend.
    headers.set("cookie", `refresh_token=${opts.refreshToken}`);
  }

  try {
    return await fetch(url, {
      method: opts.method ?? "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : null,
      // Jamais de cache : réponses authentifiées et personnalisées.
      cache: "no-store",
      redirect: "error", // l'API ne redirige jamais ; une redirection est suspecte
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
  } catch (cause) {
    logger.error("API injoignable", {
      requestId: opts.requestId,
      path,
      detail: cause instanceof Error ? cause.message : String(cause),
    });
    throw new ApiClientError(503, "unreachable");
  }
}

/** Transforme une réponse non-2xx en ApiClientError (code générique sûr). */
async function toApiError(res: Response, requestId: string, path: string): Promise<ApiClientError> {
  let code: ApiErrorCode = "internal_error";
  try {
    const parsed = apiErrorBodySchema.safeParse(await res.json());
    if (parsed.success) {
      code = parsed.data.error.code as ApiErrorCode;
    }
  } catch {
    // Corps illisible : on garde le code générique.
  }
  logger.warn("réponse d'erreur de l'API", {
    requestId,
    path,
    status: res.status,
    code,
  });
  return new ApiClientError(res.status, code);
}

/** Parse + valide un corps JSON avec zod ; rejette toute réponse hors contrat. */
async function parseBody<T>(
  res: Response,
  schema: z.ZodType<T>,
  requestId: string,
  path: string,
): Promise<T> {
  let json: unknown;
  try {
    json = await res.json();
  } catch {
    logger.error("corps de réponse API illisible", { requestId, path });
    throw new ApiClientError(502, "invalid_response");
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    // Le détail du mismatch reste côté serveur (peut contenir des données).
    logger.error("réponse API hors contrat (rejetée par zod)", {
      requestId,
      path,
      issues: parsed.error.issues.map((i) => i.path.join(".")).join(","),
    });
    throw new ApiClientError(502, "invalid_response");
  }
  return parsed.data;
}

/** Résultat d'un flux d'authentification : tokens + profil. */
export interface AuthSuccess {
  auth: ApiAuthResponse;
  /** Refresh token capturé dans le Set-Cookie du backend. */
  refreshToken: string;
}

async function authFlow(
  path: string,
  opts: RequestOptions,
): Promise<AuthSuccess> {
  const res = await apiFetch(path, opts);
  if (!res.ok) {
    throw await toApiError(res, opts.requestId, path);
  }
  const auth = await parseBody(res, authResponseSchema, opts.requestId, path);
  const refreshToken = refreshTokenFromSetCookie(res.headers.getSetCookie());
  if (refreshToken === undefined) {
    logger.error("réponse d'auth sans cookie refresh_token", {
      requestId: opts.requestId,
      path,
    });
    throw new ApiClientError(502, "invalid_response");
  }
  return { auth, refreshToken };
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export async function apiRegister(
  input: { email: string; password: string; displayName?: string },
  requestId: string,
): Promise<AuthSuccess> {
  const body: Record<string, unknown> = {
    email: input.email,
    password: input.password,
  };
  if (input.displayName !== undefined) {
    body.display_name = input.displayName;
  }
  return authFlow("/api/v1/auth/register", { method: "POST", body, requestId });
}

export async function apiLogin(
  input: { email: string; password: string },
  requestId: string,
): Promise<AuthSuccess> {
  return authFlow("/api/v1/auth/login", {
    method: "POST",
    body: { email: input.email, password: input.password },
    requestId,
  });
}

export async function apiRefresh(
  refreshToken: string,
  requestId: string,
): Promise<AuthSuccess> {
  return authFlow("/api/v1/auth/refresh", {
    method: "POST",
    refreshToken,
    requestId,
  });
}

/** Révoque le refresh token côté backend. Idempotent, jamais bloquant. */
export async function apiLogout(
  refreshToken: string,
  requestId: string,
): Promise<void> {
  const res = await apiFetch("/api/v1/auth/logout", {
    method: "POST",
    refreshToken,
    requestId,
  });
  if (!res.ok) {
    // Échec non bloquant : la session locale est détruite quoi qu'il arrive,
    // mais on trace l'anomalie (le token resterait actif côté backend).
    logger.warn("échec de révocation du refresh token", {
      requestId,
      status: res.status,
    });
  }
}

export async function apiGetMe(
  accessToken: string,
  requestId: string,
): Promise<ApiUserProfile> {
  const path = "/api/v1/users/me";
  const res = await apiFetch(path, { accessToken, requestId });
  if (!res.ok) {
    throw await toApiError(res, requestId, path);
  }
  return parseBody(res, userProfileSchema, requestId, path);
}

export async function apiUpdateMe(
  accessToken: string,
  input: { displayName: string | null },
  requestId: string,
): Promise<ApiUserProfile> {
  const path = "/api/v1/users/me";
  const res = await apiFetch(path, {
    method: "PATCH",
    accessToken,
    body: { display_name: input.displayName },
    requestId,
  });
  if (!res.ok) {
    throw await toApiError(res, requestId, path);
  }
  return parseBody(res, userProfileSchema, requestId, path);
}

/** Paramètres de recherche acceptés par le BFF (déjà validés en amont). */
export interface SearchQuery {
  q: string;
  page: number;
  pageSize: number;
  sort?: "created_at" | "title.raw" | "_score";
  order?: "asc" | "desc";
  /** Tags séparés par des virgules (filtre exact côté backend). */
  tags?: string;
}

/**
 * Recherche via le backend (seule porte vers OpenSearch — le navigateur n'a
 * jamais ni l'URL ni les credentials du cluster). Tous les paramètres sont
 * encodés par URLSearchParams : aucune concaténation de chaîne client, et le
 * backend revalide + interdit le DSL brut.
 */
export async function apiSearch(
  accessToken: string,
  query: SearchQuery,
  requestId: string,
): Promise<ApiSearchResults> {
  const params = new URLSearchParams({
    q: query.q,
    page: String(query.page),
    page_size: String(query.pageSize),
  });
  if (query.sort !== undefined) params.set("sort", query.sort);
  if (query.order !== undefined) params.set("order", query.order);
  if (query.tags !== undefined && query.tags.length > 0) {
    params.set("tags", query.tags);
  }

  const path = `/api/v1/search?${params.toString()}`;
  const res = await apiFetch(path, { accessToken, requestId });
  if (!res.ok) {
    throw await toApiError(res, requestId, path);
  }
  return parseBody(res, searchResultsSchema, requestId, path);
}

export async function apiListUsers(
  accessToken: string,
  pagination: { page: number; pageSize: number },
  requestId: string,
): Promise<ApiPaginatedUsers> {
  // Les paramètres sont des nombres déjà validés par zod (cf. page admin) et
  // encodés par URLSearchParams — pas de concaténation de chaîne utilisateur.
  const params = new URLSearchParams({
    page: String(pagination.page),
    page_size: String(pagination.pageSize),
  });
  const path = `/api/v1/admin/users?${params.toString()}`;
  const res = await apiFetch(path, { accessToken, requestId });
  if (!res.ok) {
    throw await toApiError(res, requestId, path);
  }
  return parseBody(res, paginatedUsersSchema, requestId, path);
}
