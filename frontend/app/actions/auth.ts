"use server";

import { redirect } from "next/navigation";
import { z } from "zod";

import { ApiClientError, apiLogin, apiLogout, apiRegister } from "@/lib/api";
import { currentRequestId, establishSession } from "@/lib/auth";
import { assertSameOrigin } from "@/lib/csrf";
import { logger } from "@/lib/logger";
import { safeNextPath } from "@/lib/redirect";
import { isHoneypotTriggered, loginSchema, registerSchema } from "@/lib/schemas";
import { getSession } from "@/lib/session";

/**
 * Server Actions d'authentification. Toutes les règles de sécurité
 * s'appliquent CÔTÉ SERVEUR, quoi que fasse le client :
 * - vérification d'origine (anti-CSRF) en tête de chaque mutation ;
 * - honeypot anti-bot sur les formulaires publics (exigence #7), complété
 *   par le rate limiting par IP du backend sur /auth/* ;
 * - validation zod systématique (la validation client n'est que de l'UX) ;
 * - messages d'erreur GÉNÉRIQUES : ni détail interne, ni indice permettant
 *   d'énumérer les comptes (exigences #6 et anti-énumération du backend).
 */

export interface AuthFormState {
  /** Message d'erreur global, sûr à afficher. */
  error?: string;
  /** Erreurs par champ issues de la validation zod. */
  fieldErrors?: Record<string, string[] | undefined>;
}

/** Messages volontairement génériques (pas d'oracle d'énumération). */
const GENERIC_LOGIN_ERROR = "Email ou mot de passe incorrect.";
const GENERIC_REGISTER_ERROR =
  "Impossible de créer un compte avec ces informations.";
const GENERIC_ERROR = "Une erreur est survenue. Veuillez réessayer plus tard.";
const RATE_LIMIT_ERROR =
  "Trop de tentatives. Veuillez patienter avant de réessayer.";

export async function loginAction(
  _prev: AuthFormState,
  formData: FormData,
): Promise<AuthFormState> {
  await assertSameOrigin();

  if (isHoneypotTriggered(formData)) {
    // Bot probable : réponse générique sans toucher au backend.
    return { error: GENERIC_LOGIN_ERROR };
  }

  const parsed = loginSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });
  if (!parsed.success) {
    return { fieldErrors: z.flattenError(parsed.error).fieldErrors };
  }

  const requestId = await currentRequestId();
  try {
    const result = await apiLogin(parsed.data, requestId);
    const session = await getSession();
    await establishSession(session, result);
  } catch (err) {
    return loginErrorState(err, requestId);
  }

  // Retour post-auth : UNIQUEMENT un chemin interne de la liste blanche
  // (anti open-redirect, exigence #4). Hors du try : redirect() lève.
  redirect(safeNextPath(formData.get("next")));
}

function loginErrorState(err: unknown, requestId: string): AuthFormState {
  if (err instanceof ApiClientError) {
    if (err.status === 401) {
      return { error: GENERIC_LOGIN_ERROR };
    }
    if (err.status === 429) {
      return { error: RATE_LIMIT_ERROR };
    }
    return { error: GENERIC_ERROR };
  }
  logger.error("erreur inattendue au login", {
    requestId,
    detail: err instanceof Error ? err.message : String(err),
  });
  return { error: GENERIC_ERROR };
}

export async function registerAction(
  _prev: AuthFormState,
  formData: FormData,
): Promise<AuthFormState> {
  await assertSameOrigin();

  if (isHoneypotTriggered(formData)) {
    return { error: GENERIC_REGISTER_ERROR };
  }

  const parsed = registerSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
    displayName: formData.get("displayName") ?? "",
  });
  if (!parsed.success) {
    return { fieldErrors: z.flattenError(parsed.error).fieldErrors };
  }

  const requestId = await currentRequestId();
  try {
    const input: { email: string; password: string; displayName?: string } = {
      email: parsed.data.email,
      password: parsed.data.password,
    };
    if (parsed.data.displayName !== undefined) {
      input.displayName = parsed.data.displayName;
    }
    const result = await apiRegister(input, requestId);
    const session = await getSession();
    await establishSession(session, result);
  } catch (err) {
    if (err instanceof ApiClientError) {
      // 409 inclus : message générique, on ne confirme pas qu'un compte existe.
      if (err.status === 409 || err.status === 422) {
        return { error: GENERIC_REGISTER_ERROR };
      }
      if (err.status === 429) {
        return { error: RATE_LIMIT_ERROR };
      }
      return { error: GENERIC_ERROR };
    }
    logger.error("erreur inattendue à l'inscription", {
      requestId,
      detail: err instanceof Error ? err.message : String(err),
    });
    return { error: GENERIC_ERROR };
  }

  redirect(safeNextPath(formData.get("next")));
}

export async function logoutAction(): Promise<void> {
  await assertSameOrigin();

  const session = await getSession();
  const requestId = await currentRequestId();

  // Révocation du refresh token côté backend (best effort : même si l'API
  // est injoignable, la session locale est détruite).
  if (typeof session.refreshToken === "string") {
    try {
      await apiLogout(session.refreshToken, requestId);
    } catch {
      logger.warn("révocation du refresh token impossible au logout", {
        requestId,
      });
    }
  }

  session.destroy();
  redirect("/login");
}
