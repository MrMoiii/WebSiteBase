"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { z } from "zod";

import { ApiClientError, apiUpdateMe } from "@/lib/api";
import { getAuthContext, loginRedirectUrl } from "@/lib/auth";
import { assertSameOrigin } from "@/lib/csrf";
import { logger } from "@/lib/logger";
import { profileSchema } from "@/lib/schemas";

export interface ProfileFormState {
  error?: string;
  fieldErrors?: Record<string, string[] | undefined>;
  success?: boolean;
}

const GENERIC_ERROR = "Une erreur est survenue. Veuillez réessayer plus tard.";

/**
 * Mise à jour du profil de l'utilisateur COURANT. L'identité vient de la
 * session serveur (jamais d'un champ du formulaire) et le backend la déduit
 * du token — pas d'IDOR possible.
 */
export async function updateProfileAction(
  _prev: ProfileFormState,
  formData: FormData,
): Promise<ProfileFormState> {
  await assertSameOrigin();

  const parsed = profileSchema.safeParse({
    displayName: formData.get("displayName") ?? "",
  });
  if (!parsed.success) {
    return { fieldErrors: z.flattenError(parsed.error).fieldErrors };
  }

  // Session expirée en cours d'action : on redirige proprement vers le login
  // avec retour post-auth (exigence périmètre fonctionnel).
  const ctx = await getAuthContext();
  if (ctx === null) {
    redirect(loginRedirectUrl("/profile", true));
  }

  try {
    const updated = await apiUpdateMe(
      ctx.accessToken,
      { displayName: parsed.data.displayName },
      ctx.requestId,
    );
    // Rafraîchit l'instantané du profil scellé en session (affichage nav).
    ctx.session.user = {
      id: updated.id,
      email: updated.email,
      displayName: updated.display_name,
      role: updated.role,
    };
    await ctx.session.save();
  } catch (err) {
    if (err instanceof ApiClientError) {
      if (err.status === 401) {
        // Token devenu invalide entre le refresh et l'appel : login requis.
        ctx.session.destroy();
        redirect(loginRedirectUrl("/profile", true));
      }
      if (err.status === 422) {
        return { error: "Nom d'affichage invalide." };
      }
      return { error: GENERIC_ERROR };
    }
    logger.error("erreur inattendue à la mise à jour du profil", {
      requestId: ctx.requestId,
      detail: err instanceof Error ? err.message : String(err),
    });
    return { error: GENERIC_ERROR };
  }

  revalidatePath("/profile");
  return { success: true };
}
