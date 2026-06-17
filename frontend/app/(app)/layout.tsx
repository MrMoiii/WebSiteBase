import type { ReactNode } from "react";

import { requireAuth } from "@/lib/auth";

/**
 * Layout du périmètre authentifié (exigence auth #4 : middleware ET layout).
 *
 * Le middleware a déjà refusé les requêtes sans cookie de session (premier
 * rideau, optimiste). Ici, la session est DÉCHIFFRÉE et vérifiée, avec
 * refresh transparent si l'access token a expiré. Chaque page refait en plus
 * sa propre vérification (les layouts ne se ré-exécutent pas à chaque
 * navigation interne) et le backend revérifie le token à chaque appel.
 */
export default async function ProtectedLayout({
  children,
}: Readonly<{ children: ReactNode }>) {
  await requireAuth("/profile");
  return <>{children}</>;
}
