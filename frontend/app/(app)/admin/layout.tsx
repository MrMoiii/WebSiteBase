import type { ReactNode } from "react";
import { notFound } from "next/navigation";

import { requireAuth } from "@/lib/auth";

/**
 * Layout de la zone admin : session exigée ET rôle admin.
 *
 * Un utilisateur authentifié non-admin reçoit un 404 générique : on ne
 * révèle pas l'existence de la zone d'administration. Ce contrôle est de la
 * défense en profondeur — l'autorité réelle est le backend, qui revérifie le
 * rôle EN BASE à chaque appel admin (un rôle révoqué est effectif au plus
 * tard à l'expiration de l'access token, ~15 min).
 */
export default async function AdminLayout({
  children,
}: Readonly<{ children: ReactNode }>) {
  const ctx = await requireAuth("/admin/users");
  if (ctx.user.role !== "admin") {
    notFound();
  }
  return <>{children}</>;
}
