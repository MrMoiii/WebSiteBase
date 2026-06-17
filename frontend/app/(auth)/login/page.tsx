import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { LoginForm } from "@/components/auth/login-form";
import { safeNextPath } from "@/lib/redirect";
import { getSession, isAuthenticated } from "@/lib/session";

export const metadata: Metadata = { title: "Connexion" };

/**
 * Page de connexion. Les query params sont des DONNÉES NON FIABLES :
 * - `next` est validé contre la liste blanche (anti open-redirect, #4) ;
 * - `reason` est réduit à un booléen (jamais réaffiché tel quel).
 */
export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const nextPath = safeNextPath(params.next);
  const expired = params.reason === "expired";

  // Déjà connecté ? Inutile de remontrer le formulaire.
  const session = await getSession();
  if (isAuthenticated(session)) {
    redirect(nextPath);
  }

  return (
    <section className="mx-auto max-w-md space-y-6">
      <h1 className="text-2xl font-bold">Connexion</h1>
      <LoginForm nextPath={nextPath} expired={expired} />
      <p className="text-sm text-slate-600">
        Pas encore de compte ?{" "}
        <Link href="/register" className="text-blue-700 underline">
          Créer un compte
        </Link>
      </p>
    </section>
  );
}
