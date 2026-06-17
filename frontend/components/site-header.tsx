import Link from "next/link";

import { logoutAction } from "@/app/actions/auth";
import { getSession, isAuthenticated } from "@/lib/session";

/**
 * En-tête du site (Server Component).
 *
 * Les liens affichés dépendent de la session, mais ce n'est que de
 * l'ERGONOMIE : chaque page protégée revérifie la session côté serveur et
 * le backend revérifie rôle + token à chaque appel. Masquer le lien admin
 * d'un non-admin n'est pas un contrôle de sécurité (exigence auth #4).
 */
export async function SiteHeader() {
  const session = await getSession();
  const authed = isAuthenticated(session);

  return (
    <header className="border-b border-slate-200 bg-white">
      <nav
        aria-label="Navigation principale"
        className="mx-auto flex w-full max-w-4xl items-center justify-between gap-4 px-4 py-3"
      >
        <Link href="/" className="text-lg font-semibold text-slate-900">
          WebSiteBase
        </Link>
        <ul className="flex items-center gap-4 text-sm">
          {authed ? (
            <>
              <li>
                <Link
                  href="/search"
                  className="text-slate-700 hover:text-slate-900 hover:underline"
                >
                  Recherche
                </Link>
              </li>
              <li>
                <Link
                  href="/profile"
                  className="text-slate-700 hover:text-slate-900 hover:underline"
                >
                  Mon profil
                </Link>
              </li>
              {session.user.role === "admin" ? (
                <li>
                  <Link
                    href="/admin/users"
                    className="text-slate-700 hover:text-slate-900 hover:underline"
                  >
                    Administration
                  </Link>
                </li>
              ) : null}
              <li>
                {/* Mutation -> Server Action POST (jamais un simple lien GET). */}
                <form action={logoutAction}>
                  <button
                    type="submit"
                    className="rounded border border-slate-300 px-3 py-1.5 text-slate-700 hover:bg-slate-100"
                  >
                    Se déconnecter
                  </button>
                </form>
              </li>
            </>
          ) : (
            <>
              <li>
                <Link
                  href="/login"
                  className="text-slate-700 hover:text-slate-900 hover:underline"
                >
                  Connexion
                </Link>
              </li>
              <li>
                <Link
                  href="/register"
                  className="rounded bg-blue-700 px-3 py-1.5 font-medium text-white hover:bg-blue-800"
                >
                  Créer un compte
                </Link>
              </li>
            </>
          )}
        </ul>
      </nav>
    </header>
  );
}
