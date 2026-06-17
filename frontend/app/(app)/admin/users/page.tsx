import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { z } from "zod";

import { ApiClientError, apiListUsers } from "@/lib/api";
import { loginRedirectUrl, requireAuth } from "@/lib/auth";

export const metadata: Metadata = { title: "Utilisateurs" };

/**
 * Le numéro de page vient de l'URL : donnée non fiable, validée par zod
 * (entier 1..1e6) avec repli sur 1 — jamais interpolée telle quelle.
 */
const pageParamSchema = z.coerce.number().int().min(1).max(1_000_000).catch(1);

const PAGE_SIZE = 20;

export default async function AdminUsersPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const ctx = await requireAuth("/admin/users");
  // Revérification du rôle au niveau page (les layouts ne se ré-exécutent
  // pas à chaque navigation). 404 générique pour les non-admins.
  if (ctx.user.role !== "admin") {
    notFound();
  }

  const params = await searchParams;
  const page = pageParamSchema.parse(params.page);

  let data;
  try {
    data = await apiListUsers(
      ctx.accessToken,
      { page, pageSize: PAGE_SIZE },
      ctx.requestId,
    );
  } catch (err) {
    if (err instanceof ApiClientError) {
      if (err.status === 401) {
        ctx.session.destroy();
        redirect(loginRedirectUrl("/admin/users", true));
      }
      // 403 : le rôle a été révoqué en base depuis l'émission du token.
      if (err.status === 403) {
        notFound();
      }
    }
    throw err;
  }

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));

  return (
    <section className="space-y-6">
      <header className="flex items-baseline justify-between">
        <h1 className="text-2xl font-bold">Utilisateurs</h1>
        <p className="text-sm text-slate-600">
          {data.total} compte{data.total > 1 ? "s" : ""}
        </p>
      </header>

      {/* Toutes les valeurs (emails, noms) sont rendues via JSX : React les
          échappe — un nom contenant <script> s'affiche littéralement (#3). */}
      <div className="overflow-x-auto rounded border border-slate-200 bg-white">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">
            Liste paginée des utilisateurs enregistrés
          </caption>
          <thead className="border-b border-slate-200 bg-slate-50">
            <tr>
              <th scope="col" className="px-4 py-2 font-medium">Email</th>
              <th scope="col" className="px-4 py-2 font-medium">Nom d&apos;affichage</th>
              <th scope="col" className="px-4 py-2 font-medium">Rôle</th>
              <th scope="col" className="px-4 py-2 font-medium">Créé le</th>
            </tr>
          </thead>
          <tbody>
            {data.items.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-slate-500">
                  Aucun utilisateur sur cette page.
                </td>
              </tr>
            ) : (
              data.items.map((user) => (
                <tr key={user.id} className="border-b border-slate-100 last:border-0">
                  <td className="break-all px-4 py-2">{user.email}</td>
                  <td className="break-all px-4 py-2">{user.display_name ?? "—"}</td>
                  <td className="px-4 py-2">
                    {user.role === "admin" ? (
                      <span className="rounded bg-purple-100 px-2 py-0.5 text-xs font-medium text-purple-800">
                        admin
                      </span>
                    ) : (
                      <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
                        user
                      </span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2">
                    {new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium" }).format(
                      new Date(user.created_at),
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <nav aria-label="Pagination" className="flex items-center justify-between">
        {page > 1 ? (
          <Link
            href={{ pathname: "/admin/users", query: { page: page - 1 } }}
            className="rounded border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-100"
          >
            ← Page précédente
          </Link>
        ) : (
          <span aria-hidden="true" />
        )}
        <p className="text-sm text-slate-600">
          Page {data.page} sur {totalPages}
        </p>
        {page < totalPages ? (
          <Link
            href={{ pathname: "/admin/users", query: { page: page + 1 } }}
            className="rounded border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-100"
          >
            Page suivante →
          </Link>
        ) : (
          <span aria-hidden="true" />
        )}
      </nav>
    </section>
  );
}
