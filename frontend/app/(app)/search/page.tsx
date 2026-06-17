import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { z } from "zod";

import { ApiClientError, apiSearch } from "@/lib/api";
import { loginRedirectUrl, requireAuth } from "@/lib/auth";
import { searchSchema } from "@/lib/schemas";
import { SearchBox } from "@/components/search/search-box";

export const metadata: Metadata = { title: "Recherche" };

/** Page courante : donnée non fiable de l'URL, validée puis bornée. */
const pageParamSchema = z.coerce.number().int().min(1).max(1_000_000).catch(1);

const PAGE_SIZE = 10;

/** Formate un timestamp Unix (secondes) renvoyé par le backend. */
function formatTs(seconds: number | undefined): string {
  if (seconds === undefined) return "—";
  const d = new Date(seconds * 1000);
  return Number.isNaN(d.getTime())
    ? "—"
    : new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium" }).format(d);
}

export default async function SearchPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const ctx = await requireAuth("/search");
  const params = await searchParams;

  // La requête vient de l'URL : validée par zod (jamais interpolée telle quelle).
  const rawQ = typeof params.q === "string" ? params.q : "";
  const parsedQ = searchSchema.safeParse({ q: rawQ });
  const page = pageParamSchema.parse(params.page);

  return (
    <section className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold">Recherche</h1>
        <p className="mt-1 text-sm text-slate-600">
          La recherche passe par l&apos;API : le navigateur ne contacte jamais
          le moteur directement.
        </p>
      </header>

      <SearchBox initialQuery={rawQ} />

      {/* Pas de requête (ou invalide) : on n'appelle pas le backend. */}
      {!parsedQ.success ? (
        rawQ.trim().length === 0 ? (
          <p className="text-sm text-slate-500">
            Saisissez un terme pour lancer une recherche.
          </p>
        ) : (
          <p role="alert" className="text-sm text-red-700">
            {parsedQ.error.issues[0]?.message ?? "Recherche invalide."}
          </p>
        )
      ) : (
        <Results
          q={parsedQ.data.q}
          page={page}
          accessToken={ctx.accessToken}
          requestId={ctx.requestId}
          onUnauthorized={() => {
            ctx.session.destroy();
          }}
        />
      )}
    </section>
  );
}

/** Bloc de résultats — isolé pour garder le composant de page lisible. */
async function Results({
  q,
  page,
  accessToken,
  requestId,
  onUnauthorized,
}: {
  q: string;
  page: number;
  accessToken: string;
  requestId: string;
  onUnauthorized: () => void;
}) {
  // L'appel réseau est isolé dans le try/catch ; le rendu JSX se fait APRÈS
  // (un composant rendu dans un try/catch n'y verrait pas ses erreurs de
  // rendu capturées — règle react-hooks/error-boundaries).
  let data;
  try {
    data = await apiSearch(
      accessToken,
      { q, page, pageSize: PAGE_SIZE, sort: "_score", order: "desc" },
      requestId,
    );
  } catch (err) {
    if (err instanceof ApiClientError) {
      // Session devenue invalide : on détruit et on renvoie au login.
      if (err.status === 401) {
        onUnauthorized();
        redirect(loginRedirectUrl("/search", true));
      }
      // Erreurs « attendues » présentées proprement (exigence UI : timeout,
      // forbidden, indisponible, trop de requêtes, requête invalide).
      const message =
        err.status === 503
          ? "La recherche est momentanément indisponible. Réessayez plus tard."
          : err.status === 429
            ? "Trop de recherches en peu de temps. Patientez un instant."
            : err.status === 403
              ? "Vous n'êtes pas autorisé à effectuer cette recherche."
              : err.status === 400 || err.status === 422
                ? "Requête de recherche invalide."
                : "Une erreur est survenue lors de la recherche.";
      return (
        <p role="alert" className="text-sm text-red-700">
          {message}
        </p>
      );
    }
    throw err;
  }

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));

  if (data.items.length === 0) {
    return (
      <p className="text-sm text-slate-500">
        Aucun résultat pour «&nbsp;{q}&nbsp;».
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-600">
        {data.total} résultat{data.total > 1 ? "s" : ""}
      </p>

      {/* Toutes les valeurs passent par JSX : React les échappe (anti-XSS). */}
      <ul className="space-y-3">
        {data.items.map((hit) => (
          <li
            key={hit.id}
            className="rounded border border-slate-200 bg-white p-4"
          >
            <h2 className="font-medium">{hit.title ?? "(sans titre)"}</h2>
            {hit.body ? (
              <p className="mt-1 line-clamp-3 text-sm text-slate-600">
                {hit.body}
              </p>
            ) : null}
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span>{formatTs(hit.created_at)}</span>
              {(hit.tags ?? []).map((tag) => (
                <span
                  key={tag}
                  className="rounded bg-slate-100 px-2 py-0.5 text-slate-700"
                >
                  {tag}
                </span>
              ))}
            </div>
          </li>
        ))}
      </ul>

      <nav
        aria-label="Pagination"
        className="flex items-center justify-between"
      >
        {page > 1 ? (
          <Link
            href={{ pathname: "/search", query: { q, page: page - 1 } }}
            className="rounded border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-100"
          >
            ← Précédent
          </Link>
        ) : (
          <span aria-hidden="true" />
        )}
        <p className="text-sm text-slate-600">
          Page {data.page} sur {totalPages}
        </p>
        {page < totalPages ? (
          <Link
            href={{ pathname: "/search", query: { q, page: page + 1 } }}
            className="rounded border border-slate-300 bg-white px-3 py-1.5 text-sm hover:bg-slate-100"
          >
            Suivant →
          </Link>
        ) : (
          <span aria-hidden="true" />
        )}
      </nav>
    </div>
  );
}
