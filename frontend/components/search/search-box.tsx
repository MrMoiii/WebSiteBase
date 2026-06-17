"use client";

import type { Route } from "next";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useTransition } from "react";

import { searchSchema } from "@/lib/schemas";

/**
 * Champ de recherche avec DEBOUNCE côté client (exigence UI).
 *
 * Sécurité : ce composant ne parle JAMAIS à OpenSearch ni au backend
 * directement. Il se contente de réécrire l'URL (`/search?q=…`) ; c'est le
 * Server Component de la page qui appelle le BFF, lequel appelle le backend.
 * La validation locale (zod) n'est qu'un confort UX — le backend revalide.
 */
export function SearchBox({ initialQuery }: { initialQuery: string }) {
  const router = useRouter();
  const [value, setValue] = useState(initialQuery);
  const [error, setError] = useState<string | undefined>(undefined);
  const [isPending, startTransition] = useTransition();
  // Évite de renaviguer au montage (la valeur initiale vient déjà de l'URL).
  const firstRun = useRef(true);

  useEffect(() => {
    if (firstRun.current) {
      firstRun.current = false;
      return;
    }

    const handle = setTimeout(() => {
      const trimmed = value.trim();

      // Champ vidé : on revient à la page de recherche nue (pas d'appel).
      if (trimmed.length === 0) {
        setError(undefined);
        startTransition(() => router.replace("/search" as Route));
        return;
      }

      const parsed = searchSchema.safeParse({ q: trimmed });
      if (!parsed.success) {
        setError(parsed.error.issues[0]?.message ?? "Recherche invalide.");
        return;
      }
      setError(undefined);

      // URLSearchParams encode la valeur : pas d'injection dans l'URL. On
      // repart toujours en page 1 lorsqu'on change la requête.
      const params = new URLSearchParams({ q: parsed.data.q, page: "1" });
      startTransition(() =>
        router.replace(`/search?${params.toString()}` as Route),
      );
    }, 350);

    return () => clearTimeout(handle);
  }, [value, router]);

  return (
    <div className="space-y-1">
      <label htmlFor="search-q" className="block text-sm font-medium">
        Rechercher
      </label>
      <input
        type="search"
        id="search-q"
        name="q"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        maxLength={256}
        autoComplete="off"
        placeholder="Mot-clé, titre, tag…"
        aria-describedby="search-error"
        aria-busy={isPending}
        className="w-full rounded border border-slate-300 px-3 py-2"
      />
      {error ? (
        <p id="search-error" role="alert" className="text-sm text-red-700">
          {error}
        </p>
      ) : null}
    </div>
  );
}
