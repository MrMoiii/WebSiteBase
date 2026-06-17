"use client";

import { useEffect } from "react";

/**
 * Page d'erreur GÉNÉRIQUE (exigence #6) : aucun détail technique n'est
 * affiché au client. Le détail complet est loggé côté serveur avec le
 * correlation id ; seul le `digest` (identifiant opaque généré par Next)
 * est montré comme référence pour le support — il ne révèle rien.
 */
export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Pas de console.error(error) : ne pas répandre de détail dans la
    // console du navigateur (exigence #12 — pas de fuite dans les logs client).
  }, [error]);

  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-bold">Une erreur est survenue</h1>
      <p className="text-slate-700">
        Le service est momentanément indisponible. Veuillez réessayer.
      </p>
      {error.digest ? (
        <p className="text-sm text-slate-500">
          Référence pour le support : <code>{error.digest}</code>
        </p>
      ) : null}
      <button
        type="button"
        onClick={reset}
        className="rounded bg-blue-700 px-4 py-2 font-medium text-white hover:bg-blue-800"
      >
        Réessayer
      </button>
    </section>
  );
}
