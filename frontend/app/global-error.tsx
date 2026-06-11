"use client";

/**
 * Filet de sécurité ultime (erreur dans le layout racine lui-même).
 * Même politique que app/error.tsx : message générique, zéro détail.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="fr">
      <body>
        <main style={{ fontFamily: "system-ui", padding: "2rem" }}>
          <h1>Une erreur est survenue</h1>
          <p>Le service est momentanément indisponible.</p>
          {error.digest ? <p>Référence : {error.digest}</p> : null}
          <button type="button" onClick={reset}>
            Réessayer
          </button>
        </main>
      </body>
    </html>
  );
}
