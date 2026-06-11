/**
 * Hook de démarrage Next.js : valide l'environnement AVANT de servir la
 * moindre requête (exigence sécurité #5 — fail-fast comme le backend).
 * Une variable manquante ou invalide fait échouer le démarrage du serveur.
 */
export async function register(): Promise<void> {
  const { env } = await import("./lib/env");
  const config = env();
  // Log de démarrage sans aucune valeur sensible (les secrets ne sont
  // jamais loggés — seule la présence est confirmée par le parse).
  console.log(
    JSON.stringify({
      level: "info",
      msg: "environnement validé, démarrage du frontend",
      node_env: config.NODE_ENV,
      cookie_secure: config.COOKIE_SECURE,
    }),
  );
}
