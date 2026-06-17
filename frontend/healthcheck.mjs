/**
 * Healthcheck du conteneur : interroge la route de liveness locale.
 * Fichier autonome (le conteneur n'a pas curl/wget — surface minimale).
 */
try {
  const res = await fetch("http://127.0.0.1:3000/api/health", {
    signal: AbortSignal.timeout(3000),
  });
  process.exit(res.ok ? 0 : 1);
} catch {
  process.exit(1);
}
