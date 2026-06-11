/**
 * Logger serveur minimal : lignes JSON structurées sur stdout/stderr,
 * cohérent avec les logs `tracing` du backend.
 *
 * Règles (exigences #6 et #12) :
 * - le DÉTAIL des erreurs ne va QUE dans ces logs serveur, jamais au client ;
 * - toujours joindre le correlation id (`requestId`) pour croiser avec les
 *   logs de l'API Axum (propagé via X-Request-Id) ;
 * - ne JAMAIS logger de secret, token, mot de passe ou donnée personnelle
 *   non nécessaire (l'email n'est loggé nulle part ici).
 */

type LogFields = Record<string, string | number | boolean | undefined>;

function emit(level: "info" | "warn" | "error", msg: string, fields: LogFields): void {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    msg,
    ...fields,
  });
  if (level === "error") {
    console.error(line);
  } else if (level === "warn") {
    console.warn(line);
  } else {
    console.log(line);
  }
}

export const logger = {
  info: (msg: string, fields: LogFields = {}): void => emit("info", msg, fields),
  warn: (msg: string, fields: LogFields = {}): void => emit("warn", msg, fields),
  error: (msg: string, fields: LogFields = {}): void => emit("error", msg, fields),
};
