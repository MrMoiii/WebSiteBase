/**
 * Liveness du conteneur frontend (utilisé par le HEALTHCHECK Docker).
 * Ne touche ni session ni backend : répond uniquement « le process sert ».
 */
export function GET(): Response {
  return Response.json(
    { status: "ok" },
    { headers: { "cache-control": "no-store" } },
  );
}
