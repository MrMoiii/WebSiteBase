import type { NextConfig } from "next";

/**
 * Configuration Next.js — chaque option ci-dessous est une décision de
 * sécurité, voir SECURITY.md pour la vue d'ensemble.
 *
 * NOTE : les en-têtes de sécurité (CSP avec nonce, HSTS, etc.) ne sont PAS
 * définis ici mais dans `middleware.ts`, car la CSP exige un nonce généré
 * par requête — impossible avec les `headers()` statiques de ce fichier.
 */
const nextConfig: NextConfig = {
  // Image minimale autonome pour le Dockerfile multi-stage (exigence déploiement).
  output: "standalone",

  // Ne pas révéler la technologie utilisée (réduction d'empreinte).
  poweredByHeader: false,

  images: {
    // Liste blanche STRICTE des domaines d'images distantes (exigence #10).
    // Vide par défaut : l'application ne sert que des images locales.
    // Toute origine ajoutée ici doit être justifiée et revue.
    remotePatterns: [],
  },

  // Routes typées : une redirection vers une route inexistante devient une
  // erreur de compilation (complète la liste blanche anti open-redirect).
  typedRoutes: true,

  experimental: {
    serverActions: {
      // Anti-CSRF des Server Actions : Next.js compare l'en-tête Origin à
      // l'hôte de la requête. Derrière un reverse proxy qui réécrit Host,
      // déclarer ici les origines publiques légitimes (séparées par des
      // virgules dans APP_ALLOWED_ORIGINS, ex. "app.example.com").
      // En l'absence de proxy réécrivant Host, la vérification par défaut
      // (Origin === Host) suffit et la liste reste vide.
      allowedOrigins: (process.env.APP_ALLOWED_ORIGINS ?? "")
        .split(",")
        .map((o) => o.trim())
        .filter((o) => o.length > 0),
      // Borne la taille des corps de Server Actions (anti-DoS, cohérent avec
      // MAX_BODY_BYTES=1Mo côté backend).
      bodySizeLimit: "1mb",
    },
  },
};

export default nextConfig;
