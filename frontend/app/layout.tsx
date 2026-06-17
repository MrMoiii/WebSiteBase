import type { Metadata } from "next";
import type { ReactNode } from "react";

import { SiteHeader } from "@/components/site-header";

import "./globals.css";

/**
 * Layout racine.
 *
 * Polices : pile système (`font-sans` Tailwind) — aucune fonte téléchargée,
 * donc rien à auto-héberger et zéro requête tierce (exigence #9). Si une
 * fonte personnalisée devient nécessaire, utiliser exclusivement
 * `next/font/local` (jamais de CDN).
 *
 * Le nonce CSP est géré par le middleware : Next.js le lit dans l'en-tête
 * Content-Security-Policy de la requête et l'applique à ses balises <script>.
 */
export const metadata: Metadata = {
  title: {
    default: "WebSiteBase",
    template: "%s — WebSiteBase",
  },
  description: "Modèle d'application web sécurisée.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="fr">
      <body className="min-h-screen bg-slate-50 font-sans text-slate-900 antialiased">
        {/* Lien d'évitement : accessibilité clavier (exigence accessibilité). */}
        <a
          href="#contenu"
          className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 focus:shadow"
        >
          Aller au contenu
        </a>
        <SiteHeader />
        <main id="contenu" className="mx-auto w-full max-w-4xl px-4 py-8">
          {children}
        </main>
      </body>
    </html>
  );
}
