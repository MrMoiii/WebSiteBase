import Link from "next/link";

export default function HomePage() {
  return (
    <section className="space-y-6">
      <h1 className="text-3xl font-bold">Bienvenue sur WebSiteBase</h1>
      <p className="max-w-prose text-slate-700">
        Modèle d&apos;application web avec authentification sécurisée :
        inscription, connexion, gestion de profil et espace
        d&apos;administration.
      </p>
      <div className="flex gap-3">
        <Link
          href="/register"
          className="rounded bg-blue-700 px-4 py-2 font-medium text-white hover:bg-blue-800"
        >
          Créer un compte
        </Link>
        <Link
          href="/login"
          className="rounded border border-slate-300 bg-white px-4 py-2 font-medium text-slate-800 hover:bg-slate-100"
        >
          Se connecter
        </Link>
      </div>
    </section>
  );
}
