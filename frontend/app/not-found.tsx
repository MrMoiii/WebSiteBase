import Link from "next/link";

/**
 * 404 générique. Sert aussi de réponse aux non-admins qui tentent /admin :
 * on ne révèle pas l'existence des routes d'administration.
 */
export default function NotFoundPage() {
  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-bold">Page introuvable</h1>
      <p className="text-slate-700">
        La page demandée n&apos;existe pas ou n&apos;est pas accessible.
      </p>
      <Link href="/" className="text-blue-700 underline">
        Retour à l&apos;accueil
      </Link>
    </section>
  );
}
