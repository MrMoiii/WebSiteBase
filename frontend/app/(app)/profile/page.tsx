import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { ApiClientError, apiGetMe } from "@/lib/api";
import { loginRedirectUrl, requireAuth } from "@/lib/auth";
import { ProfileForm } from "@/components/profile/profile-form";

export const metadata: Metadata = { title: "Mon profil" };

/** Formate une date ISO du backend pour l'affichage (sans lib externe). */
function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : new Intl.DateTimeFormat("fr-FR", { dateStyle: "long", timeStyle: "short" }).format(d);
}

export default async function ProfilePage() {
  const ctx = await requireAuth("/profile");

  // Lecture FRAÎCHE du profil auprès du backend (l'instantané en session ne
  // sert qu'à l'affichage de la nav). Toutes les valeurs affichées passent
  // par le rendu JSX : React échappe systématiquement — un display_name
  // contenant du HTML s'affiche comme texte (anti-XSS, exigence #3).
  let profile;
  try {
    profile = await apiGetMe(ctx.accessToken, ctx.requestId);
  } catch (err) {
    if (err instanceof ApiClientError && err.status === 401) {
      ctx.session.destroy();
      redirect(loginRedirectUrl("/profile", true));
    }
    throw err; // page d'erreur générique, détail loggé côté serveur
  }

  return (
    <section className="space-y-8">
      <h1 className="text-2xl font-bold">Mon profil</h1>

      <dl className="grid gap-4 rounded border border-slate-200 bg-white p-4 sm:grid-cols-2">
        <div>
          <dt className="text-sm font-medium text-slate-500">Adresse email</dt>
          <dd className="mt-0.5 break-all">{profile.email}</dd>
        </div>
        <div>
          <dt className="text-sm font-medium text-slate-500">Nom d&apos;affichage</dt>
          <dd className="mt-0.5 break-all">{profile.display_name ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-sm font-medium text-slate-500">Rôle</dt>
          <dd className="mt-0.5">
            {profile.role === "admin" ? "Administrateur" : "Utilisateur"}
          </dd>
        </div>
        <div>
          <dt className="text-sm font-medium text-slate-500">Inscrit le</dt>
          <dd className="mt-0.5">{formatDate(profile.created_at)}</dd>
        </div>
      </dl>

      <div className="max-w-md">
        <h2 className="mb-3 text-lg font-semibold">Modifier mon profil</h2>
        <ProfileForm initialDisplayName={profile.display_name} />
      </div>
    </section>
  );
}
