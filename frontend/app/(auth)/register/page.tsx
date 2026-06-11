import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { RegisterForm } from "@/components/auth/register-form";
import { safeNextPath } from "@/lib/redirect";
import { getSession, isAuthenticated } from "@/lib/session";

export const metadata: Metadata = { title: "Inscription" };

export default async function RegisterPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const nextPath = safeNextPath(params.next);

  const session = await getSession();
  if (isAuthenticated(session)) {
    redirect(nextPath);
  }

  return (
    <section className="mx-auto max-w-md space-y-6">
      <h1 className="text-2xl font-bold">Créer un compte</h1>
      <RegisterForm nextPath={nextPath} />
      <p className="text-sm text-slate-600">
        Déjà inscrit ?{" "}
        <Link href="/login" className="text-blue-700 underline">
          Se connecter
        </Link>
      </p>
    </section>
  );
}
