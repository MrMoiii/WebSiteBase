"use client";

import { useActionState, useState } from "react";
import { z } from "zod";

import { loginAction, type AuthFormState } from "@/app/actions/auth";
import { FieldError } from "@/components/forms/field-error";
import { Honeypot } from "@/components/forms/honeypot";
import { loginSchema } from "@/lib/schemas";

/**
 * Formulaire de connexion (Client Component).
 *
 * La validation zod côté client n'est que de l'UX (retour immédiat) : la
 * Server Action revalide tout et le backend tranche en dernier ressort.
 * `nextPath` a déjà été validé contre la liste blanche côté serveur, et la
 * Server Action le revalide (anti open-redirect).
 */
export function LoginForm({
  nextPath,
  expired,
}: {
  nextPath: string;
  expired: boolean;
}) {
  const [state, formAction, pending] = useActionState<AuthFormState, FormData>(
    loginAction,
    {},
  );
  const [clientErrors, setClientErrors] = useState<
    Record<string, string[] | undefined>
  >({});

  const fieldErrors = { ...state.fieldErrors, ...clientErrors };

  return (
    <form
      action={formAction}
      noValidate
      onSubmit={(event) => {
        // Validation UX avant envoi ; en cas d'échec on n'appelle pas l'action.
        const parsed = loginSchema.safeParse({
          email: new FormData(event.currentTarget).get("email"),
          password: new FormData(event.currentTarget).get("password"),
        });
        if (!parsed.success) {
          event.preventDefault();
          setClientErrors(z.flattenError(parsed.error).fieldErrors);
        } else {
          setClientErrors({});
        }
      }}
      className="space-y-4"
    >
      {expired ? (
        <p
          role="status"
          className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900"
        >
          Votre session a expiré. Veuillez vous reconnecter.
        </p>
      ) : null}

      {state.error ? (
        <p
          role="alert"
          className="rounded border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-800"
        >
          {state.error}
        </p>
      ) : null}

      <Honeypot />
      <input type="hidden" name="next" value={nextPath} />

      <div>
        <label htmlFor="email" className="block text-sm font-medium">
          Adresse email
        </label>
        <input
          type="email"
          id="email"
          name="email"
          required
          maxLength={320}
          autoComplete="email"
          aria-describedby="email-error"
          className="mt-1 w-full rounded border border-slate-300 px-3 py-2"
        />
        <FieldError id="email-error" messages={fieldErrors.email} />
      </div>

      <div>
        <label htmlFor="password" className="block text-sm font-medium">
          Mot de passe
        </label>
        <input
          type="password"
          id="password"
          name="password"
          required
          maxLength={128}
          autoComplete="current-password"
          aria-describedby="password-error"
          className="mt-1 w-full rounded border border-slate-300 px-3 py-2"
        />
        <FieldError id="password-error" messages={fieldErrors.password} />
      </div>

      <button
        type="submit"
        disabled={pending}
        className="w-full rounded bg-blue-700 px-4 py-2 font-medium text-white hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {pending ? "Connexion en cours…" : "Se connecter"}
      </button>
    </form>
  );
}
