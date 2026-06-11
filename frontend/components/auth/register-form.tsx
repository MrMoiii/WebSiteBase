"use client";

import { useActionState, useState } from "react";
import { z } from "zod";

import { registerAction, type AuthFormState } from "@/app/actions/auth";
import { FieldError } from "@/components/forms/field-error";
import { Honeypot } from "@/components/forms/honeypot";
import { registerSchema } from "@/lib/schemas";

/** Formulaire d'inscription — mêmes principes que LoginForm. */
export function RegisterForm({ nextPath }: { nextPath: string }) {
  const [state, formAction, pending] = useActionState<AuthFormState, FormData>(
    registerAction,
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
        const data = new FormData(event.currentTarget);
        const parsed = registerSchema.safeParse({
          email: data.get("email"),
          password: data.get("password"),
          displayName: data.get("displayName") ?? "",
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
        <label htmlFor="displayName" className="block text-sm font-medium">
          Nom d&apos;affichage <span className="text-slate-500">(optionnel)</span>
        </label>
        <input
          type="text"
          id="displayName"
          name="displayName"
          maxLength={100}
          autoComplete="nickname"
          aria-describedby="displayName-error"
          className="mt-1 w-full rounded border border-slate-300 px-3 py-2"
        />
        <FieldError id="displayName-error" messages={fieldErrors.displayName} />
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
          minLength={12}
          maxLength={128}
          autoComplete="new-password"
          aria-describedby="password-error password-help"
          className="mt-1 w-full rounded border border-slate-300 px-3 py-2"
        />
        <p id="password-help" className="mt-1 text-sm text-slate-600">
          Au moins 12 caractères.
        </p>
        <FieldError id="password-error" messages={fieldErrors.password} />
      </div>

      <button
        type="submit"
        disabled={pending}
        className="w-full rounded bg-blue-700 px-4 py-2 font-medium text-white hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {pending ? "Création du compte…" : "Créer mon compte"}
      </button>
    </form>
  );
}
