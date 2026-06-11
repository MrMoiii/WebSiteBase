"use client";

import { useActionState, useState } from "react";
import { z } from "zod";

import { updateProfileAction, type ProfileFormState } from "@/app/actions/profile";
import { FieldError } from "@/components/forms/field-error";
import { profileSchema } from "@/lib/schemas";

/** Formulaire d'édition du profil (nom d'affichage uniquement). */
export function ProfileForm({
  initialDisplayName,
}: {
  initialDisplayName: string | null;
}) {
  const [state, formAction, pending] = useActionState<ProfileFormState, FormData>(
    updateProfileAction,
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
        const parsed = profileSchema.safeParse({
          displayName:
            new FormData(event.currentTarget).get("displayName") ?? "",
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
      {state.success ? (
        <p
          role="status"
          className="rounded border border-green-300 bg-green-50 px-3 py-2 text-sm text-green-800"
        >
          Profil mis à jour.
        </p>
      ) : null}

      <div>
        <label htmlFor="displayName" className="block text-sm font-medium">
          Nom d&apos;affichage
        </label>
        <input
          type="text"
          id="displayName"
          name="displayName"
          defaultValue={initialDisplayName ?? ""}
          maxLength={100}
          autoComplete="nickname"
          aria-describedby="displayName-error displayName-help"
          className="mt-1 w-full rounded border border-slate-300 px-3 py-2"
        />
        <p id="displayName-help" className="mt-1 text-sm text-slate-600">
          Laisser vide pour le supprimer.
        </p>
        <FieldError id="displayName-error" messages={fieldErrors.displayName} />
      </div>

      <button
        type="submit"
        disabled={pending}
        className="rounded bg-blue-700 px-4 py-2 font-medium text-white hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {pending ? "Enregistrement…" : "Enregistrer"}
      </button>
    </form>
  );
}
