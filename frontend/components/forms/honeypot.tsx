import { HONEYPOT_FIELD } from "@/lib/schemas";

/**
 * Champ honeypot anti-bot (exigence #7) : invisible et inatteignable pour un
 * humain (aria-hidden + tabIndex -1 + masqué), mais rempli par les bots qui
 * soumettent tous les champs. Vérifié côté serveur (isHoneypotTriggered).
 */
export function Honeypot() {
  return (
    <div aria-hidden="true" className="absolute -left-[9999px] h-0 w-0 overflow-hidden">
      <label htmlFor={HONEYPOT_FIELD}>
        Ne pas remplir ce champ
        <input
          type="text"
          id={HONEYPOT_FIELD}
          name={HONEYPOT_FIELD}
          tabIndex={-1}
          autoComplete="off"
          defaultValue=""
        />
      </label>
    </div>
  );
}
