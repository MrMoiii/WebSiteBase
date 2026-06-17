/** Affichage accessible d'une erreur de champ (associée via aria-describedby). */
export function FieldError({
  id,
  messages,
}: {
  id: string;
  messages: string[] | undefined;
}) {
  if (!messages || messages.length === 0) {
    return null;
  }
  return (
    <p id={id} role="alert" className="mt-1 text-sm text-red-700">
      {messages[0]}
    </p>
  );
}
