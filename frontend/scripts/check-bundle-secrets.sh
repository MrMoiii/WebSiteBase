#!/usr/bin/env bash
# =============================================================================
# Check anti-fuite de secrets dans le bundle CLIENT (exigence sécurité #5).
#
# Next.js n'inline dans le JavaScript envoyé au navigateur que les variables
# préfixées NEXT_PUBLIC_. Ce projet n'en utilise AUCUNE : on vérifie donc
# qu'aucun nom de variable serveur, ni aucune VALEUR sensible réellement
# utilisée au build, n'apparaît dans `.next/static` (seul répertoire servi
# au client).
#
# Usage : npm run build && bash scripts/check-bundle-secrets.sh
# =============================================================================
set -euo pipefail

BUNDLE_DIR=".next/static"

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "ERREUR : $BUNDLE_DIR introuvable — lancer 'npm run build' d'abord." >&2
  exit 1
fi

fail=0

# 1) Les NOMS des variables serveur ne doivent jamais être inlinés côté client.
for name in SESSION_SECRET API_BASE_URL APP_ALLOWED_ORIGINS; do
  if grep -R -q -- "$name" "$BUNDLE_DIR"; then
    echo "FUITE : la variable serveur '$name' apparaît dans le bundle client :" >&2
    grep -R -l -- "$name" "$BUNDLE_DIR" >&2
    fail=1
  fi
done

# 2) Les VALEURS sensibles présentes dans l'environnement de build non plus.
for name in SESSION_SECRET API_BASE_URL; do
  value="${!name:-}"
  if [ -n "$value" ] && grep -R -q -F -- "$value" "$BUNDLE_DIR"; then
    echo "FUITE : la valeur de '$name' apparaît dans le bundle client :" >&2
    grep -R -l -F -- "$value" "$BUNDLE_DIR" >&2
    fail=1
  fi
done

# 3) Politique projet : AUCUNE variable NEXT_PUBLIC_* n'est autorisée sans
#    revue explicite (rien ne doit être exposé au client).
if env | grep -q '^NEXT_PUBLIC_'; then
  echo "POLITIQUE : variable NEXT_PUBLIC_* détectée — interdite sans revue :" >&2
  env | grep '^NEXT_PUBLIC_' | cut -d= -f1 >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "Échec du check anti-fuite de secrets." >&2
  exit 1
fi

echo "OK : aucun secret ni variable serveur dans le bundle client."
