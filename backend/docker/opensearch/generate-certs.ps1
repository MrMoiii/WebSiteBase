# =============================================================================
# Génère une PKI LOCALE pour OpenSearch sous Windows (DÉVELOPPEMENT/DEMO).
#
# Équivalent de generate-certs.sh, mais SANS dépendance à openssl sur l'hôte :
# les commandes openssl tournent dans un conteneur Docker jetable (alpine).
# Docker étant déjà requis pour la stack, ce script fonctionne « tel quel ».
#
# Produit, dans .\certs\ : ca.pem/ca.key, node.pem/node.key, admin.pem/admin.key,
# client.pem/client.key et client-identity.pem (cert+clé concaténés, mTLS backend).
# Les clés sont au format PKCS#8 (BEGIN PRIVATE KEY) — REQUIS par le plugin de
# sécurité d'OpenSearch (le PKCS#1 de `openssl genrsa` ferait échouer le nœud).
#
# Ces fichiers NE DOIVENT PAS être committés (cf. .gitignore). En production :
# PKI gérée + gestionnaire de secrets, jamais des certs auto-signés locaux.
#
# Usage (PowerShell, depuis n'importe où) :
#   .\docker\opensearch\generate-certs.ps1
# =============================================================================
$ErrorActionPreference = "Stop"

# Vérifie que Docker est disponible.
try { docker version --format '{{.Server.Version}}' | Out-Null }
catch { Write-Error "Docker ne répond pas. Démarre Docker Desktop puis relance."; exit 1 }

# Dossier de sortie : <script>\certs
$certDir = Join-Path $PSScriptRoot "certs"
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

# Script POSIX exécuté DANS le conteneur alpine (openssl installé à la volée).
# Génération en PKCS#8 via `openssl genpkey` (et non `genrsa`).
$sh = @'
set -e
apk add --no-cache openssl >/dev/null 2>&1
cd /certs
DAYS=825

echo "==> CA locale"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ca.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/O=WebSiteBase/CN=websitebase-local-ca" -out ca.pem

gen() {
  name="$1"; cn="$2"; san="$3"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${name}.key"
  openssl req -new -key "${name}.key" -subj "/O=WebSiteBase/CN=${cn}" -out "${name}.csr"
  if [ -n "$san" ]; then
    printf "subjectAltName=%s\n" "$san" > "${name}.ext"
    openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
      -days "$DAYS" -sha256 -extfile "${name}.ext" -out "${name}.pem"
    rm -f "${name}.ext"
  else
    openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
      -days "$DAYS" -sha256 -out "${name}.pem"
  fi
  rm -f "${name}.csr"
}

echo "==> Certificat noeud (SAN: opensearch, localhost)"
gen node "opensearch" "DNS:opensearch,DNS:localhost,IP:127.0.0.1"
echo "==> Certificat admin"
gen admin "admin" ""
echo "==> Certificat client (mTLS backend)"
gen client "app_search" ""

cat client.pem client.key > client-identity.pem
chmod 600 *.key client-identity.pem 2>/dev/null || true
echo "==> Certificats generes dans ./certs"
'@

# Normalise les fins de ligne (CRLF -> LF) pour sh, puis exécute dans alpine.
# --mount gère proprement les chemins Windows contenant des espaces.
$sh = $sh -replace "`r`n", "`n"
docker run --rm --mount "type=bind,source=$certDir,target=/certs" alpine:3.20 sh -c $sh

Write-Host ""
Write-Host "OK. Certificats dans : $certDir" -ForegroundColor Green
Write-Host "Tu peux maintenant lancer :" -ForegroundColor Green
Write-Host "  docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build"
