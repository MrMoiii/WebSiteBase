#!/usr/bin/env bash
# =============================================================================
# Génère une PKI LOCALE pour OpenSearch (DÉVELOPPEMENT/DEMO uniquement).
#
# Produit, dans ./docker/opensearch/certs/ :
#   - ca.pem / ca.key            : autorité de certification locale
#   - node.pem / node.key        : certificat du nœud OpenSearch (TLS REST + transport)
#   - admin.pem / admin.key      : certificat admin (securityadmin.sh)
#   - client.pem                 : identité client (cert+clé concaténés) pour le
#                                  mTLS du backend (OPENSEARCH_CLIENT_IDENTITY_PATH)
#
# Ces fichiers NE DOIVENT PAS être committés (cf. .gitignore). En production,
# utilisez une PKI gérée (Vault, cert-manager, ACM…) et un gestionnaire de
# secrets, jamais des certs auto-signés générés localement.
# =============================================================================
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

DAYS=825

echo "==> CA locale"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/O=WebSiteBase/CN=websitebase-local-ca" -out ca.pem

# Génère un certificat signé par la CA. $1=nom de base, $2=CN, $3=SAN (optionnel)
gen_cert() {
  local name="$1" cn="$2" san="${3:-}"
  openssl genrsa -out "${name}.key" 2048
  local ext=""
  if [[ -n "$san" ]]; then
    ext=$(mktemp)
    printf 'subjectAltName=%s\n' "$san" > "$ext"
  fi
  openssl req -new -key "${name}.key" -subj "/O=WebSiteBase/CN=${cn}" -out "${name}.csr"
  if [[ -n "$ext" ]]; then
    openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
      -days "$DAYS" -sha256 -extfile "$ext" -out "${name}.pem"
    rm -f "$ext"
  else
    openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
      -days "$DAYS" -sha256 -out "${name}.pem"
  fi
  rm -f "${name}.csr"
}

echo "==> Certificat nœud (SAN: opensearch, localhost)"
gen_cert node "opensearch" "DNS:opensearch,DNS:localhost,IP:127.0.0.1"

echo "==> Certificat admin (securityadmin)"
gen_cert admin "admin"

echo "==> Certificat client (mTLS backend)"
gen_cert client "app_search"
# Identité client = cert + clé concaténés (format attendu par reqwest/rustls).
cat client.pem client.key > client-identity.pem

chmod 600 ./*.key ./client-identity.pem
echo "==> Certificats générés dans $CERT_DIR"
echo "    Backend  : OPENSEARCH_CA_CERT_PATH=.../ca.pem"
echo "               OPENSEARCH_CLIENT_IDENTITY_PATH=.../client-identity.pem"
