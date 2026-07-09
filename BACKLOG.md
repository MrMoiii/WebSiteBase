# Backlog — durcissement d'architecture & mise en conformité

Backlog des travaux visant une architecture « exemplaire » et alignée sur les
normes actuelles, **par domaine**. La base est déjà solide (sécurité
applicative, supply-chain Rust/npm, conteneurs durcis, pattern BFF, monitoring
logs + métriques, 147 tests unitaires + 22 d'intégration) ; ce document liste ce
qui **reste à faire**.

## Légende

- **Priorité** : 🔴 P1 (haute) · 🟠 P2 (moyenne) · 🟢 P3 (optionnel).
- Cochez `- [x]` une action réalisée (référencer la PR à côté).
- Chaque action cite la **norme / raison** qui la justifie.

## Feuille de route — Top 8 (impact × effort)

1. [ ] `/health/ready` teste **Redis** + **Redis en HA** (Redis est devenu SPOF de l'auth).
2. [ ] **Détection de rejeu** des refresh tokens → révocation de la famille de sessions.
3. [ ] Trio d'auth manquant : **MFA + vérification email + reset password**.
4. [ ] **Spécification OpenAPI 3.1** (débloque doc, contrat, tests de contrat).
5. [ ] **SAST + scan de secrets + scan d'image** en CI.
6. [ ] **Traces OpenTelemetry** (OTLP → Tempo/Jaeger).
7. [ ] **Droits RGPD** : export (portabilité) + suppression (droit à l'oubli).
8. [ ] **IaC + manifests Kubernetes** pour un déploiement reproductible.

---

## 1. Authentification & Identité

- [ ] 🔴 **MFA / 2FA** (TOTP RFC 6238, WebAuthn/passkeys) — NIST 800-63B.
- [ ] 🔴 **Vérification d'email** (double opt-in) — anti-énumération réelle sur `/register`, anti-spam.
- [ ] 🔴 **Reset / forgot password** (token à usage unique, TTL court, non énumérant).
- [ ] 🟠 **JWT asymétrique RS256/EdDSA** ou **délégation OIDC** à un IdP — HS256 symétrique ne passe pas à l'échelle multi-services.
- [ ] 🟠 **Vérification de mot de passe compromis** (HIBP k-anonymity) + estimateur de force (zxcvbn) — OWASP ASVS 2.1.
- [ ] 🟢 Validation du claim `aud` (audience) sur le JWT — défense en profondeur.

## 2. Sessions & Tokens

- [ ] 🔴 **Détection de vol → révocation de la famille** au rejeu d'un refresh token — OWASP « rotation + reuse detection » (aujourd'hui : 401 seul ; `revoke_others` existe déjà côté store).
- [ ] 🟠 **Plafond de sessions par utilisateur** (éviction de la plus ancienne) — anti-abus mémoire Redis.
- [ ] 🟢 Liaison optionnelle session ↔ empreinte device/UA — détection de session hijacking.

## 3. API — Design & Contrat

- [ ] 🔴 **Spécification OpenAPI 3.1** (via `utoipa`) + contract testing — standard de facto, absente.
- [ ] 🟠 **Problem Details RFC 9457** (`application/problem+json`) — format d'erreur normalisé (aujourd'hui : shape maison).
- [ ] 🟠 **Pagination par curseur (keyset)** — l'`OFFSET` ne scale pas sur gros volumes.
- [ ] 🟠 **Clés d'idempotence** sur les mutations — fiabilité des retries.
- [ ] 🟢 En-têtes `RateLimit-*` / `Retry-After` (RFC 9331) — contrat de rate-limit explicite.

## 4. Sécurité outillée (AppSec / DevSecOps)

- [ ] 🔴 **SAST en CI** (CodeQL et/ou Semgrep) — norme GitHub/OpenSSF, absent.
- [ ] 🔴 **Scan de secrets** (gitleaks/trufflehog) en CI + pre-commit — anti-fuite de credentials.
- [ ] 🔴 **Scan d'image conteneur** (Trivy/Grype) — vulnérabilités OS/libs de l'image.
- [ ] 🟠 **SBOM** (CycloneDX via `cargo-cyclonedx`/syft) + attestation — supply-chain (EO 14028).
- [ ] 🟠 **Actions GitHub épinglées par SHA** + suivi **OpenSSF Scorecard**.
- [ ] 🟢 Fuzzing des parseurs (`cargo-fuzz`) ; revue de dépendances (`cargo-vet`/`crev`).
- [ ] 🟢 `.well-known/security.txt` + politique de divulgation (RFC 9116).

## 5. Observabilité & SLO

- [ ] 🔴 **Traces distribuées OpenTelemetry** (OTLP → Tempo/Jaeger) — aujourd'hui logs + métriques seulement, pas de vraies spans.
- [ ] 🔴 **Readiness inclut Redis** (et OpenSearch si activé) — `/health/ready` ne teste que Postgres alors que Redis est critique à l'auth.
- [ ] 🟠 **Règles d'alerting versionnées** (Alertmanager) + définition de **SLO / error budget** — norme SRE.
- [ ] 🟠 Journal d'**audit** séparé des logs applicatifs (actions admin) — traçabilité / conformité.

## 6. Résilience & Disponibilité

- [ ] 🔴 **Redis en HA** (Sentinel/Cluster, `rediss://`) — Redis est un SPOF de l'auth.
- [ ] 🟠 **Postgres HA** (réplica lecture, failover) + stratégie **backup/restore testée**.
- [ ] 🟠 **Tests de charge** (k6/Gatling) + capacity planning.
- [ ] 🟢 Retries + backoff / circuit breaker sur les appels sortants (OpenSearch déjà best-effort).

## 7. Données & Persistance

- [ ] 🟠 **Migrations réversibles testées** (down-migrations vérifiées en CI).
- [ ] 🟠 **Politique de rétention / purge PII** + chiffrement au repos documenté (TDE) — RGPD, ASVS.
- [ ] 🟢 Chiffrement applicatif au niveau champ pour les PII sensibles — défense en profondeur.

## 8. CI/CD & Release

- [ ] 🟠 **Couverture de code** (llvm-cov/tarpaulin) avec seuil bloquant.
- [ ] 🟠 **Dependabot/Renovate** — mises à jour de dépendances automatisées (absent).
- [ ] 🟠 **Images signées** (cosign/sigstore) + provenance **SLSA**.
- [ ] 🟢 **CHANGELOG + SemVer** (release automation).
- [ ] 🟢 Environnements + approbations, déploiement canary/blue-green + rollback automatisé.

## 9. Infrastructure & Déploiement

- [ ] 🔴 **IaC** (Terraform/Pulumi) — aujourd'hui inexistant.
- [ ] 🟠 **Manifests Kubernetes / Helm chart** (limits/requests, probes, HPA).
- [ ] 🟠 **NetworkPolicies + PodSecurityStandards** ; secrets via KMS/Vault/External-Secrets (aujourd'hui en variables d'env).
- [ ] 🟢 mTLS interne (service mesh) / images multi-arch — zero-trust réseau.

## 10. Tests & QA

- [ ] 🟠 **Couverture des chemins Redis** lockout / rate-limit en intégration — non exercés aujourd'hui.
- [ ] 🟠 **Property-based testing** (`proptest`) + **mutation testing** (`cargo-mutants`).
- [ ] 🟢 **Tests de contrat** (dérivés de l'OpenAPI) + tests de charge.

## 11. Frontend

- [ ] 🟠 **Audit accessibilité automatisé** (axe/pa11y) en CI — WCAG 2.2 AA (EAA 2025 UE).
- [ ] 🟢 Rate limiting applicatif / anti-abus côté front (au-delà du honeypot).
- [ ] 🟢 Collecte des rapports CSP (`report-to`) + Web Vitals / RUM.
- [ ] 🟢 Internationalisation (i18n) — selon la cible produit.

## 12. Conformité, Vie privée & Gouvernance

- [ ] 🔴 **Droits RGPD** : export (portabilité) + suppression (droit à l'oubli).
- [ ] 🟠 **Fichiers de gouvernance** : `LICENSE`, `CONTRIBUTING.md`, `CODEOWNERS`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`.
- [ ] 🟠 **ADR** (Architecture Decision Records) + diagrammes **C4** / modèle de menace **STRIDE**.
- [ ] 🟠 **Runbooks / réponse à incident** + registre de traitement des données — ISO 27001 / SRE.
- [ ] 🟢 Politique de rétention des logs (OpenSearch ISM) documentée — vie privée / coûts.

---

> Ce backlog est une photographie à la date du commit ; il est destiné à être
> tenu à jour au fil des PR (cocher les actions réalisées et référencer la PR).
