# WebSiteBase

Projet de modèle de site web. Le développement est organisé par briques, chacune
introduite via une *pull request* dédiée vers `main`.

## Composants

| Composant | Emplacement | État |
|---|---|---|
| Backend (API REST Rust/Axum sécurisée) | [`backend/`](./backend) | intégré dans `main` |
| Frontend (Next.js/TypeScript sécurisé, pattern BFF) | [`frontend/`](./frontend) | intégré dans `main` |
| Monitoring d'API (OpenSearch + Dashboards + Prometheus, optionnel) | [`backend/MONITORING.md`](./backend/MONITORING.md) | intégré (issu de la branche `opensearch`) |
| Sessions Redis (source de vérité, révocation immédiate, cookies) | [`backend/SESSIONS.md`](./backend/SESSIONS.md) | intégré (issu de la branche `redis`) |
| Base de tests (unitaires exhaustifs + intégration) | [`backend/tests/`](./backend/tests) | intégré (issu de la branche `test-unitaire`) |

## Démarrage rapide (stack complète)

```bash
cd backend && docker compose up -d --build   # API + PostgreSQL + Redis
cd ../frontend && docker compose up --build  # frontend sur http://localhost:3000
```

## Contribution

- `main` est la branche d'intégration stable.
- Chaque brique est développée sur une branche dédiée et fusionnée par PR après
  passage de la CI.

Voir le [README du backend](./backend/README.md) et le
[README du frontend](./frontend/README.md) pour le détail de chaque partie.
