# WebSiteBase

Projet de modèle de site web. Le développement est organisé par briques, chacune
introduite via une *pull request* dédiée vers `main`.

## Composants

| Composant | Emplacement | État |
|---|---|---|
| Backend (API REST Rust/Axum sécurisée) | [`backend/`](./backend) | en cours d'intégration (PR) |
| Frontend (Next.js/TypeScript sécurisé, pattern BFF) | [`frontend/`](./frontend) | en cours d'intégration (PR) |
| Monitoring d'API (OpenSearch + Dashboards, optionnel) | [`backend/MONITORING.md`](./backend/MONITORING.md) | brique dédiée (branche `opensearch`) |
| Sessions Redis (source de vérité, révocation immédiate, cookies) | [`backend/SESSIONS.md`](./backend/SESSIONS.md) | brique dédiée (branche `redis`) |

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
