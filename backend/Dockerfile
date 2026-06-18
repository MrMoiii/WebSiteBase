# =============================================================================
# Image multi-stage : build Rust puis image finale distroless minimale.
# - Build avec SQLX_OFFLINE (cache .sqlx) => aucune base requise à la compilation.
# - Image finale distroless (pas de shell, pas de gestionnaire de paquets) :
#   surface d'attaque réduite, exécutée en utilisateur non-root.
# =============================================================================

# ---- Stage 1 : build ----
FROM rust:1-slim-bookworm AS builder

# Dépendances de build : compilateur C pour `ring` (TLS rustls) et `cmake` + C
# pour `aws-lc-sys` (backend cryptographique de `jsonwebtoken`), + certificats.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Compilation hors-ligne : les métadonnées des requêtes proviennent de .sqlx,
# pas d'une base de données.
ENV SQLX_OFFLINE=true

# 1) Copie des manifestes + cache des requêtes pour optimiser le cache de couches.
COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx

# 2) Pré-compile les dépendances avec un main vide (couche mise en cache tant
#    que Cargo.toml/Cargo.lock ne changent pas).
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

# 3) Copie du code réel et build final, lié statiquement au maximum.
COPY migrations ./migrations
COPY src ./src
# Touch pour forcer la recompilation du crate applicatif.
RUN touch src/main.rs && cargo build --release --locked \
    && cp target/release/websitebase-backend /websitebase-backend

# ---- Stage 2 : image finale distroless ----
# `cc` fournit la glibc + libgcc nécessaires au binaire ; `nonroot` exécute en
# uid 65532 sans privilèges.
FROM gcr.io/distroless/cc-debian12:nonroot

# Binaire unique, possédé par root mais exécuté par l'utilisateur non-root.
COPY --from=builder /websitebase-backend /app/websitebase-backend

# Port non privilégié (le binaire suppose un reverse proxy TLS en frontal).
EXPOSE 8080

USER nonroot:nonroot

# Healthcheck autonome (le binaire interroge lui-même /health ; distroless
# n'a ni shell ni curl).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/websitebase-backend", "healthcheck"]

ENTRYPOINT ["/app/websitebase-backend"]
