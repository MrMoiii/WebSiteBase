# =============================================================================
# Image multi-stage : dépendances -> build -> image finale minimale non-root.
#
# - `npm ci --ignore-scripts` : aucune exécution de script post-install de
#   dépendance (réduction du risque supply chain) ;
# - build `standalone` : l'image finale ne contient que le serveur compilé et
#   ses node_modules tracés, pas l'outillage de build ;
# - utilisateur non-root, port non privilégié, healthcheck sans shell réseau ;
# - le check anti-fuite de secrets est exécuté PENDANT le build de l'image.
#
# Le conteneur suppose un reverse proxy TLS en frontal (cf. README,
# en-têtes X-Forwarded-* attendus).
# =============================================================================

# ---- Stage 1 : dépendances (couche cacheable tant que le lockfile ne bouge pas)
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

# ---- Stage 2 : build ----
FROM node:22-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Valeurs FACTICES uniquement pour satisfaire le build : les vraies valeurs
# sont injectées au RUNTIME par l'orchestrateur et validées au démarrage
# (instrumentation.ts). Rien n'est inliné côté client : vérifié juste après
# par le check anti-fuite, qui fait échouer le build en cas de fuite.
RUN API_BASE_URL=http://api.invalid \
    SESSION_SECRET=build_time_dummy_secret_32_characters \
    COOKIE_SECURE=true \
    npm run build \
    && bash scripts/check-bundle-secrets.sh

# ---- Stage 3 : image finale minimale ----
FROM node:22-slim AS runner
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
WORKDIR /app

# Utilisateur non-root fourni par l'image node.
USER node

# Uniquement le serveur autonome + les assets statiques.
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/healthcheck.mjs ./healthcheck.mjs

# Port non privilégié, TLS terminé par le reverse proxy en frontal.
EXPOSE 3000

# Healthcheck sans curl/wget (image minimale) : fetch Node natif.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "healthcheck.mjs"]

CMD ["node", "server.js"]
