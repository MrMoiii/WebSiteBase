# Test de sécurité — audit des attaques « niches »

Ce document complète les `SECURITY.md` du [backend](./backend/SECURITY.md) et du
[frontend](./frontend/SECURITY.md), qui couvrent les attaques classiques (OWASP
Top 10 / API Security Top 10) — toutes vérifiées **conformes**. Il se concentre
sur des **vecteurs plus pointus**, classés des plus aux moins connus, avec pour
chacun le verdict et la mesure (ou le correctif apporté).

## Synthèse

| # | Attaque | Verdict | Suite donnée |
|---|---------|---------|--------------|
| A | Contournement du rate-limit via usurpation de `X-Forwarded-For` | 🟠 Faille | **Corrigé** |
| B | Race TOCTOU sur la rotation des refresh tokens | 🟠 Faille | **Corrigé** |
| D | Dépassement d'entier (overflow) sur la pagination | 🟡 Robustesse | **Corrigé** |
| C | Oracle d'énumération via le verrouillage de compte | 🟡 Tradeoff | Documenté/accepté |
| E | Énumération via `/auth/register` (409 ≠ 201) | 🟡 Inhérent | Documenté/accepté |

---

## A — Contournement du rate-limit via `X-Forwarded-For` (corrigé)

**Attaque.** Le rate limiting anti-bruteforce de `/auth/*` était keyé par
`tower_governor::SmartIpKeyExtractor`, qui retient l'IP **la plus à gauche** de
`X-Forwarded-For` — une valeur entièrement contrôlée par le client. Un attaquant
n'avait qu'à faire tourner cet en-tête (`X-Forwarded-For: <aléatoire>`) à chaque
requête pour obtenir un nouveau quota à chaque fois, neutralisant l'anti-bruteforce
réseau (password spraying, abus de `/register` et `/refresh`). Le verrouillage de
compte limitait encore le bruteforce ciblé sur **un** compte, mais pas le spraying.

Ironie : `middleware/client.rs` calculait déjà une IP de confiance pour les logs,
mais le rate-limiter ne l'utilisait pas — et cette logique contenait elle-même un
**off-by-one** (`index = len - 1 - hops` au lieu de `len - hops`) qui retenait une
entrée XFF forgeable.

**Correctif.**
- `middleware/client.rs` : fonction `client_ip()` partagée, corrigée. Modèle
  standard (nginx `proxy_add_x_forwarded_for`) : les `trusted_hops` entrées **les
  plus à droite** sont écrites par notre infrastructure et infalsifiables ; l'IP
  réelle est à l'index `len - trusted_hops`. `trusted_hops == 0` ⇒ XFF jamais
  utilisé. Chaîne plus courte que `hops` ⇒ repli prudent sur le pair TCP.
- Nouveau `RateLimitKeyExtractor` (même logique) remplace `SmartIpKeyExtractor`
  dans `routes/mod.rs`, keyé sur l'IP de confiance.
- 6 tests unitaires, dont `one_hop_rejects_spoofed_leftmost_xff` qui prouve qu'une
  valeur forgée à gauche est ignorée au profit de l'IP réelle.

## B — Race TOCTOU sur la rotation des refresh tokens (corrigé)

**Attaque.** `POST /auth/refresh` faisait `SELECT (vérifie non révoqué) → UPDATE
(révoque) → émet`. Le résultat de la révocation était **ignoré**. Deux requêtes
concurrentes présentant le même refresh token passaient toutes deux le contrôle
« non révoqué » avant le `UPDATE`, et émettaient **chacune** une nouvelle session :
un même token engendrait plusieurs sessions valides (rejeu).

**Correctif.** `handlers/auth.rs` : la révocation est déjà atomique
(`UPDATE … WHERE revoked_at IS NULL`) et retourne le nombre de lignes affectées.
On **exige désormais `rows_affected == 1`** ; sinon (race perdue ou rejeu d'un
token déjà tourné) la requête est rejetée en `401` et un événement SOC
`refresh_token_reuse` est journalisé.

> Renforcement possible (non inclus, nécessite une nouvelle requête SQL donc une
> régénération du cache `.sqlx` avec une base) : sur rejeu détecté, révoquer
> **toute la famille** de tokens de l'utilisateur (détection de vol façon OWASP).

## D — Overflow d'entier sur la pagination (corrigé)

**Attaque.** `PaginationQuery.page` n'avait pas de borne **maximale**. Le calcul
`offset = (page - 1) * page_size` en `i64` débordait pour un `page` proche de
`i64::MAX` : en build *release*, l'enroulement silencieux pouvait produire un
OFFSET négatif (erreur SQL → 500) ; en *debug*, une panique (→ 500 via CatchPanic).

**Correctif.** `models/pagination.rs` : `offset()` utilise une arithmétique
**saturante** (`saturating_sub` / `saturating_mul`). Le pire cas devient un OFFSET
plafonné à `i64::MAX` (page vide), sans erreur ni panique. Test
`offset_saturates_instead_of_overflowing` ajouté.

## C — Oracle d'énumération via le verrouillage (accepté/documenté)

Un compte verrouillé renvoie **429**, un compte inexistant **401**. En provoquant
le lockout (N échecs), un attaquant distingue « le compte existe » — contournant
partiellement l'anti-énumération (401 générique + hash factice). Cela permet aussi
un **DoS ciblé** (verrouiller une victime ~15 min).

**Décision.** Tradeoff classique du verrouillage de compte, déjà borné par le
rate-limit IP (désormais non contournable, cf. A). Masquer l'état verrouillé
(renvoyer un 401 générique) supprimerait l'oracle au prix de l'UX (l'utilisateur
légitime n'est plus informé de son verrouillage) ; à arbitrer selon le besoin
produit. Non modifié dans cette itération.

## E — Énumération via `/auth/register` (inhérent/documenté)

`register` renvoie **409** sur email déjà pris (≠ 201) : oracle d'existence au
niveau de l'API. Le frontend BFF le masque (message générique), mais le backend —
l'autorité, joignable directement — fuit l'information.

**Décision.** Inhérent à l'inscription synchrone. La parade standard est un **flux
de vérification d'email** (réponse toujours générique « si l'adresse est nouvelle,
consultez votre boîte mail »), explicitement hors périmètre de cette itération
(cf. `backend/SECURITY.md`, « Limites connues »).

---

## Validation

- `cargo test --lib` : 26/26 OK (dont 9 nouveaux tests pour A et D).
- `cargo fmt --all --check` : propre.
- `cargo clippy --all-targets --all-features -- -D warnings` : zéro warning.
- Aucune requête SQL ajoutée/modifiée : le cache `.sqlx` reste valide (build
  offline CI inchangé). Les tests d'intégration (base requise) s'exécutent en CI.
