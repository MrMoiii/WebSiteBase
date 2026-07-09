//! Store de sessions Redis — source de vérité des sessions/refresh tokens.
//!
//! Modèle de données (Redis) :
//! - `sess:{sid}`  HASH  { user_id, created_at, last_seen, ua, ip, rth } — une
//!   session logique STABLE à travers les rotations de refresh token. TTL glissant
//!   (idle) rafraîchi à chaque usage ; un plafond ABSOLU (`created_at`) borne la
//!   durée totale.
//! - `rt:{token_hash}`  STRING = `sid` — pointe le refresh token courant vers sa
//!   session. La rotation fait un `GETDEL` ATOMIQUE : un seul appelant obtient le
//!   `sid`, les rejeux/concurrents obtiennent `nil` (anti-rejeu, comme l'ancien
//!   `rows_affected == 1` de Postgres).
//! - `usess:{user_id}`  SET de `sid` — index pour lister/révoquer les sessions.
//! - `lock:{user_id}`  compteur d'échecs de login (verrouillage distribué).
//! - `rl:{clé}`  compteur de rate limiting distribué (fenêtre fixe).
//!
//! Sécurité : le refresh token n'est jamais stocké en clair (on n'indexe que son
//! empreinte, cf. `auth::tokens`). Redis n'est jamais exposé au frontend.

use std::collections::HashMap;
use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::RedisConfig;

/// Erreur d'infrastructure du store (Redis injoignable, réponse illisible…).
/// Les issues MÉTIER (rejeu, session absente) sont des valeurs de retour, pas
/// des erreurs.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("redis error: {0}")]
    Backend(String),
}

impl From<redis::RedisError> for SessionError {
    fn from(e: redis::RedisError) -> Self {
        SessionError::Backend(e.to_string())
    }
}

/// Résultat d'une rotation réussie.
#[derive(Debug, Clone)]
pub struct Rotated {
    pub sid: Uuid,
    pub user_id: Uuid,
}

/// Vue interne d'une session (pour l'endpoint « mes sessions actives »).
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub sid: Uuid,
    pub created_at: i64,
    pub last_seen: i64,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

/// Store de sessions clonable (la `ConnectionManager` multiplexe une connexion).
#[derive(Clone)]
pub struct SessionStore {
    conn: ConnectionManager,
    idle_ttl: Duration,
    absolute_ttl: Duration,
    auth_rl_max: u32,
    auth_rl_window: Duration,
}

fn sess_key(sid: &Uuid) -> String {
    format!("sess:{sid}")
}
fn rt_key(token_hash: &str) -> String {
    format!("rt:{token_hash}")
}
fn user_key(user_id: &Uuid) -> String {
    format!("usess:{user_id}")
}

/// Convertit une chaîne vide en `None` (les champs ua/ip absents sont vides).
fn opt(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

impl SessionStore {
    /// Ouvre la connexion Redis (fail-fast au démarrage si injoignable).
    pub async fn connect(cfg: &RedisConfig, idle_ttl: Duration) -> Result<Self, SessionError> {
        let client = redis::Client::open(cfg.url.expose())?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            idle_ttl,
            absolute_ttl: cfg.session_absolute_ttl,
            auth_rl_max: cfg.auth_rate_limit_max,
            auth_rl_window: cfg.auth_rate_limit_window,
        })
    }

    fn idle_secs(&self) -> i64 {
        self.idle_ttl.as_secs() as i64
    }
    fn abs_secs(&self) -> i64 {
        self.absolute_ttl.as_secs() as i64
    }

    /// Vérifie la disponibilité du store (readiness).
    pub async fn ping(&self) -> Result<(), SessionError> {
        let mut conn = self.conn.clone();
        redis::cmd("PING").query_async::<()>(&mut conn).await?;
        Ok(())
    }

    /// Crée une nouvelle session et son refresh token courant. Renvoie le `sid`
    /// (stable, à placer dans le JWT). Écriture atomique (pipeline `MULTI`).
    pub async fn create(
        &self,
        user_id: Uuid,
        user_agent: Option<&str>,
        ip: Option<&str>,
        rt_hash: &str,
    ) -> Result<Uuid, SessionError> {
        let sid = Uuid::new_v4();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let sess = sess_key(&sid);
        let mut conn = self.conn.clone();

        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&sess)
            .arg("user_id")
            .arg(user_id.to_string())
            .arg("created_at")
            .arg(now)
            .arg("last_seen")
            .arg(now)
            .arg("ua")
            .arg(user_agent.unwrap_or(""))
            .arg("ip")
            .arg(ip.unwrap_or(""))
            .arg("rth")
            .arg(rt_hash)
            .ignore()
            .cmd("EXPIRE")
            .arg(&sess)
            .arg(self.idle_secs())
            .ignore()
            .cmd("SET")
            .arg(rt_key(rt_hash))
            .arg(sid.to_string())
            .arg("EX")
            .arg(self.idle_secs())
            .ignore()
            .cmd("SADD")
            .arg(user_key(&user_id))
            .arg(sid.to_string())
            .ignore()
            .cmd("EXPIRE")
            .arg(user_key(&user_id))
            .arg(self.abs_secs())
            .ignore()
            .query_async::<()>(&mut conn)
            .await?;

        Ok(sid)
    }

    /// Rotation du refresh token. `GETDEL` atomique sur l'ancien token : renvoie
    /// `Ok(None)` si le token est inconnu/déjà tourné (rejeu) ou si le plafond
    /// absolu est dépassé (dans ce cas la session est détruite).
    pub async fn rotate(
        &self,
        old_hash: &str,
        new_hash: &str,
    ) -> Result<Option<Rotated>, SessionError> {
        let mut conn = self.conn.clone();

        // Prise ATOMIQUE de l'ancien refresh token : un seul gagnant.
        let sid: Option<String> = conn.get_del(rt_key(old_hash)).await?;
        let Some(sid) = sid else {
            return Ok(None);
        };
        let Ok(sid) = Uuid::parse_str(&sid) else {
            return Ok(None);
        };
        let sess = sess_key(&sid);

        let fields: HashMap<String, String> = conn.hgetall(&sess).await?;
        let (Some(user_id), Some(created)) = (fields.get("user_id"), fields.get("created_at"))
        else {
            return Ok(None);
        };
        let Ok(user_id) = Uuid::parse_str(user_id) else {
            return Ok(None);
        };
        let created: i64 = created.parse().unwrap_or(0);
        let now = OffsetDateTime::now_utc().unix_timestamp();

        // Plafond absolu : au-delà, la session est morte (re-login exigé).
        if now - created > self.abs_secs() {
            self.delete(&sid, &user_id).await?;
            return Ok(None);
        }

        // Installe le nouveau token + prolonge la session (TTL glissant).
        redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(rt_key(new_hash))
            .arg(sid.to_string())
            .arg("EX")
            .arg(self.idle_secs())
            .ignore()
            .cmd("HSET")
            .arg(&sess)
            .arg("last_seen")
            .arg(now)
            .arg("rth")
            .arg(new_hash)
            .ignore()
            .cmd("EXPIRE")
            .arg(&sess)
            .arg(self.idle_secs())
            .ignore()
            .cmd("EXPIRE")
            .arg(user_key(&user_id))
            .arg(self.abs_secs())
            .ignore()
            .query_async::<()>(&mut conn)
            .await?;

        Ok(Some(Rotated { sid, user_id }))
    }

    /// Vérifie qu'une session est toujours active et renvoie son propriétaire
    /// (utilisé par l'extracteur d'auth pour révoquer immédiatement un JWT).
    pub async fn owner_if_active(&self, sid: &Uuid) -> Result<Option<Uuid>, SessionError> {
        let mut conn = self.conn.clone();
        let uid: Option<String> = conn.hget(sess_key(sid), "user_id").await?;
        Ok(uid.and_then(|u| Uuid::parse_str(&u).ok()))
    }

    /// Déconnexion : révoque la session portant le refresh token présenté.
    /// Idempotent.
    pub async fn logout(&self, rt_hash: &str) -> Result<(), SessionError> {
        let mut conn = self.conn.clone();
        let sid: Option<String> = conn.get_del(rt_key(rt_hash)).await?;
        if let Some(sid) = sid.and_then(|s| Uuid::parse_str(&s).ok()) {
            if let Some(uid) = self.owner_if_active(&sid).await? {
                self.delete(&sid, &uid).await?;
            }
        }
        Ok(())
    }

    /// Liste les sessions actives d'un utilisateur (purge les `sid` périmés).
    pub async fn list(&self, user_id: &Uuid) -> Result<Vec<SessionSummary>, SessionError> {
        let mut conn = self.conn.clone();
        let sids: Vec<String> = conn.smembers(user_key(user_id)).await?;
        let mut out = Vec::with_capacity(sids.len());
        for sid_str in sids {
            let Ok(sid) = Uuid::parse_str(&sid_str) else {
                continue;
            };
            let fields: HashMap<String, String> = conn.hgetall(sess_key(&sid)).await?;
            if fields.is_empty() {
                // Session expirée via TTL : on purge le `sid` orphelin de l'index.
                let _: i64 = conn.srem(user_key(user_id), &sid_str).await?;
                continue;
            }
            out.push(SessionSummary {
                sid,
                created_at: fields
                    .get("created_at")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                last_seen: fields
                    .get("last_seen")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
                user_agent: fields.get("ua").cloned().and_then(opt),
                ip: fields.get("ip").cloned().and_then(opt),
            });
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.last_seen));
        Ok(out)
    }

    /// Révoque UNE session d'un utilisateur (vérifie l'appartenance). Renvoie
    /// `true` si une session a bien été révoquée.
    pub async fn revoke(&self, user_id: &Uuid, sid: &Uuid) -> Result<bool, SessionError> {
        // Ownership : on ne révoque que si la session appartient à l'utilisateur.
        match self.owner_if_active(sid).await? {
            Some(owner) if &owner == user_id => {
                self.delete(sid, user_id).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Révoque toutes les sessions de l'utilisateur SAUF `keep` (déconnexion des
    /// autres appareils). Renvoie le nombre de sessions révoquées.
    pub async fn revoke_others(&self, user_id: &Uuid, keep: &Uuid) -> Result<u64, SessionError> {
        let mut conn = self.conn.clone();
        let sids: Vec<String> = conn.smembers(user_key(user_id)).await?;
        let mut revoked = 0u64;
        for sid_str in sids {
            let Ok(sid) = Uuid::parse_str(&sid_str) else {
                continue;
            };
            if &sid == keep {
                continue;
            }
            self.delete(&sid, user_id).await?;
            revoked += 1;
        }
        Ok(revoked)
    }

    /// Supprime une session : efface le hash, son refresh token courant et le
    /// retire de l'index utilisateur.
    async fn delete(&self, sid: &Uuid, user_id: &Uuid) -> Result<(), SessionError> {
        let mut conn = self.conn.clone();
        let sess = sess_key(sid);
        let rth: Option<String> = conn.hget(&sess, "rth").await?;
        let mut pipe = redis::pipe();
        pipe.atomic();
        if let Some(rth) = rth {
            pipe.cmd("DEL").arg(rt_key(&rth)).ignore();
        }
        pipe.cmd("DEL")
            .arg(&sess)
            .ignore()
            .cmd("SREM")
            .arg(user_key(user_id))
            .arg(sid.to_string())
            .ignore();
        pipe.query_async::<()>(&mut conn).await?;
        Ok(())
    }

    // --- Verrouillage anti-bruteforce (distribué) --------------------------

    /// L'utilisateur est-il verrouillé (>= `max` échecs récents) ?
    pub async fn is_locked(&self, user_id: &Uuid, max: i64) -> Result<bool, SessionError> {
        let mut conn = self.conn.clone();
        let n: Option<i64> = conn.get(format!("lock:{user_id}")).await?;
        Ok(n.unwrap_or(0) >= max)
    }

    /// Enregistre un échec de login et (ré)arme la fenêtre. Renvoie le compteur
    /// courant.
    ///
    /// `INCR` + `EXPIRE` sont émis dans un **`MULTI` atomique** : les deux
    /// s'appliquent ensemble ou pas du tout. Sans cela, une panne entre les deux
    /// (erreur réseau sur l'`EXPIRE`, ou crash du process) laisserait la clé
    /// SANS TTL — verrouillant le compte DÉFINITIVEMENT une fois le seuil
    /// atteint. Poser l'`EXPIRE` à chaque échec en fait une fenêtre glissante
    /// (le verrou n'expire qu'après l'arrêt des tentatives), ce qui est le
    /// comportement souhaité pour un anti-bruteforce.
    pub async fn record_login_failure(
        &self,
        user_id: &Uuid,
        window: Duration,
    ) -> Result<i64, SessionError> {
        let mut conn = self.conn.clone();
        let key = format!("lock:{user_id}");
        let (count,): (i64,) = redis::pipe()
            .atomic()
            .incr(&key, 1)
            .expire(&key, window.as_secs() as i64)
            .ignore()
            .query_async(&mut conn)
            .await?;
        Ok(count)
    }

    /// Réinitialise le compteur d'échecs (login réussi).
    pub async fn clear_login_failures(&self, user_id: &Uuid) -> Result<(), SessionError> {
        let mut conn = self.conn.clone();
        let _: i64 = conn.del(format!("lock:{user_id}")).await?;
        Ok(())
    }

    // --- Rate limiting distribué (fenêtre fixe) ----------------------------

    /// Autorise (ou non) une requête d'auth pour `key` (typiquement l'IP), selon
    /// le quota configuré.
    ///
    /// `INCR` + `EXPIRE` sont émis dans un **`MULTI` atomique** (même raison que
    /// `record_login_failure` : sans cela une clé sans TTL bloquerait l'IP à
    /// vie). Fenêtre glissante : elle se réarme tant que le client insiste, ce
    /// qui maintient le blocage sous rafale — le comportement voulu.
    pub async fn auth_rate_limit_ok(&self, key: &str) -> Result<bool, SessionError> {
        let mut conn = self.conn.clone();
        let rl = format!("rl:auth:{key}");
        let (count,): (i64,) = redis::pipe()
            .atomic()
            .incr(&rl, 1)
            .expire(&rl, self.auth_rl_window.as_secs() as i64)
            .ignore()
            .query_async(&mut conn)
            .await?;
        Ok(count <= i64::from(self.auth_rl_max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_helpers_are_namespaced() {
        let sid = Uuid::nil();
        assert_eq!(sess_key(&sid), format!("sess:{sid}"));
        assert_eq!(rt_key("abc"), "rt:abc");
        assert_eq!(user_key(&sid), format!("usess:{sid}"));
    }

    #[test]
    fn opt_maps_empty_to_none() {
        assert_eq!(opt(String::new()), None);
        assert_eq!(opt("x".to_string()), Some("x".to_string()));
        // Seule la chaîne VIDE devient None : un blanc est une valeur légitime.
        assert_eq!(opt(" ".to_string()), Some(" ".to_string()));
    }

    #[test]
    fn keys_use_distinct_namespaces_for_same_uuid() {
        // Un même UUID ne doit jamais produire de collision entre espaces de clés.
        let id = Uuid::new_v4();
        let sess = sess_key(&id);
        let user = user_key(&id);
        assert!(sess.starts_with("sess:"));
        assert!(user.starts_with("usess:"));
        assert_ne!(sess, user);
        assert!(sess.contains(&id.to_string()));
    }

    #[test]
    fn error_from_redis_is_backend_variant() {
        // Toute erreur d'infrastructure Redis se mappe sur `Backend` (=> 503).
        let redis_err: redis::RedisError = (redis::ErrorKind::IoError, "connection reset").into();
        let mapped: SessionError = redis_err.into();
        assert!(matches!(mapped, SessionError::Backend(_)));
    }
}
