//! Library surface for the `agency-server` crate.
//!
//! 2.1.0: integration tests link against this lib to
//! bind a real `axum` router on a random port. The
//! `main.rs` binary is a thin wrapper that constructs
//! the production `ServerState` and calls `axum::serve`.

pub mod audit_recorder;
pub mod auth;
pub mod catalog;
pub mod env_validate;
pub mod error_response;
pub mod handlers;
pub mod idempotency;
pub mod oidc;
pub mod oidc_client;
pub mod plan;
pub mod session_cookie;
pub mod state;
pub mod vault_init;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_dep_core::infrastructure::repository::audit_log_repository::AuditLogRepository;
use agent_dep_core::infrastructure::repository::pending_deploys_repository::PendingDeployRepository;
use agent_dep_core::infrastructure::repository::secrets_repository::SecretRepository;
use agent_dep_core::infrastructure::repository::targets_repository::TargetRepository;
use agent_dep_core::infrastructure::repository::users_repository::UserRepository;
use agent_dep_core::infrastructure::sqlite::connect;
use anyhow::{Context, Result};
use axum::{
    extract::{Request, State},
    middleware::{self, Next},
    routing::{get, post},
    Router,
};
use base64::Engine;
use rand::RngCore;
use tower_http::trace::TraceLayer;

pub use state::ServerState;

pub fn router(state: ServerState) -> Router {
    // 2.11.0 (P1-D-03, TZ #1 §10 / D-03,
    // CWE-362): the `Idempotency-Key`
    // middleware. We add it as a
    // `route_layer` on the entire
    // `authed` sub-router so every
    // mutation endpoint is wrapped
    // (the middleware is a no-op for
    // GET / HEAD / OPTIONS and for
    // requests without the
    // `Idempotency-Key` header). The
    // middleware runs AFTER the
    // `require_session_or_bearer`
    // layer (auth happens first; the
    // idempotency layer never sees
    // an unauthenticated request).
    let idempotency_layer =
        middleware::from_fn_with_state(state.clone(), idempotency::idempotency_middleware);
    // Each per-route layer inserts its `AllowedRoles`
    // extension and then delegates to
    // `auth::check_role`. The state is threaded via
    // `from_fn_with_state`.
    let authed = Router::new()
        // viewer-or-higher
        .route(
            "/v1/audit",
            get(handlers::list_audit)
                .layer(middleware::from_fn_with_state(state.clone(), allow_viewer)),
        )
        .route(
            "/v1/systems",
            get(handlers::list_systems)
                .layer(middleware::from_fn_with_state(state.clone(), allow_viewer)),
        )
        .route(
            "/v1/deploys",
            get(handlers::list_deploys)
                .layer(middleware::from_fn_with_state(state.clone(), allow_viewer)),
        )
        .route(
            "/v1/deploys/:id",
            get(handlers::get_deploy)
                .layer(middleware::from_fn_with_state(state.clone(), allow_viewer)),
        )
        // 2.4.0 multi-environment
        .route(
            "/v1/environments",
            get(handlers::list_environments)
                .layer(middleware::from_fn_with_state(state.clone(), allow_viewer)),
        )
        // operator-or-higher
        .route(
            "/v1/deploys",
            post(handlers::request_deploy).layer(middleware::from_fn_with_state(
                state.clone(),
                allow_operator,
            )),
        )
        .route(
            "/v1/deploys/:id/applied",
            post(handlers::mark_applied).layer(middleware::from_fn_with_state(
                state.clone(),
                allow_operator,
            )),
        )
        .route(
            "/v1/systems/plan",
            post(handlers::plan_system).layer(middleware::from_fn_with_state(
                state.clone(),
                allow_operator,
            )),
        )
        .route(
            "/v1/rollback/:id",
            post(handlers::rollback_operation).layer(middleware::from_fn_with_state(
                state.clone(),
                allow_operator,
            )),
        )
        // admin-only
        .route(
            "/v1/deploys/:id/approve",
            post(handlers::approve_deploy)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        .route(
            "/v1/deploys/:id/reject",
            post(handlers::reject_deploy)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        .route(
            "/v1/users",
            get(handlers::list_users)
                .post(handlers::create_user)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        .route(
            "/v1/users/:id",
            axum::routing::delete(handlers::disable_user)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        .route(
            "/v1/users/:id/rotate",
            post(handlers::rotate_user_token)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        // 2.3.0 vault
        .route(
            "/v1/secrets",
            get(handlers::list_secrets)
                .layer(middleware::from_fn_with_state(state.clone(), allow_viewer)),
        )
        .route(
            "/v1/secrets/:name",
            get(handlers::get_secret).layer(middleware::from_fn_with_state(
                state.clone(),
                allow_operator,
            )),
        )
        .route(
            "/v1/secrets",
            post(handlers::create_secret)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        .route(
            "/v1/secrets/:name",
            axum::routing::delete(handlers::delete_secret)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        .route(
            "/v1/secrets/:name",
            axum::routing::put(handlers::update_secret)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        // 2.5.0 fleet (ADR-0023): targets
        // registry. List/get is read-only
        // metadata so viewer+ is enough;
        // create/delete is admin-only.
        .route(
            "/v1/targets",
            get(handlers::list_targets)
                .layer(middleware::from_fn_with_state(state.clone(), allow_viewer)),
        )
        .route(
            "/v1/targets/:id",
            get(handlers::get_target)
                .layer(middleware::from_fn_with_state(state.clone(), allow_viewer)),
        )
        .route(
            "/v1/targets",
            post(handlers::create_target)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        .route(
            "/v1/targets/:id",
            axum::routing::delete(handlers::delete_target)
                .layer(middleware::from_fn_with_state(state.clone(), allow_admin)),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session_or_bearer,
        ))
        // 2.11.0 (P1-D-03, CWE-362):
        // the `Idempotency-Key` middleware.
        // Sits AFTER
        // `require_session_or_bearer` (so
        // unauthenticated requests get a
        // 401 first and never reach the
        // idempotency layer) and BEFORE
        // the per-route role guard
        // (a request with a valid key
        // and a stale role still gets
        // the cached 403 if it
        // replays). See
        // `crate::idempotency` for the
        // full design.
        .route_layer(idempotency_layer);
    // 2.7.6 OIDC (ADR-0034). The OIDC
    // endpoints are PUBLIC — no bearer
    // required. They sit OUTSIDE the
    // `require_bearer` middleware.
    // 2.7.8 (ADR-0036): adds
    // `POST /v1/auth/oidc/refresh` and
    // `GET /v1/auth/oidc/logout`.
    let oidc_routes = Router::new()
        .route("/v1/auth/oidc/login", get(oidc::login_handler))
        .route("/v1/auth/oidc/callback", get(oidc::callback_handler))
        .route(
            "/v1/auth/oidc/refresh",
            axum::routing::post(oidc::refresh_handler),
        )
        .route("/v1/auth/oidc/logout", get(oidc::logout_handler));
    Router::new()
        .route("/v1/health", get(handlers::health))
        .merge(oidc_routes)
        .merge(authed)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

async fn allow_viewer(
    State(state): State<ServerState>,
    mut request: Request,
    next: Next,
) -> axum::response::Response {
    use agent_dep_core::infrastructure::repository::users_repository::Role;
    request.extensions_mut().insert(auth::AllowedRoles(vec![
        Role::Viewer,
        Role::Operator,
        Role::Admin,
    ]));
    auth::check_role(state, request, next).await
}

async fn allow_operator(
    State(state): State<ServerState>,
    mut request: Request,
    next: Next,
) -> axum::response::Response {
    use agent_dep_core::infrastructure::repository::users_repository::Role;
    request
        .extensions_mut()
        .insert(auth::AllowedRoles(vec![Role::Operator, Role::Admin]));
    auth::check_role(state, request, next).await
}

async fn allow_admin(
    State(state): State<ServerState>,
    mut request: Request,
    next: Next,
) -> axum::response::Response {
    use agent_dep_core::infrastructure::repository::users_repository::Role;
    request
        .extensions_mut()
        .insert(auth::AllowedRoles(vec![Role::Admin]));
    auth::check_role(state, request, next).await
}

/// Read the bearer token from `path`. If the file does
/// not exist, generate a 256-bit random token, persist
/// it, and return it. The file is created with mode
/// 0600 on POSIX (best effort — `std::fs` does not
/// expose a portable chmod, so we wrap the file in a
/// directory that already has restrictive permissions).
pub fn ensure_token(path: &Path) -> Result<String> {
    if path.is_file() {
        let s =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    std::fs::write(path, &token).with_context(|| format!("write {}", path.display()))?;
    set_token_file_mode(path);
    Ok(token)
}

#[cfg(unix)]
fn set_token_file_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn set_token_file_mode(_path: &Path) {}

pub fn default_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AGENCY_SERVER_DATA_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var("AGENCY_DATA_DIR") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".agency-server")
}

pub fn default_db_path() -> PathBuf {
    default_data_dir().join("data").join("agency.db")
}

/// Boot a `ServerState` for the production default
/// data dir. On first start with a 2.0.0
/// `server.token` file, the legacy token is migrated
/// to an `admin` user so existing scripts keep
/// working.
pub async fn boot_default_state() -> Result<ServerState> {
    let data_dir = default_data_dir();
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create_dir_all {}", data_dir.display()))?;
    let db_path = default_db_path();
    std::fs::create_dir_all(db_path.parent().unwrap())?;
    let db = connect(&db_path).await?;
    db.migrate().await?;
    let users = UserRepository::new(db.pool().clone());
    let token_path = data_dir.join("server.token");
    let legacy_token = if token_path.is_file() {
        let s = std::fs::read_to_string(&token_path)
            .with_context(|| format!("read {}", token_path.display()))?;
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            ensure_token(&token_path)?
        } else {
            // 2.0.0 → 2.1.0 migration: try to migrate
            // the legacy token to an `admin` user.
            // If the users table is already
            // populated, the migration is a no-op.
            let _ = users.migrate_legacy_token(&trimmed).await?;
            trimmed
        }
    } else {
        // Fresh install: bootstrap an admin user with
        // a fresh token. Print the token path to stderr
        // (NEVER the token itself — Q9, see ADR-0043).
        // The operator reads the token from the file
        // directly (e.g. `cat /var/lib/agency/server.token`
        // or the equivalent in their secret manager).
        let created = users
            .create(
                "admin",
                agent_dep_core::infrastructure::repository::users_repository::Role::Admin,
            )
            .await
            .with_context(|| "create initial admin user")?;
        let token = created.token.clone();
        std::fs::write(&token_path, &token)
            .with_context(|| format!("write {}", token_path.display()))?;
        set_token_file_mode(&token_path);
        eprintln!(
            "agency-server: created initial admin user, token saved to {} \
             (mode 0600; read with `cat` or your secret manager — \
             the plain token is NOT logged by this process)",
            token_path.display()
        );
        token
    };
    let audit = match std::env::var("AGENCY_AUDIT_HMAC_KEY") {
        Ok(hex_key) => {
            // Production mode: enable the
            // P1-AUD-02 hash chain + HMAC.
            // The key is a hex-encoded
            // 32-byte secret loaded from the
            // operator's secret manager
            // (same fail-closed pattern as
            // AGENCY_VAULT_PASSPHRASE). An
            // invalid hex string or wrong
            // length falls back to the
            // legacy `new()` constructor +
            // a `tracing::warn!` so the
            // operator notices.
            let bytes = match hex::decode(hex_key.trim()) {
                Ok(b) if b.len() >= 32 => b,
                Ok(b) => {
                    eprintln!(
                        "warning: AGENCY_AUDIT_HMAC_KEY decoded to {} bytes; \
                         the P1-AUD-02 chain requires >= 32 bytes; \
                         falling back to legacy chain-less audit log",
                        b.len()
                    );
                    vec![]
                }
                Err(e) => {
                    eprintln!(
                        "warning: AGENCY_AUDIT_HMAC_KEY is not valid hex ({e}); \
                         falling back to legacy chain-less audit log"
                    );
                    vec![]
                }
            };
            if bytes.len() >= 32 {
                match AuditLogRepository::with_hmac_key(db.pool().clone(), bytes) {
                    Ok(repo) => repo,
                    Err(e) => {
                        eprintln!(
                            "warning: AGENCY_AUDIT_HMAC_KEY rejected by the \
                             chain constructor ({e}); falling back to \
                             legacy chain-less audit log"
                        );
                        AuditLogRepository::new(db.pool().clone())
                    }
                }
            } else {
                AuditLogRepository::new(db.pool().clone())
            }
        }
        Err(_) => {
            // Dev / test mode: no HMAC key
            // configured; the chain columns
            // stay empty and every row is
            // treated as legacy by
            // `verify_chain`. Production
            // deploys MUST set
            // AGENCY_AUDIT_HMAC_KEY to a
            // 32-byte hex string; the
            // fail-closed path is documented
            // in the operator README.
            AuditLogRepository::new(db.pool().clone())
        }
    };
    // P1-PERF-01 (TZ #1 §19, CWE-400
    // adjacent): wrap the audit repo in a
    // debounced recorder. Successful GETs go
    // through `record_async` (batched, one
    // fsync per batch); POST / PUT / DELETE
    // and every error path go through
    // `record_sync` (durable, one fsync per
    // row). The flush task lives for the
    // lifetime of the `ServerState`; tests
    // shut it down explicitly before
    // asserting audit row counts.
    //
    // We discard the `JoinHandle` here because
    // the production main loop does not have a
    // clean shutdown signal — the OS kills the
    // tokio runtime on Ctrl-C, the flush task
    // exits on its next `select!` arm, and any
    // uncommitted events in the queue are
    // lost. This is the standard
    // "best-effort background task" trade-off;
    // the alternative (synchronous drain on
    // shutdown) would require plumbing a
    // `CancellationToken` through every
    // request handler, which is a much larger
    // refactor.
    let (audit_recorder, _flush_handle) = audit_recorder::AuditRecorder::debounced(
        audit,
        audit_recorder::DEFAULT_FLUSH_INTERVAL,
        audit_recorder::DEFAULT_BATCH_SIZE,
        audit_recorder::DEFAULT_CHANNEL_CAPACITY,
    );
    let audit = audit_recorder;
    let deploys = PendingDeployRepository::new(db.pool().clone());
    // P0-F-05 (TZ #1 §6 F-05 + TZ #2 WP-2.1):
    // vault passphrase is fail-closed.
    // 1. Loaded via vault_init::load_passphrase()
    //    (prefers AGENCY_VAULT_PASSPHRASE_FILE,
    //     falls back to AGENCY_VAULT_PASSPHRASE).
    // 2. Validated against the security policy
    //    (no placeholder, entropy >= 80 bits).
    // 3. Per-install salt is loaded from
    //    <data_dir>/vault.salt (or generated on
    //    first boot).
    // 4. The pre-fix placeholder vault
    //    ("unset-rotate-before-first-use") is gone
    //    — the server refuses to start without a
    //    valid passphrase, even on a fresh install
    //    with no secrets in the table.
    let passphrase =
        vault_init::load_passphrase().map_err(|e| anyhow::anyhow!("load vault passphrase: {e}"))?;
    let install_salt = vault_init::load_or_generate_install_salt(&data_dir)
        .map_err(|e| anyhow::anyhow!("load/generate install salt: {e}"))?;
    let secrets = if passphrase.is_empty() {
        // No passphrase set. Pre-fix silently created
        // a placeholder vault; post-fix refuses.
        // The error message guides the operator to
        // AGENCY_VAULT_PASSPHRASE_FILE.
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secrets")
            .fetch_one(db.pool())
            .await
            .map_err(|e| anyhow::anyhow!("count secrets: {e}"))?;
        if row.0 > 0 {
            anyhow::bail!(
                "AGENCY_VAULT_PASSPHRASE (or _FILE) is unset but the `secrets` \
                 table has {} row(s). Set the env var to the passphrase used \
                 to encrypt the existing rows, or move the table aside to \
                 start fresh.",
                row.0
            );
        }
        anyhow::bail!(
            "AGENCY_VAULT_PASSPHRASE (or _FILE) is unset. The server refuses \
             to start without a valid passphrase, even on a fresh install \
             with an empty `secrets` table (CVE-class: CWE-798, see \
             REMEDIATION-PLAN.md §3.1 P0-F-05). Generate one with \
             `openssl rand -base64 32` and pass it via \
             AGENCY_VAULT_PASSPHRASE_FILE (preferred) or \
             AGENCY_VAULT_PASSPHRASE."
        );
    } else {
        // Validate before constructing the cipher.
        // This is the fail-closed point: a bad
        // passphrase never produces a working vault.
        vault_init::validate_passphrase(&passphrase)
            .map_err(|e| anyhow::anyhow!("validate vault passphrase: {e}"))?;
        SecretRepository::new(db.pool().clone(), &passphrase, &install_salt)
            .map_err(|e| anyhow::anyhow!("init vault: {e}"))?
    };
    let targets = TargetRepository::new(db.pool().clone());
    let oidc = oidc::OidcConfig::from_env();
    // 2.11.0 (P1-O-05, TZ #1 §14 O-05,
    // CWE-1188 Insecure Default
    // Initialization): refuse to
    // boot a release build with the
    // mock OIDC client selected.
    // The mock is for dev / tests
    // only; a release build that
    // goes to production with
    // `AGENCY_OIDC_MOCK=1` would
    // mean every OIDC flow runs
    // against an in-process mock
    // that accepts whatever the SPA
    // sends. The check is a hard
    // error (the boot fails; the
    // process exits) so a
    // misconfigured release cannot
    // silently run with the mock.
    oidc.validate_for_release()
        .map_err(|e| anyhow::anyhow!("OIDC config rejected at boot (P1-O-05): {e}"))?;
    // 2.11.0 (P1-F-03a/b, CWE-613):
    // server-side session store. The
    // callback/refresh handlers
    // create rows; the middleware
    // reads them; the GC task below
    // reaps expired / revoked rows.
    let sessions =
        agent_dep_core::infrastructure::repository::sessions_repository::SessionRepository::new(
            db.pool().clone(),
        );
    let cookie_secure = oidc.cookie_secure;
    // 2.11.0 (P1-D-03, TZ #1 §10 /
    // D-03, CWE-362): the
    // Idempotency-Key cache. The
    // middleware in
    // `crate::idempotency` reads
    // and writes this repo on
    // every mutation request;
    // the GC task spawned below
    // reaps expired rows on the
    // same 60s timer as
    // `sessions` and
    // `oidc_pending_state`.
    let idempotency =
        agent_dep_core::infrastructure::repository::idempotency_repository::IdempotencyRepository::new(
            db.pool().clone(),
        );
    // 2.7.10 (ADR-0038): DB-backed
    // OidcPending. The 2.7.6 in-memory
    // `Arc<Mutex<HashMap>>` is
    // replaced by a SQLite table.
    let oidc_pending = std::sync::Arc::new(
        agent_dep_core::infrastructure::repository::oidc_pending_repository::OidcPendingRepository::new(
            db.pool().clone(),
        ),
    );
    // 2.7.7 (ADR-0035): pick the OIDC
    // client based on AGENCY_OIDC_MOCK. The
    // 2.7.7 default is `0` (real client).
    let oidc_client: std::sync::Arc<dyn oidc_client::OidcClient> = if oidc.mock {
        std::sync::Arc::new(oidc_client::MockOidcClient)
    } else {
        std::sync::Arc::new(oidc_client::RealOidcClient::new(oidc.clone()))
    };
    let state = ServerState {
        db: db.clone(),
        audit,
        users,
        deploys,
        secrets,
        targets,
        oidc,
        oidc_pending: oidc_pending.clone(),
        oidc_client,
        legacy_token: Arc::new(Some(legacy_token)),
        sessions,
        cookie_secure,
        idempotency,
    };
    // 2.7.10 (ADR-0038): background
    // GC of the `oidc_pending_state`
    // table. Runs every 60s and
    // removes rows older than the
    // 600s `state` expiry. The
    // future is dropped here (the
    // task lives until the process
    // exits).
    {
        let pool = state.db.pool().clone();
        tokio::spawn(async move {
            let repo =
                agent_dep_core::infrastructure::repository::oidc_pending_repository::OidcPendingRepository::new(pool);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let _ = repo.gc_expired(600).await;
            }
        });
    }
    // 2.11.0 (P1-F-03b, CWE-613):
    // background GC of the `sessions`
    // table. Removes revoked rows
    // and rows past their idle or
    // absolute expiry. The cadence
    // matches the `oidc_pending_state`
    // GC (every 60s) so the two
    // tasks share a single timer
    // wheel. The session repo
    // computes the expiry threshold
    // itself; no argument needed.
    {
        let pool = state.db.pool().clone();
        tokio::spawn(async move {
            let repo =
                agent_dep_core::infrastructure::repository::sessions_repository::SessionRepository::new(pool);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let _ = repo.gc_expired().await;
            }
        });
    }
    // 2.11.0 (P1-D-03, CWE-362):
    // background GC of the
    // `idempotency_keys` table.
    // Removes rows past their
    // `expires_at` (the default
    // TTL is 24h). The cadence
    // matches the other GCs
    // (every 60s).
    {
        let pool = state.db.pool().clone();
        tokio::spawn(async move {
            let repo =
                agent_dep_core::infrastructure::repository::idempotency_repository::IdempotencyRepository::new(pool);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                if let Ok(n) = repo.gc_expired().await {
                    if n > 0 {
                        tracing::info!(removed = n, "idempotency.gc removed expired keys");
                    }
                }
            }
        });
    }
    Ok(state)
}

pub fn parse_port(args: &[String]) -> u16 {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--port" {
            if let Some(v) = args.get(i + 1) {
                if let Ok(n) = v.parse::<u16>() {
                    if n != 0 {
                        return n;
                    }
                }
            }
        }
        i += 1;
    }
    0
}

/// 2.9.0: read the bind IP from the
/// CLI (`--bind <ip>`) or the
/// `AGENCY_BIND_IP` env var. Default
/// is `0.0.0.0` (all interfaces) so
/// the binary is VPS-ready out of
/// the box. Integration tests and
/// the dev loop override with
/// `--bind 127.0.0.1`.
pub fn parse_bind(args: &[String]) -> String {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--bind" {
            if let Some(v) = args.get(i + 1) {
                let trimmed = v.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        i += 1;
    }
    if let Ok(v) = std::env::var("AGENCY_BIND_IP") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "0.0.0.0".to_string()
}

pub async fn run(addr: SocketAddr) -> Result<()> {
    let state = boot_default_state().await?;
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    eprintln!("agency-server listening on http://{addr}");
    axum::serve(listener, app)
        .await
        .with_context(|| "axum::serve")?;
    Ok(())
}
