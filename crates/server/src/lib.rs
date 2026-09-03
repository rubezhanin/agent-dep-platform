//! Library surface for the `agency-server` crate.
//!
//! 2.1.0: integration tests link against this lib to
//! bind a real `axum` router on a random port. The
//! `main.rs` binary is a thin wrapper that constructs
//! the production `ServerState` and calls `axum::serve`.

pub mod auth;
pub mod catalog;
pub mod handlers;
pub mod oidc;
pub mod oidc_client;
pub mod plan;
pub mod state;

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
            auth::require_bearer,
        ));
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
        // a fresh token. Print the token to stderr
        // exactly once so the operator can copy it.
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
            "agency-server: created initial admin user, token in {}",
            token_path.display()
        );
        eprintln!(
            "agency-server: token={} (save this; the plain token is not stored)",
            token
        );
        token
    };
    let audit = AuditLogRepository::new(db.pool().clone());
    let deploys = PendingDeployRepository::new(db.pool().clone());
    // 2.3.0: vault passphrase comes from
    // `AGENCY_VAULT_PASSPHRASE`. If the `secrets`
    // table is non-empty and the env var is unset,
    // we refuse to start.
    let passphrase = std::env::var("AGENCY_VAULT_PASSPHRASE").unwrap_or_default();
    let secrets = if passphrase.is_empty() {
        let count_placeholder = PendingDeployRepository::new(db.pool().clone());
        // We use a temporary repo to count — but
        // actually we need to check the count
        // before constructing the vault, because
        // the vault constructor requires a
        // non-empty passphrase. Drop the
        // placeholder and check directly.
        drop(count_placeholder);
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secrets")
            .fetch_one(db.pool())
            .await
            .map_err(|e| anyhow::anyhow!("count secrets: {e}"))?;
        if row.0 > 0 {
            anyhow::bail!(
                "AGENCY_VAULT_PASSPHRASE is unset but the `secrets` table has {} row(s). \
                 Set the env var to the passphrase used to encrypt the existing rows, \
                 or move the table aside to start fresh.",
                row.0
            );
        }
        // No secrets yet — build a placeholder
        // vault with a temporary passphrase. The
        // operator can rotate later by re-creating
        // rows. The placeholder is NOT secure
        // against a leaked memory dump.
        SecretRepository::new(db.pool().clone(), "unset-rotate-before-first-use")
            .map_err(|e| anyhow::anyhow!("init placeholder vault: {e}"))?
    } else {
        SecretRepository::new(db.pool().clone(), &passphrase)
            .map_err(|e| anyhow::anyhow!("init vault: {e}"))?
    };
    let targets = TargetRepository::new(db.pool().clone());
    let oidc = oidc::OidcConfig::from_env();
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
    let oidc_client: std::sync::Arc<dyn oidc_client::OidcClient> =
        if oidc.mock {
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
