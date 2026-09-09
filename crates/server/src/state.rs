//! Shared application state for the 2.1.0 server.

use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use agent_dep_core::infrastructure::repository::idempotency_repository::IdempotencyRepository;
use agent_dep_core::infrastructure::repository::oidc_pending_repository::OidcPendingRepository;
use agent_dep_core::infrastructure::repository::pending_deploys_repository::PendingDeployRepository;
use agent_dep_core::infrastructure::repository::secrets_repository::SecretRepository;
use agent_dep_core::infrastructure::repository::sessions_repository::SessionRepository;
use agent_dep_core::infrastructure::repository::targets_repository::TargetRepository;
use agent_dep_core::infrastructure::repository::users_repository::UserRepository;
use agent_dep_core::infrastructure::sqlite::Db;

use crate::audit_recorder::AuditRecorder;
use crate::oidc::OidcConfig;
use crate::oidc_client::OidcClient;
use crate::rate_limit::RateLimiter;

#[derive(Clone)]
pub struct ServerState {
    pub db: Db,
    /// 2.11.0 (P1-PERF-01, TZ #1 §19):
    /// two-tier audit recorder. Successful
    /// GETs go through `record_async`
    /// (batched, one fsync per batch); POST /
    /// PUT / DELETE and every error path go
    /// through `record_sync` (one fsync per
    /// row, durable). The `Arc<AuditRecorder>`
    /// is `Clone`-cheap so handlers can take
    /// a reference without owning a mutable
    /// borrow.
    pub audit: Arc<AuditRecorder>,
    /// 2.1.0: per-user lookup. The 2.0.0 single-token
    /// field is gone — the `users` table is the only
    /// source of truth.
    pub users: UserRepository,
    /// 2.2.0: approvals workflow state machine.
    pub deploys: PendingDeployRepository,
    /// 2.3.0: encrypted secret store.
    pub secrets: SecretRepository,
    /// 2.5.0: fleet — named target registry.
    pub targets: TargetRepository,
    /// 2.7.6 (ADR-0034): OIDC config. When
    /// `is_enabled()` is false, the OIDC endpoints
    /// return 503 "not configured". Bearer-token
    /// auth is unaffected.
    pub oidc: OidcConfig,
    /// 2.7.10 (ADR-0038): DB-backed
    /// `OidcPending` repository. The
    /// 2.7.6 in-memory
    /// `Arc<Mutex<HashMap<String,
    /// PendingAuth>>>` is replaced by
    /// a SQLite table so multi-process
    /// / multi-instance
    /// `agency-server` deployments
    /// can hand the callback request
    /// off to a different replica than
    /// the one that handled
    /// `/v1/auth/oidc/login`.
    pub oidc_pending: Arc<OidcPendingRepository>,
    /// 2.7.7 (ADR-0035): the OIDC wire-protocol
    /// client. `MockOidcClient` when
    /// `AGENCY_OIDC_MOCK=1`; `RealOidcClient`
    /// otherwise. The 2.7.7 default is
    /// `AGENCY_OIDC_MOCK=0` (real client) — a
    /// behavioural break from 2.7.6's
    /// `AGENCY_OIDC_MOCK=1` default.
    pub oidc_client: Arc<dyn OidcClient>,
    /// Retained for 2.0.0→2.1.0 migration: if the
    /// `users` table is empty on first start and this
    /// is `Some(legacy)`, the server creates an
    /// `admin` user with `token_hash = sha256(legacy)`
    /// so existing scripts keep working.
    pub legacy_token: Arc<Option<String>>,
    /// 2.11.0 (P1-F-03b, CWE-613): server-side
    /// session store. The `require_session_or_bearer`
    /// middleware reads the `agency_session` cookie
    /// and looks it up here; the OIDC handlers
    /// (`callback`, `refresh`, `logout`) create /
    /// rotate / revoke sessions through this
    /// repository.
    pub sessions: SessionRepository,
    /// 2.11.0 (P1-F-03b, CWE-613): the `Secure`
    /// flag for the `Set-Cookie` header. `true`
    /// in production (HTTPS); `false` only in
    /// dev / integration tests over plain HTTP
    /// localhost. Configured via
    /// `AGENCY_COOKIE_SECURE` (default `true`).
    pub cookie_secure: bool,
    /// 2.11.0 (P1-D-03, TZ #1 §10 / D-03,
    /// CWE-362): the `Idempotency-Key` cache.
    /// Every mutation endpoint is wrapped by
    /// `idempotency_middleware`, which looks
    /// up `(key, route)` here and either
    /// replays the cached response or runs
    /// the handler and stores its result. A
    /// GC task (spawned in `lib::boot_default_state`)
    /// reaps expired rows on the same 60s
    /// timer as `sessions` and
    /// `oidc_pending_state`.
    pub idempotency: IdempotencyRepository,
    /// 2.11.0 (P1-RL-01): in-memory token
    /// bucket per `(principal, route)`. The
    /// `Arc` keeps the middleware's lookup
    /// path lock-free for the common case
    /// (a hit on an existing key is a
    /// `HashMap::entry` + `Bucket::try_consume`,
    /// both of which are O(1)).
    pub rate_limiter: Arc<RateLimiter>,
    /// 2.11.0 (P1-API-03): maximum request
    /// body size in bytes. The
    /// `body_size_limit_middleware` reads
    /// this on every request; using
    /// `AtomicU32` instead of `usize`
    /// (a) keeps the `Clone` cheap for the
    /// `ServerState`, and (b) lets an
    /// operator hot-reload the limit by
    /// calling `ServerState::set_max_body_bytes`
    /// from a signal handler (a follow-up;
    /// not in this commit).
    pub max_body_bytes: Arc<AtomicU32>,
    /// 2.11.0 (P1-API-03): maximum request
    /// header count.
    pub max_header_count: Arc<AtomicU32>,
}
