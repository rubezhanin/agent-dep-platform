# 3.0.0 API Freeze — Public Surface of the 2.x Line

> **Назначение:** этот документ фиксирует
> **public API surface** `agency-server` +
> `agency` CLI + `agent-dep-platform`
> crates по состоянию на 2.11.0. После
> 3.0.0 любое изменение сигнатур,
> типов, формата JSON, HTTP кодов,
> HTTP заголовков, env vars или CLI
> флагов считается **breaking change** и
> требует major version bump + migration
> guide.
>
> Frozen on 2.11.0 (2026-09-09).
> Source: `git tag 2.11.0` will be the
> last commit that mutates this surface
> in a backward-compatible way.

---

## 1. HTTP API surface (`agency-server`)

### 1.1 Routes (2.11.0 final)

| Method | Path | Auth | Role | Status |
|---|---|---|---|---|
| `GET` | `/v1/health` | none | — | 200 `{status: "ok"}` |
| `GET` | `/v1/audit` | session or bearer | viewer | 200 `{items, next_cursor}` |
| `GET` | `/v1/audit/stats` | session or bearer | **admin** | 200 `AuditRecorderStats` |
| `GET` | `/v1/users` | session or bearer | viewer | 200 `UserView[]` |
| `POST` | `/v1/users` | session | **admin** | 201 `UserView` |
| `DELETE` | `/v1/users/:id` | session | **admin** | 204 |
| `POST` | `/v1/users/:id/rotate` | session | **admin** | 200 `UserView` |
| `GET` | `/v1/systems` | session or bearer | viewer | 200 `System[]` |
| `POST` | `/v1/systems/plan` | session | operator | 200 `PlanSummary` |
| `POST` | `/v1/rollback/:id` | session | operator | 200 `RollbackSummary` |
| `GET` | `/v1/deploys` | session or bearer | viewer | 200 `DeployView[]` |
| `GET` | `/v1/deploys/:id` | session or bearer | viewer | 200 `DeployView` |
| `POST` | `/v1/deploys` | session | operator | 201 `DeployView` |
| `POST` | `/v1/deploys/:id/approve` | session | **admin** | 200 `DeployView` |
| `POST` | `/v1/deploys/:id/reject` | session | **admin** | 200 `DeployView` |
| `GET` | `/v1/environments` | session or bearer | viewer | 200 `string[]` |
| `GET` | `/v1/secrets` | session or bearer | viewer | 200 `Secret[]` (no `value` field) |
| `POST` | `/v1/secrets/:name/reveal` | session | **admin** | 200 `{name, value}` (no-cache) |
| `POST` | `/v1/secrets` | session | **admin** | 201 `Secret` |
| `PUT` | `/v1/secrets/:name` | session | **admin** | 200 `Secret` |
| `DELETE` | `/v1/secrets/:name` | session | **admin** | 204 |
| `GET` | `/v1/targets` | session or bearer | viewer | 200 `Target[]` |
| `GET` | `/v1/targets/:id` | session or bearer | viewer | 200 `Target` |
| `POST` | `/v1/targets` | session | **admin** | 201 `Target` |
| `DELETE` | `/v1/targets/:id` | session | **admin** | 204 |
| `GET` | `/v1/auth/oidc/login` | none | — | 302 redirect to IdP |
| `GET` | `/v1/auth/oidc/callback` | none | — | 200 `{token, user, expires_at, csrf_token, refresh_token?}` + Set-Cookie |
| `POST` | `/v1/auth/oidc/refresh` | none | — | 200 `RefreshResponse` (with new `csrf_token` since 2.10.0) + Set-Cookie |
| `POST` | `/v1/auth/oidc/logout` | none | — | 200 + Clear-Cookie |

### 1.2 Headers

**Requests:**
- `Authorization: Bearer <token>` —
  legacy, deprecated in 2.11.0,
  removed in 2.12.0. **Do not use in
  new code.** Existing clients
  using bearer get a 401 unless
  `AGENCY_BEARER_FALLBACK=1` is set
  in 2.11.0; in 2.12.0 always 401.
- `Cookie: agency_session=<sid>` —
  primary auth mechanism in 2.7.6+.
- `X-CSRF-Token: <csrf_token>` —
  required on POST/PUT/DELETE when
  using session-cookie auth. Get the
  token from `csrf_token` field of
  the OIDC callback / refresh
  response.
- `Content-Type: application/json`
  on bodies.
- `Idempotency-Key: <uuid>` —
  optional, 24h TTL, replays the
  cached response (2.11.0 P1-D-03).

**Responses:**
- `Cache-Control: no-store, no-cache,
  must-revalidate, private` —
  on `POST /v1/secrets/:name/reveal`
  responses (2.10.0 B3).
- `Pragma: no-cache` + `Expires: 0` —
  on `POST /v1/secrets/:name/reveal`
  responses (2.10.0 B3).
- `Set-Cookie: agency_session=<sid>;
  HttpOnly; SameSite=Strict; Path=/`
  — on OIDC callback / refresh.
- `Clear-Cookie: agency_session=...`
  — on OIDC logout.

### 1.3 Error response shape

```json
{
  "code": "schema.invalid",
  "kind": "client",
  "hint": "request body must include non-empty `reason`"
}
```

| `code` | HTTP | When |
|---|---|---|
| `schema.gone` | 410 | GET /v1/secrets/:name (B3) |
| `csrf.mismatch` | 403 | POST/PUT/DELETE without `X-CSRF-Token` (B2) |
| `schema.invalid` | 400 | Bad request body |
| `internal.io` | 500 | DB error |
| `internal.untyped` | 500 | Other unhandled error |

### 1.4 Auth contract

- `agency_session` cookie is the
  primary mechanism. The session
  row carries a `csrf_token` (32
  random bytes hex-encoded). Mutations
  (POST/PUT/DELETE/PATCH) MUST include
  `X-CSRF-Token: <session.csrf_token>`
  (constant-time compare).
- Bearer is removed in 2.12.0.

---

## 2. CLI surface (`agency`)

### 2.1 Top-level subcommands (2.11.0 final)

| Command | Purpose | Status |
|---|---|---|
| `agency status` | Show deployment status | stable |
| `agency catalog update <path>` | Ingest local catalog | stable |
| `agency catalog add <url>` | Ingest remote catalog | stable |
| `agency catalog scan ...` | Scan a directory for agents | stable |
| `agency system plan ...` | Compose + plan a system | stable |
| `agency deploy ...` | Apply a system to a target | stable |
| `agency lock ...` | Inspect / generate `agency.lock` | stable |
| `agency mcp install / list / remove` | Install/inspect/remove MCP servers | stable |
| `agency hermes probe` | Probe a Flow A router plugin | stable |
| `agency completion <shell>` | Generate shell completion script | stable |
| **`agency health --url <url>`** | HTTP probe for `GET /v1/health` | **new in 2.10.0 (D1)** |
| `agency serve` | Run the embedded server (dev only) | deprecated (use `agency-server` binary) |

### 2.2 Global flags

- `--help` / `-h`
- `--version` / `-V`
- `AGENCY_DATA_DIR` env (CLI-only)
- `AGENCY_HERMES_HOME` env (CLI-only)
- `AGENCY_CAS_ROOT` env (CLI-only)

### 2.3 Exit codes

| Code | When |
|---|---|
| 0 | Success |
| 1 | Generic error |
| 2 | Bad CLI usage (clap error) |
| 1 (from `agency health`) | Health probe failed (timeout / non-2xx / missing `status: "ok"`) |

---

## 3. `agency-server` binary

### 3.1 Flags (2.10.0 A6)

- `--bind <IP>` — IP to bind.
  Default `0.0.0.0`. Env
  `AGENCY_BIND_IP`.
- `--port <PORT>` — TCP port.
  Default `8080`.
- `--help` / `--version`.

### 3.2 Env vars (2.11.0 final)

| Var | Default | Effect |
|---|---|---|
| `AGENCY_BIND_IP` | `0.0.0.0` | Bind IP (overridden by `--bind`) |
| `AGENCY_VAULT_PASSPHRASE` | required | Vault master passphrase |
| `AGENCY_VAULT_PASSPHRASE_FILE` | none | Alt: path to passphrase file (preferred) |
| `AGENCY_AUDIT_HMAC_KEY` | none | Hex 32+ bytes. Required for tamper-evident audit log. Missing → legacy mode + `tracing::warn!` |
| `AGENCY_BEARER_FALLBACK` | `0` | `1`/`true`/`yes`/`on` re-enables pre-OIDC bearer (REMOVED in 2.12.0) |
| `AGENCY_OIDC_*` | various | OIDC config (issuer, client_id, client_secret, jwks_url, redirect_uri) |
| `AGENCY_RUST_LOG` | `info,sqlx=warn` | tracing-subscriber filter |

---

## 4. Library surface (`agent-dep-core`, `agent-dep-server`)

### 4.1 `agent-dep-core` public modules (not exhaustive)

- `application::ingest::IngestService`
- `application::scanner::trust_store::TrustStore`
- `application::policy::Policy`
- `domain::agent::Agent`
- `domain::agent_yaml::parse_agent_yaml`
- `domain::skill_yaml::parse_skill_yaml`
- `domain::system::SystemFile`
- `domain::lock::LockFile`
- `domain::version::Version`
- `infrastructure::repository::audit_log_repository::AuditLogRepository`
- `infrastructure::repository::secrets_repository::SecretRepository`
- `infrastructure::repository::users_repository::UserRepository`
- `infrastructure::repository::sessions_repository::SessionRepository`
- `infrastructure::repository::targets_repository::TargetRepository`
- `infrastructure::repository::pending_deploys_repository::PendingDeployRepository`
- `infrastructure::repository::ingest_repository::IngestRepository`

### 4.2 `agent-dep-server` public surface

- `ServerArgs { bind: IpAddr, port: u16 }`
  (`clap::Parser`)
- `ServerState` — Arc-shared, cheap-clone
- `auth::CsrfContext`
- `auth::AuthenticatedUser`
- `audit_recorder::AuditRecorder` +
  `AuditRecorderStats`
- `rate_limit::RateLimiter`
- `vault_init::load_passphrase`
- `error_response::ErrorResponse { code, kind, hint }`

### 4.3 Hard breaking-change rules for 3.0.0

1. **No route removal.** Once a route
   is in this list, it stays.
2. **No JSON field removal.** Fields
   become optional (`Option<>`) but
   are not deleted.
3. **No HTTP code change.** A 201
   stays 201, a 410 stays 410.
4. **No auth mechanism removal in
   3.x.** The session-cookie +
   X-CSRF-Token contract is frozen.
5. **No env-var removal.** `AGENCY_*`
   vars are additive; new ones can
   be added, existing ones are not
   renamed.
6. **Migrations are additive.** New
   SQLite migrations append
   columns/tables; they never
   rename or drop.

### 4.4 Soft extension rules (3.0.0 → 3.x)

1. **New routes** are allowed
   (additive).
2. **New optional JSON fields** are
   allowed (additive).
3. **New env vars** are allowed
   (additive).
4. **New CLI subcommands** are
   allowed (additive).
5. **New `agent-dep-core` modules**
   are allowed; existing modules
   follow the breaking-change rules.

---

## 5. Deprecation timeline

| Item | Deprecated in | Removed in | Migration |
|---|---|---|---|
| Bearer auth | 2.7.8 (P1-F-03b) | **2.12.0** | OIDC session-cookie + `X-CSRF-Token` |
| `parse_bind` / `parse_port` | 2.10.0 (A6) | 2.11.0 | `ServerArgs::parse()` |
| `agency serve` subcommand | 2.0.0 | TBD | use `agency-server` binary |
| `serde_yaml` crate | 2.11.0 (B8) | 2.12.0 | `serde_yaml_ng` |
| `Mutex<HashMap>` rate limiter | 2.11.0 (B5) | TBD | `DashMap` (already migrated) |

---

## 6. Test surface (informational, not part of the API contract)

- `cargo test --workspace` — full suite
  (45+ http_integration, 50+ unit
  tests in `agent_dep_core`, etc.)
- `cargo test -p agent_dep_server --test
  http_integration -- --test-threads=1`
  — primary CI gate
- `agency health` exit 0/1 — used
  as Docker healthcheck

---

## 7. Sign-off

- Author: project maintainer
- Date: 2026-09-09
- HEAD: `4ad29cd` (post-2.12.0 commit
  on `main`)
- Status: **FROZEN at 2.11.0 + 2.12.0
  deprecation aids**. 3.0.0 will lock
  this surface.
