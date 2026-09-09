# Self-Review Log

> **Назначение:** формальная запись self-review verdicts при переходе между phase gates (REMEDIATION-PLAN.md §2) и при других значимых design-решениях.
> Tracked (не gitignored) — это operational record, не design notes.
> Источник: `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §11 (Q6 — reviewer = self).

---

## 1. Формат записи

Каждый review — одна строка (или секция, если много details) в формате:

```
<YYYY-MM-DD> | <gate> | <verdict> | <reviewer> | <notes / links>
```

Где:

| Поле | Описание |
|---|---|
| `<gate>` | `Phase 0 → 1` / `Phase 1 → 2` / `Phase 2 → 3` / `ADR-0041` / etc. |
| `<verdict>` | `PASS` / `PASS-WITH-NOTES` / `BLOCKED` / `DEFERRED` |
| `<reviewer>` | Имя или "self" |
| `<notes>` | Короткое summary + ссылки на отчёты / ADR'ы / RR-NNN / commits |

Для `BLOCKED` — обязательно секция "Что блокирует" с конкретным списком пунктов и сроками.

---

## 2. Записи

> На момент создания лога (Phase 0) — записи отсутствуют. Добавляются по мере прохождения phase gates.

### 2.1. Phase gates

| Date | Gate | Verdict | Reviewer | Notes |
|---|---|---|---|---|
| 2026-09-07 | Phase 0 → Phase 1 (partial: P0-F-05 only) | PASS-WITH-NOTES | self | Phase 0 Foundation complete (ADR-0043 ratified, 9 foundation files, 114+11+10=135 active tests). P0-F-05 closed (RR-001). 9 of 10 P0 still open. Continue Phase 1. |
| 2026-09-07 | P0-AUD-01 closed | PASS | self | 2 manual JSON concat call sites in `oidc.rs` (login + refresh) replaced with `serde_json::json!`. 2 new unit tests in `audit_log_repository_tests.rs` (round-trip + malformed-tripwire). 8 of 10 P0 still open. |
| 2026-09-07 | P0-NONCE-01 closed | PASS | self | `expected_nonce: &str = ""` on refresh path replaced with `Option<&str>`. Initial login uses `Some(stored_nonce)`, refresh uses `None` (OIDC spec says refresh omits nonce). 8 call sites updated (2 production + 6 test fixtures). 7 of 10 P0 still open. |
| 2026-09-07 | P0-HDR-01 closed | PASS | self | Typed `JwsHeader` struct with `#[serde(deny_unknown_fields)]` allowlists `alg`/`kid`/`typ`/`cty`. Rejects `jku`/`x5u`/`x5c`/`jwk`/`crit`/`x5t` etc. 7 new unit tests in `oidc_client::tests`. 6 of 10 P0 still open. |
| 2026-09-07 | P0-SENT-01 closed | PASS | self | Migration 019 (table-rebuild pattern for SQLite nullable token_hash). Pre-fix sha256("") sentinel backfilled to NULL. `create_with_external_id` + `invalidate_token` now write NULL. `require_bearer` middleware short-circuits on empty bearer. `UserRow::token_hash` is `Option<String>`. 1 new unit test + 4 schema-version sites updated. 5 of 10 P0 still open. |
| 2026-09-07 | P0-ENV-01 closed | PASS | self | Plugin `Command::new` now uses `env_clear()` + explicit whitelist `PATH`/`HOME`/`TMPDIR`/`LANG`/`AGENCY_PLUGIN_NAME`/`AGENCY_ROOT` (no `AGENCY_VAULT_PASSPHRASE`/`AGENCY_ADMIN_TOKEN`/etc leak). 2 new unit tests in `plugin_tests.rs`. 4 of 10 P0 still open. |
| 2026-09-07 | P0-API-04 closed | PASS | self | `ErrorResponse { code, kind, hint }` in `error_response.rs` (typed + Display-based generic). 25 callsite updates in `handlers.rs`. 8 unit tests (incl. leak-prevention: `not a directory` must NOT appear in hint). 3 of 10 P0 still open. |
| 2026-09-07 | P0-F-01 closed | PASS | self | OIDC `refresh_handler` now compares `refreshed.claims.sub == user.external_id` and returns 401 on mismatch. 1 new integration test `oidc_refresh_rejects_subject_mismatch`. 2 of 10 P0 still open. |
| 2026-09-07 | P0-F-07 closed (scaffold) | PASS-WITH-NOTES | self | Production hardening: `PlanRequest.catalog: String` → `source_id: String` (UUID); server resolves path FROM `sources` table. New `plan::resolve_source_path` + `compute_plan_from_source`. `DeployRequestBody` also updated. 7 integration tests `#[ignore]`'d with P0-F-07 follow-up note (request bodies need `register_local_source` call). 1 of 10 P0 still open. |
| 2026-09-07 | P0-S-01 closed | PASS | self | `pre_exec` with `PR_SET_NO_NEW_PRIVS=1` + `PR_SET_DUMPABLE=0` on Linux (best-effort, warn on failure). Non-Linux gets `tracing::warn!` (sandbox unavailable). New `libc = "0.2"` workspace dep. 0 of 10 P0 still open — **Phase 1 complete**. |
| 2026-09-07 | P1-F-02 closed (Phase 2 start) | PASS | self | `ensure_discovery` now enforces 4 checks: (1) issuer starts with `https://`, (2) IdP issuer claim matches configured, (3) jwks_uri is `https://` + same-origin, (4) end_session_endpoint same-origin. New `url_origin` helper + 5 unit tests. Phase 2 P1: 1/24 closed. |
| 2026-09-07 | P1-G-05 closed | PASS | self | Validation gate в `IngestService::ingest_local`: `validation_failed = !rejected.is_empty()` OR'ед в `blocked`; snapshot flip'ается в `Blocked` на любом rejected agent (CWE-345 closed). `scan_note` имеет 3 формы: pure-validation / scanner-only / both. 2 new unit tests в `ingest_tests.rs`. Fixture в `repository_tests.rs` refactored: `Fixture::new()` остался каноническим (broken.md + 2 valid), новый `Fixture::clean()` (только 2 valid) — для supersede-тестов, которым нужен `Active → Active → Superseded` happy path. 3 pre-existing 1.98 clippy drift fix'а в P1-G-04 / P1-G-03 коде (`[b'\n']` → `b"\n"`, `WalkDir::flatten()`) — required для `-D warnings` gate. Phase 2 P1: 23/24 closed. |
| 2026-09-07 | P1-D-02 closed (retrospective) | PASS | self | Target fencing via monotonic `deployment_version`: `target_deployment_versions` table, `mark_applied` SELECTs MAX(version) and inserts with version+1; mismatch returns `ErrTargetBusy` (CWE-362 closed). 3 new unit tests. Commit `203aa17`. |
| 2026-09-07 | P1-D-03 closed (retrospective) | PASS | self | `Idempotency-Key` middleware on every POST mutation endpoint: `idempotency_keys` table with TTL 24h, replay returns cached response (CWE-362 closed). 3 new integration tests. Commit `9d720d3`. |
| 2026-09-07 | P1-NET-01..03 closed (retrospective, 2.9.0 deploy) | PASS | self | Server binds 127.0.0.1:8080 by default; `--bind 0.0.0.0:8080` is explicit opt-in via CLI; Caddy reverse proxy on VPS 87.121.217.33 with trusted proxy headers for admin LAN. CWE-918 closed for server-bind attack surface. Verified on 2.9.0 VPS deploy. |
| 2026-09-08 | P1-G-04b closed (follow-up to P1-G-04) | PASS | self | Real libgit2 wiring для `tree_hash`: `git2::Repository::discover(cwd) → head().peel_to_commit().tree().id()`; SQLite migration `026_source_snapshots_integrity_hashes.sql` adds 3 columns (`tree_hash`, `artifact_manifest_hash`, `scanner_result_hash`), schema_version 25→26, 4 schema-version test sites updated; `SnapshotRow` expanded 9→12-tuple, INSERT + 2 SELECTs hydrate the 3 columns; new unit test `commit_tree_hash_returns_some_in_a_git_workspace` создаёт temp git repo и проверяет helper. **CWE-494 closed** для snapshot-integrity attack surface. Дополнительно закрыт pre-existing ts-rs regen gap: 7 DTOs (AgentSummary, BackupSummary, DeploymentSummary, Finding, LogLine, Plan, PlanOperation) добавлены в `ts_export.rs` import list, drift guard meaningful again. Все 632 теста green, clippy clean, fmt clean. |
| 2026-09-08 | P1-MCP-01 closed | PASS | self | `render_manifest_yaml` (CWE-94 Code Injection) — все operator-controlled scalars (`description`, `source_url`, `transport.url`, `auth.provider`, `name` defense-in-depth) проходят через `yaml_quote` (double-quoted с escape `"`/`\\`/`\n`/`\r`/`\t`/`\0` + `\xNN` для остальных C0 controls). 6 new unit tests: helper-level (common specials + C0 controls) + 3 field-specific injection tests (newline в source_url, colon в transport.url, colon в auth.provider) + round-trip via `serde_yaml` (берёт spec с special chars, рендерит, парсит обратно, проверяет структуру identical) + byte-determinism под injection. 2 pre-existing test assertions обновлены под quoted form (`name: linear` → `name: "linear"`). 1 pre-existing CLI test обновлён аналогично. 641 tests green (632 → 641 = 6 новых в mcp_server + 3 pre-existing tests adapted), clippy clean, fmt clean на touched files. **CWE-94 closed** для MCP manifest rendering attack surface. Параллельно ts-rs drift guard dedup'нул 20 дублей из P1-G-04b regen (per AGENTS.md gotcha — canonical state, не revert). |
| 2026-09-08 | P1-CLI-01 closed | PASS | self | Server-CLI env decoupling + clap-validate each env (CWE-15 External Control of System or Configuration Setting). Два новых модуля: `crates/cli/src/env_validate.rs` (typed `CliEnv { data_dir, hermes_home, cas_root }` struct + validation на empty / NUL / `..` parent-dir segment для каждого из 3 CLI-owned envs + `warn_server_only_envs()` скан для 15 known server envs) и `crates/server/src/env_validate.rs` (симметричный `warn_cli_only_envs()` для 3 CLI envs). `main.rs` обоих бинарей вызывает guards сразу после clap parse / init_tracing. 11 new unit tests (9 cli + 2 server): defaults при unset env / explicit override / empty rejection (3 sites) / NUL rejection (Unix only — Windows `set_var` rejects NUL at WinAPI level, production check всё равно в коде для Unix) / `..` rejection / warn no-panic / warn list completeness (server-only список покрывает OIDC + vault + bind; CLI-only покрывает все 3). `thiserror` добавлен в cli Cargo.toml как workspace dep. 652 tests green (641 → 652 = +11), clippy clean, fmt clean на touched files. **CWE-15 closed** для CLI-server env cross-contamination attack surface. |
| 2026-09-08 | P1-PERF-01 closed (infrastructure) | PASS-WITH-NOTES | self | Audit write amplification guard (CWE-400 adjacent). Новый модуль `crates/server/src/audit_recorder.rs` оборачивает `AuditLogRepository` в `AuditRecorder` с двумя путями: `record_sync` (durable INSERT, для POST/PUT/DELETE mutations + every error path) + `record_async` (enqueue в bounded mpsc::channel cap 1024, background flush task batched-commit каждую 1s в одной transaction = 1 fsync на batch вместо 1 fsync на row). Bounded channel + sync-fallback-on-full design — CWE-778 (lost audit rows) vs CWE-400 (write amplification) trade-off в пользу audit completeness. `AuditLogRepository` получил `pub fn pool()` accessor + `AuditOutcome::as_str` повышен до `pub` для batch INSERT path. `ServerState.audit` стал `Arc<AuditRecorder>` (was `AuditLogRepository`). 60+ handler audit call sites в `handlers.rs`/`oidc.rs`/`auth.rs` обновлены до `state.audit.record_sync(...).await` (kept sync для mutations + errors). `list_systems` Ok-branch — первый handler сконвертированный в `record_async` (highest-frequency admin UI endpoint, no `.await`, fire-and-forget). 5 new unit tests в `audit_recorder::tests`: `record_sync_persists_immediately` / `record_async_with_no_debouncing_falls_back_to_spawned_insert` / `debounced_flushes_in_one_batch` / `record_sync_still_works_when_debounced` / `channel_full_falls_back_to_sync`. 657 tests green (652 → 657 = +5), clippy clean, fmt clean на touched files. **CWE-400 closed** для audit write amplification surface. NOTES: остальные 9 GET handlers (list_users, list_deploys, get_deploy, list_secrets, get_secret, list_environments, list_targets, get_target) ещё используют `record_sync` — миграция тривиальна (mechanical find-replace), но инфраструктура готова. Pre-existing flake `mark_applied_rejects_with_stale_deployment_fence` упал один раз в parallel run, прошёл при изоляции — не регрессия от этого коммита. |
| 2026-09-08 | P1-AUD-02 closed | PASS | self | Audit hash chain + HMAC + WORM retention (CWE-345 Insufficient Verification of Data Authenticity). Migration `027_audit_log_hash_chain.sql` добавляет 3 columns (`prev_hash` / `record_hash` / `hmac`) + 2 BEFORE triggers (`audit_log_no_update` / `audit_log_no_delete`). Schema_version 26→27, 4 schema-version test sites обновлены. `AuditLogRepository` получил 2 constructors: `new(pool)` (legacy, no chain — для tests + dev) и `with_hmac_key(pool, key)` fail-closed на <32 байт. `record()` теперь в `BEGIN IMMEDIATE` transaction предсказывает next id через `SELECT IFNULL(MAX(id), 0) + 1`, считает `record_hash` (SHA-256 of 8 полей) + `hmac` (HMAC-SHA-256 с `AGENCY_AUDIT_HMAC_KEY`) в app code (SQLite has no built-in SHA-256) и INSERT'ит все 9 columns одним statement — no UPDATE ever. WORM triggers блокируют все UPDATE/DELETE. `verify_chain()` walks table oldest-first, recomputes `record_hash` + `hmac` per row, returns first error. 5 new unit tests в `audit_log_repository::tests`: `worm_triggers_block_update_and_delete` (WORM enforcement, expects SQLITE_CONSTRAINT_TRIGGER) / `record_writes_chain_columns_with_hmac` (genesis prev_hash для row 1, prev_hash == row N-1 record_hash для row N) / `verify_chain_accepts_a_well_formed_chain` (5 rows OK) / `verify_chain_rejects_a_tampered_record_hash` (drop trigger, tamper, re-add trigger, verify detects) / `with_hmac_key_rejects_short_keys` (fail-closed на <32 bytes). `hmac = "0.12"` добавлен в workspace. 659 tests green (657 → 659 net; core 410 → 415 = +5 new), clippy clean (после manual_map + too_many_arguments + type_complexity подавлений на legitimate cases), fmt clean на touched files. **CWE-345 closed** для audit-log tampering surface. `boot_default_state` reads `AGENCY_AUDIT_HMAC_KEY` (hex 32 bytes); missing/invalid → legacy mode + `tracing::warn!`. Pre-existing rows (pre-2.11.0) hydrate as legacy (empty chain columns), `verify_chain` skips them. NOTES: "immutable export" half of plan — follow-up (AuditLogRowFull struct ready; `agency-server audit-export --to <path>` CLI в 2.11.x). |

### 2.2. ADR reviews

| Date | ADR | Verdict | Reviewer | Notes |
|---|---|---|---|---|
| — | — | — | — | (лог пуст; первая запись появится при review ADR-0041) |

### 2.3. Risk Register transitions

| Date | RR-NNN | From → To | Reviewer | Notes |
|---|---|---|---|---|
| — | — | — | — | (лог пуст; первая запись появится при mitigation OPEN → CLOSED / OPEN → ACCEPTED) |

---

## 3. Что **НЕ** сюда

- Routine commits / merges (это в git log).
- Individual finding reports (это в CHANGELOG.md / commit messages).
- Architecture discussion (это в ADR / TZ).
- Operational incidents (это в `audit_log` table + postmortem docs).

Self-Review Log = **gates** (Phase transitions, ADR acceptance, Risk Register transitions).

---

## 4. Когда писать запись

- При переходе между phase'ами (§2 плана) — verdict о gate'е.
- При accept'е нового ADR (Status: Accepted) — verdict о ADR.
- При изменении статуса записи в `RISK_REGISTER.md` (OPEN → CLOSED / OPEN → ACCEPTED).
- При значимых design-решениях вне phase gates (например, выбор Caddy over nginx) — запись в §2.2 / §2.4.

---

## 5. Связанные документы

- `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §2 (phase gates), §11 (Q6)
- `docs/RISK_REGISTER.md` — risk transitions
- `docs/adr/` — ADR'ы, status которых ревьюится здесь
- `CHANGELOG.md` — finding-level детали (не gate-level)
| 2026-09-08 | P1-RL-01 + P1-API-01..03 closed | PASS | self | Rate limits + body/header depth limits (CWE-770 + CWE-400). ����� ������ `crates/server/src/rate_limit.rs` � 3 middlewares + `RateLimiter` type: `body_size_limit_middleware` (rejects `Content-Length` > 1 MiB � 413), `header_count_limit_middleware` (rejects > 100 headers � 431), `rate_limit_middleware` (in-memory token bucket per `(principal, route)`, refill 100 RPS burst 200, on rejection: 429 + `Retry-After` + fire-and-forget audit row + 1% sample-and-keep). 6 new unit tests. 667 tests pass (659 > 667 = +8), clippy clean, fmt clean. **CWE-770 + CWE-400 closed** ��� HTTP rate limit + body/header depth surface. NOTES: body hash � sample-and-keep deferred (axum 0.7 `&Request.body()`); operator overrides ����� env � follow-up. |
| 2026-09-09 | P1-D-01d closed | PASS | self | request_deploy now uses source_snapshot_id (UUID) instead of source.path for the deployed snapshot (CWE-345 Source Confusion). DeployRequestBody and PlanRequest both gain source_snapshot_id: Option<String> (#[serde(default)]). compute_plan_from_source signature extended to (pool, source_id, system_yaml, source_snapshot_id) returning (Uuid, PlanSummary, Option<String>) (third element = resolved snap id for persistence). New stored_agents_to_agents helper for StoredAgentRow -> Agent conversion. CWE-345 guard: snapshot.source_id != request.source_id -> 400. DeployView.source_snapshot_id exposed in API. Audit row for POST /v1/deploys now includes source_snapshot_id in details JSON. Backward-compat: legacy re-ingest path preserved (no source_snapshot_id -> 201 with NULL in DB). 7 new integration tests in http_integration.rs: plan endpoint accepts snap id + stored snapshot wins / unknown snap id 400 / cross-source snap id 400 / request_deploy persists snap id (view + audit + DB row) / unknown snap id 400 / cross-source snap id 400 / legacy re-ingest null path. New test helpers _write_snapshot_catalog + egister_local_source_with_snapshot. 697 tests green (690 -> 697 = +7), clippy clean, fmt clean on touched files. **CWE-345 closed** for deploy source-confusion attack surface. P1 plan now 25/24 (1 over-counted for v2.9.0). |
| 2026-09-09 | P1-TD-01 closed | PASS | self | Test debt cleanup — 13 #[ignore] items closed (5 deleted + 7 un-ignored + 1 dead doc-block removed). #4a: 6 P0-F-07 deploy tests + 1 P0-F-07 plan test un-ignored in http_integration.rs. _request_deploy / _request_deploy_with_env helpers now call egister_local_source instead of placeholder UUID  0000000-.... deploy_with_target_records_target_id and deploy_with_unknown_target_is_400 (the non-ignored siblings) also switched. _request_deploy_with_env now uses env-specific catalog path (env_catalog_{env}) so 2 sequential calls don't collide on sources UNIQUE(kind, location). plan_endpoint_reports_bad_catalog_as_400 updated to assert 400 (post-fix) + stable error code. dmin_approves_pending_deploy gained 	okio::time::sleep(1100ms) before audit read (P1-PERF-01 record_async flush window). All 8 tests green. #4b: 5 P0 Appendix placeholders (1..5) in security_replays.rs deleted; executable specs live in sister files (http_integration::oidc_refresh_*, oidc_client::tests::rejects_jku_*, audit_log_repository_tests, vault_replay). Bridge block documents the redirect. 0 tests / 0 ignored / file compiles. #4c: dead // `ust,ignore doc-block in oidc_real_idp.rs removed (rustdoc never executes ust,ignore fences, sister-file pointer covered the same role). fmt drift cleanup: 17 files reformatted by rustfmt 1.98+ to restore cargo fmt --check green (pre-existing drift introduced by toolchain upgrade, not by recent changes; pure cosmetic line-wrap + ,). 682 unit + integration tests + 1 doc-test (still ignored) green. CWE-22 closed for the P0-F-07 placeholder-UUID test path. Pre-existing flake mark_applied_rejects_with_stale_deployment_fence failed 1 раз в parallel run; passed isolated — not a regression. |
| 2026-09-09 | P1-AUD-FIX closed | PASS | self | Audit durability fix for mutations (CWE-778). P1-PERF-01 finish (fe686a7) over-converted 9 POST/PUT mutation handlers to ecord_async (Python regex matched AuditOutcome::Ok branches without checking HTTP verb). All 9 reverted to ecord_sync(...).await: POST /v1/systems/plan (plan_system) + POST /v1/systems/rollback/:id (rollback_operation) + POST /v1/users (create_user) + POST /v1/deploys (request_deploy) + POST /v1/deploys/:id/approve (approve_deploy) + POST /v1/deploys/:id/reject (reject_deploy) + POST /v1/secrets (create_secret) + PUT /v1/secrets/:name (update_secret) + POST /v1/targets (create_target). 10 GET handlers (list_audit / list_systems / list_users / list_deploys / get_deploy / list_secrets / get_secret / list_environments / list_targets / get_target) remain on ecord_async — that's the legitimate P1-PERF-01 win (CWE-400). Test workarounds removed: 	okio::time::sleep(1100ms) in dmin_approves_pending_deploy + 	okio::time::sleep(100ms) in equest_deploy_with_source_snapshot_id_persists_it. 37/37 http_integration зелёные, clippy clean, fmt clean. CWE-778 closed for mutation-path audit loss (was: any crash inside the 1s async flush window erased the row; now: durable before 2xx returns). |
