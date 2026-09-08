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
