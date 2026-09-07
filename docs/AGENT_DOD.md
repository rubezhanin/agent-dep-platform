# Agent Definition of Done (DoD)

> **Назначение:** шаблон + формат отчёта, по которым агент (или человек) **закрывает** finding'и аудита.
> Источник: `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §1.
> Tracked (не gitignored) — это часть dev-process, не design notes.

---

## 1. Definition of Done — 12 обязательных пунктов

Finding считается **CLOSED** только когда выполнены **ВСЕ** 12 пунктов:

| # | Пункт | Как проверить |
|---|---|---|
| 1 | Root cause identified (с CWE) | В отчёте явно `CWE: CWE-NNN` |
| 2 | Production code изменён | `Changed:` секция в отчёте, `file:line` ссылки |
| 3 | Regression test (unit) | Test name → PASS в `cargo test` |
| 4 | Integration / e2e test | Test name → PASS (если архитектурно применимо) |
| 5 | Все существующие тесты зелёные | `cargo test --workspace` → 0 failures |
| 6 | `cargo test --workspace` passed | CI зелёный |
| 7 | `cargo clippy --workspace --all-targets -- -D warnings` | CI зелёный |
| 8 | `cargo fmt --check` | CI зелёный |
| 9 | Ни один security control не ослаблен | Явно в `Security verification:` секции |
| 10 | `CHANGELOG.md` обновлён в `Unreleased` | `git diff CHANGELOG.md` показывает изменение |
| 11 | ADR создан/обновлён (если архитектурно / публичный API) | `ADR: docs/adr/NNNN-...md` ссылка |
| 12 | Status в `REMEDIATION-PLAN.md` §3 → `CLOSED` + residual risk → `docs/RISK_REGISTER.md` | `RR-NNN` ссылка в отчёте |

**Если хотя бы один пункт не выполнен — finding НЕ closed, продолжаем работу.**

---

## 2. Формат отчёта (обязательный)

Каждый finding оформляется **строго** по этому шаблону:

```markdown
## <FINDING-ID> — <title>

CWE:             CWE-<NNN>      (например, CWE-287 — Improper Authentication)
Exploit scenario: <ref>          (TZ #1 §6 §3.1 / TZ #2 WP-N.M / Appendix A.N)
Status:          CLOSED          (было: <prior — OPEN / PARTIAL / etc.>)
Plan ref:        REMEDIATION-PLAN.md §3.<group>, строка <ID>
Date:            YYYY-MM-DD
Author:          <agent or human>

Root cause:
  - <1-3 строки, объясняющие ПОЧЕМУ баг был возможен>

Changed:
  - crates/<crate>/src/<file>.rs:<line> — <что изменено, зачем>
  - crates/<crate>/src/<file>.rs:<line> — <ещё изменение>
  - crates/<crate>/tests/<file>.rs:<line> — <новый test>

Tests:
  - unit:        <test name>                       → PASS
  - integration: <test name>                       → PASS (если есть)
  - replay:      crates/core/tests/security_replays.rs::<name> → PASS
                 (если finding покрывается replay-сценарием)

Security verification:
  - <attack from exploit scenario> → denied (manual или integration test)
  - <control X> — не ослаблен (явная ссылка: "kept, see <file>:<line>")
  - <control Y> — не ослаблен

Residual risk:
  - <явный список, даже если пусто — пиши "none">
  - запись в docs/RISK_REGISTER.md: <RR-NNN> (если residual != none)

Files changed:
  - crates/<crate>/src/<file>.rs
  - crates/<crate>/tests/<file>.rs
  - docs/adr/NNNN-<slug>.md  (если есть)
  - CHANGELOG.md

ADR:         docs/adr/<NNNN>-<slug>.md  (или "none — non-architectural")
CHANGELOG:   updated (Unreleased: "<finding-id> — <title>")
REPLAY:      crates/core/tests/security_replays.rs::<name>  (если применимо)
RR:          RR-<NNN> в docs/RISK_REGISTER.md  (если residual != none)
```

---

## 3. Где живёт отчёт

Отчёт по finding'у **не отдельный файл** — он добавляется в `CHANGELOG.md` в секцию `Unreleased` (для краткого summary) и/или в коммит-сообщение (для подробного). Полный отчёт — в git history (через `git show <sha>`).

Сам finding ID (P0-F-01 и т.п.) — это ключ. По нему ищем:
- В `REMEDIATION-PLAN.md` §3 — описание и Phase assignment
- В `CHANGELOG.md` Unreleased — статус
- В `docs/RISK_REGISTER.md` — residual risk
- В `crates/core/tests/security_replays.rs` — replay-тест
- В git log — отчёт

---

## 4. Категории DoD по типу finding

Не все 12 пунктов одинаково применимы к каждому finding'у:

| Категория | Пункты которые **можно** опустить | Обоснование |
|---|---|---|
| Non-architectural bug (refactor) | ADR | "none — non-architectural" |
| P3 / backlog (не security) | CWE, replay | Только если это security finding |
| Test-only / docs change | (нет пропусков) | Все 12 применимы |
| Config / infra (например, AGENCY_GIT_ALLOWED_HOSTS) | Юнит-тесты | Можно без unit, но integration обязательно |

**Если не уверен — пиши все 12.** Лишний "Security verification" не вредит, недостающий — причина rollback'а на code review.

---

## 5. CWE-каталог (cheat-sheet)

| CWE | Name | Пример finding |
|---|---|---|
| CWE-22 | Path Traversal | F-07, G-01 |
| CWE-79 | Cross-site Scripting | Tauri (out of scope) |
| CWE-94 | Code Injection | MCP-01 (YAML heredoc) |
| CWE-1188 | Insecure Default Initialization | O-05 (mock OIDC) |
| CWE-1357 | Reliance on Insufficiently Trustworthy Component | O-01, SC-* |
| CWE-200 | Exposure of Sensitive Information | ENV-01 (plugin env) |
| CWE-209 | Generation of Error Message Containing Sensitive Information | API-04, ERR-01 |
| CWE-250 | Execution with Unnecessary Privileges | S-01 (plugin sandbox) |
| CWE-287 | Improper Authentication | F-01, F-04, SENT-01, NONCE-01 |
| CWE-295 | Improper Certificate Validation | F-02 (issuer / key) |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | F-06 (Argon2id) |
| CWE-345 | Insufficient Verification of Data Authenticity | HDR-01, AUD-02 |
| CWE-352 | Cross-Site Request Forgery | LOGOUT-01 |
| CWE-362 | Concurrent Execution using Shared Resource | D-02, D-03 |
| CWE-400 | Uncontrolled Resource Consumption | G-03, S-02, S-03, API-* |
| CWE-494 | Download of Code Without Integrity Check | G-04, D-01, S-05 |
| CWE-601 | URL Redirection to Untrusted Site | O-04 |
| CWE-613 | Insufficient Session Expiration | F-03 |
| CWE-770 | Allocation of Resources Without Limits | API-01, RL-01 |
| CWE-798 | Use of Hard-coded Credentials | F-05 (placeholder vault) |
| CWE-918 | Server-Side Request Forgery | G-01, G-02, NET-* |
| CWE-1021 | Improper Restriction of Rendered UI Layers | UI-06 (Tauri CSP) |

---

## 6. Exploit scenario — где брать

- **TZ #1 §6** — F-01, F-02, F-03, F-04, F-05, F-06 (OIDC + vault)
- **TZ #1 §7** — G-01..G-05 (Git policy)
- **TZ #1 §8** — F-07 (path ID)
- **TZ #1 §9** — S-01..S-04 (plugin)
- **TZ #1 §10** — D-01..D-03 (deployment)
- **TZ #1 §16** — AUD-01..AUD-03 (audit)
- **TZ #1 §17** — API-01..API-04 (error format, rate limits, pagination, body size)
- **TZ #1 §27.1** — 23 integration test names (один = один сценарий)
- **TZ #2 Appendix A** — A.1..A.5 (seed-сценарии в `security_replays.rs`)

Если finding не покрыт ни одним из этих — **создать новый** в `docs/RISK_REGISTER.md` с RR-NNN и сослаться.

---

## 7. Чек-лист перед merge

```
[ ] CWE: CWE-XXX (не "n/a" для security finding)
[ ] Exploit scenario: <ref> (не "n/a" для security finding)
[ ] Status: CLOSED
[ ] Root cause: <1-3 строки>
[ ] Changed: file:line ссылки
[ ] Tests: unit / integration / replay (если применимо) → PASS
[ ] Security verification: явный список "не ослаблено"
[ ] Residual risk: "none" ИЛИ RR-NNN в docs/RISK_REGISTER.md
[ ] ADR: <path> ИЛИ "none — non-architectural"
[ ] CHANGELOG.md: обновлён в Unreleased
[ ] REMEDIATION-PLAN.md §3: status → CLOSED
[ ] cargo test --workspace: 0 failures
[ ] cargo clippy --workspace --all-targets -- -D warnings: 0 warnings
[ ] cargo fmt --check: clean
[ ] security_replays.rs::replay-тест: PASS (если применимо, без #[ignore])
```

Если хотя бы один не отмечен — **НЕ merge'ить**, откатить на fix.
