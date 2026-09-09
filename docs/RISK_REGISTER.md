# Risk Register

> **Назначение:** единственный источник правды по **residual risks** (то, что остаётся после closing'а finding'а, или то, что сознательно accept'нуто без полного устранения).
> Tracked (не gitignored) — это operational reality, не design notes.
> Источник: `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §1, §11 (Q9, Q10).

---

## 1. Формат записи

Каждый risk — одна строка в формате:

```
RR-NNN | <status> | <finding ref> | <category> | <description> | <owner> | <mitigation / acceptance> | <date>
```

Где:

| Поле | Описание |
|---|---|
| `RR-NNN` | Уникальный ID (RR-001, RR-002, ...). Монотонно возрастает. |
| `<status>` | `OPEN` (mitigation в работе), `ACCEPTED` (риск сознательно не устраняем), `CLOSED` (mitigation применена, риск больше не residual) |
| `<finding ref>` | `P0-F-01` и т.п. — из `REMEDIATION-PLAN.md` §3. `—` если risk не из конкретного finding'а |
| `<category>` | CWE category (CWE-287 / CWE-918 / etc.) или `ARCH` / `OPS` / `BUSINESS` |
| `<description>` | 1-2 строки: ЧТО остаётся риском |
| `<owner>` | Кто accept'нул / работает над mitigation |
| `<mitigation / acceptance>` | Что сделано для снижения риска, или почему он accept'нут |
| `<date>` | YYYY-MM-DD |

---

## 2. Шкала severity (informal)

| Severity | Пример |
|---|---|
| **CRITICAL** | Прямой compromise в production-конфигурации по умолчанию |
| **HIGH** | Требует attacker-controlled условий (specific deployment / env) |
| **MEDIUM** | Требует insider access или chained exploit |
| **LOW** | Defense-in-depth gap; не exploitable в текущей конфигурации |
| **INFO** | Не security risk, но документируем для полноты |

---

## 3. Записи

> На момент создания реестра (Phase 0) — реестр пуст. Записи появляются по мере closing'а P0/P1 finding'ов и фиксации их residual risk.

| RR-NNN | Status | Finding | Category | Description | Owner | Mitigation / acceptance | Date |
|---|---|---|---|---|---|---|---|
| RR-005 | ACCEPTED | audit D2 | OPS | Two reqwest versions in Cargo.lock: `reqwest 0.12.28` (workspace: cli, server, hermes-adapter, dev-deps) and `reqwest 0.13.4` (transitive via `tauri 2.11.5` for webview internals). The audit recommendation (unify on one version) is impossible without forking tauri. Impact: ~doubled HTTP-client compile time, larger tauri-app binary (which is the only consumer of 0.13.4). Server / CLI / hermes-adapter still get a single version (0.12.28). | self | ACCEPTED. If tauri ships an upstream `reqwest = 0.12` compat release, re-evaluate. Otherwise this is a permanent tax for embedding tauri. | 2026-09-09 |

| RR-NNN | Status | Finding ref | Category | Description | Owner | Mitigation / acceptance | Date |
|---|---|---|---|---|---|---|---|
| RR-001 | OPEN | P0-F-05 | CWE-798 | Windows file ACL для `vault.salt` не enforced агентом — `set_salt_file_mode` is no-op на Windows. Если Windows host с shared user'ами, другие user'ы могут прочитать salt. | operator | Документировать в `docs/DEPLOY.md` Windows deployment; mitigation = `icacls` post-install или dedicated agency user. ACCEPTED до Phase 5. | 2026-09-07 |
| RR-002 | OPEN | P0-S-01 | CWE-250 | Plugin sandbox `PR_SET_NO_NEW_PRIVS` is Linux-only. На Windows / macOS the plugin runs with the parent's full privilege set; a malicious plugin could exploit setuid binaries or call `setuid(0)` directly. | operator | Документировать в `docs/DEPLOY.md` что production deploy — Linux only. ACCEPTED для dev / test. Production deployment на non-Linux — Phase 5 follow-up (requires bwrap / nsjail / containerd). | 2026-09-07 |

---

## 4. Когда добавлять запись

1. **При closing'е finding'а** — если в `Residual risk:` секции отчёта что-то перечислено (не "none").
2. **При accept'нутом ограничении** — например: "Windows не имеет plugin sandbox, потому что WSL/Job Objects — out of scope. ACCEPTED until Phase 5".
3. **При operational risk'е** — например: "admin token в `/var/lib/agency/server.token` mode 0600, но root на shared host может его прочитать. MEDIUM, mitigation = dedicated agency user (uid=60001)".

---

## 5. Lifecycle

```
OPEN → (mitigation применена) → CLOSED
OPEN → (сознательное решение не устранять) → ACCEPTED
ACCEPTED → (revisit позже, mitigation теперь feasible) → OPEN
```

Любой переход — запись в `docs/REVIEW_LOG.md` со ссылкой на RR-NNN.

---

## 6. Audit / export

Risk Register не считается audit trail (для этого есть `audit_log` table в SQLite). Это **planning artifact** — "что мы знаем о residual risk'ах и что с этим делаем". При incident postmortem — первое место, куда смотрим.

---

## 7. Связанные документы

- `TZ_agent-dep-platform-REMEDIATION-PLAN.md` §3 — источник finding'ов
- `docs/AGENT_DOD.md` §1 п.12 — обязательная ссылка на RR-NNN в каждом отчёте
- `docs/REVIEW_LOG.md` — log переходов RR-NNN по статусам
- `crates/core/tests/security_replays.rs` — replay-сценарии из TZ #2 Appendix A
