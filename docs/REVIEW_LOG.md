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
| — | — | — | — | (лог пуст; первая запись появится при переходе Phase 0 → Phase 1) |

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
