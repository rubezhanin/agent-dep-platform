# i18n review checklist — Russian (ru-RU)

MVP-1.0 ships two locales per TZ v2 §3A: `en-US` (mandatory
fallback) and `ru-RU` (mandatory for MVP). This file is the
canonical review surface for the Russian translations: every
key below is shipped in both bundles, and the bilingual parity
test in `crates/core/src/i18n/i18n_tests.rs` enforces that
no key is missing from one side or the other.

The CLI strings live in `crates/core/src/i18n/mod.rs`
(`ru_ru_entries`). The Svelte UI strings live in
`src/lib/i18n.ts` (the `RU_RU` object).

## How to read this

Each row is `key | English | Russian`. Please flag any Russian
string that reads awkwardly, is too literal, or violates
house style (we follow Microsoft Localization Style Guide for
Russian technical copy):

- Code identifiers (`plugin_id`, `manifest_sha256`, `HERMES_HOME`)
  stay verbatim — they are not translated.
- Parameter placeholders are `{id}` etc. and MUST stay in
  sync between the two languages.
- Lower-case noun forms (`записано`, `пропущено`, `уже актуально`)
  are the result of the `kv` table shape: the CLI prints
  them in a two-column `key: value` layout, so the value
  is a stand-alone label, not a sentence.

## CLI strings (Rust)

| Key | English | Russian |
|---|---|---|
| `cli.deploy.apply.ok` | Deployed system: {id} | Развёрнута система: {id} |
| `cli.deploy.install.ok` | Installed router plugin for system: {id} | Установлен плагин-роутер для системы: {id} |
| `cli.deploy.kv.operation_id` | operation_id | operation_id |
| `cli.deploy.kv.target` | target | целевая директория |
| `cli.deploy.kv.wrote` | wrote | записано |
| `cli.deploy.kv.skipped` | skipped | пропущено |
| `cli.deploy.kv.backed_up` | backed_up | резервных копий |
| `cli.deploy.kv.journaled_to` | journaled_to | журнал сохранён в |
| `cli.deploy.kv.skill_count` | skill_count | количество скиллов |
| `cli.deploy.kv.manifest_sha256` | manifest_sha256 | sha256 манифеста |
| `cli.deploy.kv.skills_sha256` | skills_sha256 | sha256 скиллов |
| `cli.deploy.kv.plugin_id` | plugin_id | идентификатор плагина |
| `cli.deploy.kv.plugin_dir` | plugin_dir | каталог плагина |
| `cli.deploy.kv.hermes_home` | hermes_home | каталог Hermes |
| `cli.deploy.install.header` | Installed router plugin for system: {id} | Установлен плагин-роутер для системы: {id} |
| `cli.deploy.apply.header` | Deployed system: {id} | Развёрнута система: {id} |
| `cli.lock.generate.ok` | Lock file for system: {id} | Lock-файл для системы: {id} |
| `cli.lock.kv.lock_path` | lock_path | путь к lock-файлу |
| `cli.lock.kv.agent_count` | agent_count | количество агентов |
| `cli.lock.kv.skill_count` | skill_count | количество скиллов |
| `cli.lock.kv.catalog_commit` | catalog_commit | коммит каталога |
| `cli.lock.header` | Lock file for system: {id} | Lock-файл для системы: {id} |
| `cli.rollback.header` | Rollback plan for operation: {id} | План отката для операции: {id} |
| `cli.rollback.kv.target_root` | target_root | корневая директория |
| `cli.rollback.kv.files_to_revert` | files_to_revert | файлов к откату |
| `cli.rollback.kv.restored` | restored | восстановлено |
| `cli.rollback.kv.kept_current` | kept_current | уже актуально |
| `cli.rollback.kv.failed` | failed | ошибок |
| `cli.rollback.todo_cas` | (Phase 5 TODO: actually re-write the pre-deploy bytes from CAS) | (TODO Phase 5: записать байты до деплоя из CAS) |
| `cli.status.unknown` | no deployment found | развёртывание не найдено |

## Svelte UI strings (TypeScript)

| Key | English | Russian |
|---|---|---|
| `nav.sources` | Sources | Источники |
| `nav.catalog` | Catalog | Каталог |
| `nav.systems` | Systems | Системы |
| `nav.deployments` | Deployments | Развёртывания |
| `nav.hermes` | Hermes | Hermes |
| `nav.backups` | Backups | Резервные копии |
| `nav.security` | Security | Безопасность |
| `nav.logs` | Logs | Журналы |
| `nav.settings` | Settings | Настройки |
| `placeholder.title.sources` | Sources | Источники |
| `placeholder.hint.sources` | Connect Git repositories (TZ §10). MVP-1.0 ships a local ingest; SSH/HTTPS Git lands in 1.x. | Подключение Git-репозиториев (TZ §10). В MVP-1.0 доступен локальный импорт; SSH/HTTPS Git появится в 1.x. |
| `placeholder.title.catalog` | Catalog | Каталог |
| `placeholder.hint.catalog` | Browse agents and skills (TZ §28.1). | Просмотр агентов и скиллов (TZ §28.1). |
| `placeholder.title.systems` | Systems | Системы |
| `placeholder.hint.systems` | Compose agent systems from resolved catalog snapshots. | Сборка систем агентов из зафиксированных снимков каталога. |
| `placeholder.title.deployments` | Deployments | Развёртывания |
| `placeholder.hint.deployments` | Inspect desired vs. actual state and the history of operations. | Сравнение желаемого и фактического состояния, история операций. |
| `placeholder.title.hermes` | Hermes | Hermes |
| `placeholder.hint.hermes` | Runtime health + plugin lifecycle (TZ §12). | Здоровье runtime + жизненный цикл плагинов (TZ §12). |
| `placeholder.title.backups` | Backups / Rollback | Резервные копии / Откат |
| `placeholder.hint.backups` | Restore a previous deployment snapshot (TZ §19). | Восстановление предыдущего снимка развёртывания (TZ §19). |
| `placeholder.title.security` | Security | Безопасность |
| `placeholder.hint.security` | Scanner findings and policy decisions (TZ §23, §24). | Результаты сканера и политики (TZ §23, §24). |
| `placeholder.title.logs` | Logs | Журналы |
| `placeholder.hint.logs` | Structured JSON diagnostics (TZ §34). | Структурированные JSON-диагностики (TZ §34). |
| `placeholder.title.settings` | Settings | Настройки |
| `placeholder.hint.settings` | Locale, policy path, Hermes home, and storage layout. | Локаль, путь к политике, каталог Hermes и схема хранилища. |
| `settings.locale.label` | Language: | Язык: |
| `settings.locale.en` | English | English |
| `settings.locale.ru` | Русский | Русский |

## Specific things to look for

1. **Disambiguating the two "rollback" KV labels.** The two
   Russian strings `файлов к откату` and `уже актуально` carry
   most of the rollback UX weight — are they clear without
   seeing the English?
2. **`Lock-файл` hyphenation.** The Russian writing style for
   loan-words like `Lock-файл` is inconsistent; some style
   guides prefer `lock-файл` (lowercase Latin prefix), others
   `Lock-файл` (capitalised). We've used `Lock-файл` to match
   the capitalization of the literal filename. Confirm.
3. **Genitive vs. nominative in counts.** The `kv` block
   uses bare nominative forms (`записано`, `пропущено`,
   `ошибок`). For a future phase, the count-aware form
   (`1 ошибка / 2 ошибки / 5 ошибок`) would be nicer; for
   MVP-1.0 we keep it simple and consistent with the
   two-column key-value layout.
4. **`Plurality of "скиллов"`** — some style guides prefer
   `скиллов` (genitive plural of `скилл`), others reject
   the loan-word and use `навыков`. We've kept `скиллов` for
   terminological consistency with the English `skill`.

## What is NOT translated

- The `TZ §…` references — these are pointers to the source
  document, not English text.
- The `Phase 5 TODO` placeholder in `cli.rollback.todo_cas`
  is kept in English on purpose: it is dev-facing and will
  be removed before 1.0.
- All code identifiers (`plugin_id`, `manifest_sha256`, etc.)
  are not translated.
- The Svelte `<a11y-clean locale picker>` widget labels in
  `settings.svelte` go through `settings.locale.en` /
  `settings.locale.ru` and are listed above.

## How to apply edits

1. Edit the matching entry in
   `crates/core/src/i18n/mod.rs::ru_ru_entries` (CLI) and/or
   `src/lib/i18n.ts::RU_RU` (UI).
2. Run `cargo test -p agent_dep_core --lib i18n` — the
   bilingual parity test will fail if the two bundles drift
   out of sync.
3. Commit with a message like `i18n(ru): …`.
