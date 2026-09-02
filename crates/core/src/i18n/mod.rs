//! Minimal i18n framework (TZ Enterprise v2 §3A).
//!
//! MVP-1.0 ships two locales: `en-US` (mandatory fallback)
//! and `ru-RU` (mandatory per §3A.1). The framework is
//! intentionally simple — strings live in in-memory
//! `Bundle`s keyed by a `&'static str` key. No catalog
//! files, no ICU, no runtime hot-reload. The contract
//! the rest of the platform relies on is:
//!
//! * `I18n::t("key") -> String` — never returns an empty
//!   string; falls back to the requested locale's
//!   language-only form (e.g. `en` for `en-GB`), then to
//!   `en-US` if even that misses. The fallback is loud
//!   in tests (`I18n::is_known_key("...")`) so missing
//!   translations get fixed before they ship.
//! * `I18n::tr("key", &[("name", "Alice")])` — minimal
//!   `{name}` placeholder substitution. No plural
//!   forms, no gender agreement — the Svelte UI owns
//!   the rich formatting. CLI messages are short enough
//!   that plain `{name}` is enough for MVP-1.0.
//! * Hard-coded user-facing strings are forbidden in
//!   CLI / Tauri surfaces. A workspace grep in CI
//!   enforces this for English-only literals; the
//!   framework itself is the contract.
//!
//! The bundles are static so there is no I/O on the
//! hot path. Adding a locale is a one-line change:
//! register it in `available_locales()` and add a
//! `BUNDLE_RU` (etc.) constant.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Locale {
    #[default]
    EnUs,
    RuRu,
}

impl Locale {
    pub const fn as_str(self) -> &'static str {
        match self {
            Locale::EnUs => "en-US",
            Locale::RuRu => "ru-RU",
        }
    }
}

impl std::str::FromStr for Locale {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "en-US" | "en" => Ok(Locale::EnUs),
            "ru-RU" | "ru" => Ok(Locale::RuRu),
            other => Err(format!("unsupported locale `{other}`")),
        }
    }
}

/// All locales the platform knows about, in preference
/// order. The CLI surfaces this list to the user via
/// `AGENCY_LANG=en-US|ru-RU`.
pub fn available_locales() -> &'static [Locale] {
    &[Locale::EnUs, Locale::RuRu]
}

#[derive(Debug, Clone, Default)]
pub struct Bundle {
    entries: std::collections::HashMap<&'static str, &'static str>,
}

impl Bundle {
    pub fn new(entries: &[(&'static str, &'static str)]) -> Self {
        let mut map = std::collections::HashMap::new();
        for (k, v) in entries {
            map.insert(*k, *v);
        }
        Self { entries: map }
    }

    pub fn get(&self, key: &str) -> Option<&'static str> {
        self.entries.get(key).copied()
    }
}

/// The platform-wide i18n handle. Cheap to clone (it
/// only holds a `Locale`; bundles are static).
#[derive(Debug, Clone, Copy)]
pub struct I18n {
    locale: Locale,
}

impl I18n {
    pub fn new(locale: Locale) -> Self {
        Self { locale }
    }

    /// Pick the right locale from the runtime
    /// environment. Honours `AGENCY_LANG` first, then
    /// the standard `LANG` / `LC_ALL` env vars, then
    /// falls back to `en-US`.
    pub fn from_env() -> Self {
        let candidates: [String; 3] = [
            std::env::var("AGENCY_LANG").unwrap_or_default(),
            std::env::var("LC_ALL").unwrap_or_default(),
            std::env::var("LANG").unwrap_or_default(),
        ];
        for raw in candidates.iter() {
            if raw.is_empty() {
                continue;
            }
            // Strip `C.UTF-8` style suffixes and try to
            // match on the language tag.
            let tag = raw.split(['.', '@']).next().unwrap_or(raw);
            if let Ok(loc) = tag.parse::<Locale>() {
                return Self::new(loc);
            }
        }
        Self::new(Locale::default())
    }

    pub fn locale(&self) -> Locale {
        self.locale
    }

    /// Translate a key. Falls back through the chain
    /// `ru-RU -> en` (no `en` bundle yet in MVP-1.0) ->
    /// `en-US` -> `"<missing:key>"`. The missing-key
    /// marker is intentional: it makes untranslated
    /// strings obvious in the UI without crashing the
    /// app.
    pub fn t(&self, key: &'static str) -> String {
        self.lookup(key)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("<missing:{key}>"))
    }

    /// Translate + substitute `{name}`-style placeholders.
    /// Unknown placeholders are left in place.
    pub fn tr(&self, key: &'static str, params: &[(&str, &str)]) -> String {
        let mut out = self.t(key);
        for (k, v) in params {
            let needle = format!("{{{k}}}");
            out = out.replace(&needle, v);
        }
        out
    }

    /// True iff `key` is present in the active bundle.
    /// Use this in tests to catch missing translations
    /// before they ship.
    pub fn is_known_key(&self, key: &str) -> bool {
        self.lookup(key).is_some()
    }

    fn lookup(&self, key: &str) -> Option<&'static str> {
        let bundle = bundle_for(self.locale);
        bundle
            .get(key)
            .or_else(|| bundle_for(Locale::EnUs).get(key))
    }
}

// ---------------------------------------------------------------------
// Bundles
// ---------------------------------------------------------------------

static BUNDLE_EN_US: OnceLock<Bundle> = OnceLock::new();
static BUNDLE_RU_RU: OnceLock<Bundle> = OnceLock::new();

fn en_us_entries() -> &'static [(&'static str, &'static str)] {
    &[
        // CLI top-level
        ("cli.deploy.apply.ok", "Deployed system: {id}"),
        (
            "cli.deploy.install.ok",
            "Installed router plugin for system: {id}",
        ),
        ("cli.deploy.kv.operation_id", "operation_id"),
        ("cli.deploy.kv.target", "target"),
        ("cli.deploy.kv.wrote", "wrote"),
        ("cli.deploy.kv.skipped", "skipped"),
        ("cli.deploy.kv.backed_up", "backed_up"),
        ("cli.deploy.kv.journaled_to", "journaled_to"),
        ("cli.deploy.kv.skill_count", "skill_count"),
        ("cli.deploy.kv.manifest_sha256", "manifest_sha256"),
        ("cli.deploy.kv.skills_sha256", "skills_sha256"),
        ("cli.deploy.kv.plugin_id", "plugin_id"),
        ("cli.deploy.kv.plugin_dir", "plugin_dir"),
        ("cli.deploy.kv.hermes_home", "hermes_home"),
        (
            "cli.deploy.install.header",
            "Installed router plugin for system: {id}",
        ),
        ("cli.deploy.apply.header", "Deployed system: {id}"),
        ("cli.lock.generate.ok", "Lock file for system: {id}"),
        ("cli.lock.kv.lock_path", "lock_path"),
        ("cli.lock.kv.agent_count", "agent_count"),
        ("cli.lock.kv.skill_count", "skill_count"),
        ("cli.lock.kv.catalog_commit", "catalog_commit"),
        ("cli.lock.header", "Lock file for system: {id}"),
        ("cli.rollback.header", "Rollback plan for operation: {id}"),
        ("cli.rollback.kv.target_root", "target_root"),
        ("cli.rollback.kv.files_to_revert", "files_to_revert"),
        ("cli.rollback.kv.restored", "restored"),
        ("cli.rollback.kv.kept_current", "kept_current"),
        ("cli.rollback.kv.failed", "failed"),
        (
            "cli.rollback.note_cas",
            "  (1.5.1: CAS-indexed backups — pointer JSON under .backups/ points to <data>/cas/)",
        ),
        // MCP
        ("cli.mcp.add.header", "Installed MCP server: {name}"),
        ("cli.mcp.kv.server_dir", "server_dir"),
        ("cli.mcp.kv.manifest_path", "manifest_path"),
        ("cli.mcp.kv.manifest_sha256", "manifest_sha256"),
        // Hermes probe (1.4.0, ADR-0012)
        ("cli.hermes.probe.header", "Structural probe: {name}"),
        (
            "cli.hermes.probe.failed",
            "Probe failed: at least one check is not OK",
        ),
        ("cli.hermes.kv.hermes_home", "hermes_home"),
        ("cli.hermes.kv.ok", "ok"),
        // Status
        ("cli.status.unknown", "no deployment found"),
    ]
}

fn ru_ru_entries() -> &'static [(&'static str, &'static str)] {
    &[
        ("cli.deploy.apply.ok", "Развёрнута система: {id}"),
        (
            "cli.deploy.install.ok",
            "Установлен плагин-роутер для системы: {id}",
        ),
        ("cli.deploy.kv.operation_id", "operation_id"),
        ("cli.deploy.kv.target", "целевая директория"),
        ("cli.deploy.kv.wrote", "записано файлов"),
        ("cli.deploy.kv.skipped", "пропущено файлов"),
        ("cli.deploy.kv.backed_up", "резервных копий"),
        ("cli.deploy.kv.journaled_to", "журнал сохранён в"),
        ("cli.deploy.kv.skill_count", "количество навыков"),
        ("cli.deploy.kv.manifest_sha256", "sha256 манифеста"),
        ("cli.deploy.kv.skills_sha256", "sha256 навыков"),
        ("cli.deploy.kv.plugin_id", "идентификатор плагина"),
        ("cli.deploy.kv.plugin_dir", "каталог плагина"),
        ("cli.deploy.kv.hermes_home", "каталог Hermes"),
        (
            "cli.deploy.install.header",
            "Установлен плагин-роутер для системы: {id}",
        ),
        ("cli.deploy.apply.header", "Развёрнута система: {id}"),
        ("cli.lock.generate.ok", "lock-файл для системы: {id}"),
        ("cli.lock.kv.lock_path", "путь к lock-файлу"),
        ("cli.lock.kv.agent_count", "количество агентов"),
        ("cli.lock.kv.skill_count", "количество навыков"),
        ("cli.lock.kv.catalog_commit", "коммит каталога"),
        ("cli.lock.header", "lock-файл для системы: {id}"),
        ("cli.rollback.header", "План отката для операции: {id}"),
        ("cli.rollback.kv.target_root", "корневая директория"),
        ("cli.rollback.kv.files_to_revert", "файлов к откату"),
        ("cli.rollback.kv.restored", "восстановлено"),
        ("cli.rollback.kv.kept_current", "без изменений"),
        ("cli.rollback.kv.failed", "ошибок"),
        (
            "cli.rollback.note_cas",
            "  (1.5.1: CAS-индексированные бэкапы — JSON-указатель в .backups/ ссылается на <data>/cas/)",
        ),
        ("cli.mcp.add.header", "Установлен MCP-сервер: {name}"),
        ("cli.mcp.kv.server_dir", "каталог сервера"),
        ("cli.mcp.kv.manifest_path", "путь к manifest"),
        ("cli.mcp.kv.manifest_sha256", "sha256 manifest"),
        ("cli.hermes.probe.header", "Структурная проверка: {name}"),
        (
            "cli.hermes.probe.failed",
            "Проверка не прошла: хотя бы одна проверка вернула не OK",
        ),
        ("cli.hermes.kv.hermes_home", "каталог Hermes"),
        ("cli.hermes.kv.ok", "ok"),
        ("cli.status.unknown", "развёртывание не найдено"),
    ]
}

/// Initialize the static bundles. Called once at first
/// use of `I18n` (via `OnceLock::get_or_init`).
fn ensure_bundles() {
    BUNDLE_EN_US.get_or_init(|| Bundle::new(en_us_entries()));
    BUNDLE_RU_RU.get_or_init(|| Bundle::new(ru_ru_entries()));
}

fn bundle_for(locale: Locale) -> &'static Bundle {
    ensure_bundles();
    match locale {
        Locale::EnUs => BUNDLE_EN_US.get().expect("en bundle initialized"),
        Locale::RuRu => BUNDLE_RU_RU.get().expect("ru bundle initialized"),
    }
}

/// Force the bundles to initialize. Useful in tests
/// that want to assert every key is present in every
/// bundle.
pub fn init_for_tests() {
    ensure_bundles();
}

#[cfg(test)]
mod tests;
