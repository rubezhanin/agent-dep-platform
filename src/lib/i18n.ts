// Minimal Svelte i18n helper that mirrors the Rust
// i18n framework in `crates/core/src/i18n/`.
//
// MVP-1.0 ships two locales: `en-US` and `ru-RU`.
// The bundle lives in TypeScript so the renderer never
// round-trips through Tauri IPC for a translated string.

export type Locale = "en-US" | "ru-RU";

type Bundle = Record<string, string>;

const EN_US: Bundle = {
  "nav.sources": "Sources",
  "nav.catalog": "Catalog",
  "nav.systems": "Systems",
  "nav.deployments": "Deployments",
  "nav.hermes": "Hermes",
  "nav.backups": "Backups",
  "nav.security": "Security",
  "nav.logs": "Logs",
  "nav.settings": "Settings",
  "placeholder.title.sources": "Sources",
  "placeholder.hint.sources":
    "Connect Git repositories (TZ В§10). MVP-1.0 ships a local ingest; SSH/HTTPS Git lands in 1.x.",
  "placeholder.title.catalog": "Catalog",
  "placeholder.hint.catalog":
    "Browse agents and skills (TZ В§28.1).",
  "placeholder.title.systems": "Systems",
  "placeholder.hint.systems":
    "Compose agent systems from resolved catalog snapshots.",
  "placeholder.title.deployments": "Deployments",
  "placeholder.hint.deployments":
    "Inspect desired vs. actual state and the history of operations.",
  "placeholder.title.hermes": "Hermes",
  "placeholder.hint.hermes":
    "Runtime health + plugin lifecycle (TZ В§12).",
  "placeholder.title.backups": "Backups / Rollback",
  "placeholder.hint.backups":
    "Restore a previous deployment snapshot (TZ В§19).",
  "placeholder.title.security": "Security",
  "placeholder.hint.security":
    "Scanner findings and policy decisions (TZ В§23, В§24).",
  "placeholder.title.logs": "Logs",
  "placeholder.hint.logs":
    "Structured JSON diagnostics (TZ В§34).",
  "placeholder.title.settings": "Settings",
  "placeholder.hint.settings":
    "Locale, policy path, Hermes home, and storage layout.",
  "settings.locale.label": "Language:",
  "settings.locale.en": "English",
  "settings.locale.ru": "Русский",
};

const RU_RU: Bundle = {
  "nav.sources": "Источники",
  "nav.catalog": "Каталог",
  "nav.systems": "Системы",
  "nav.deployments": "Развёртывания",
  "nav.hermes": "Hermes",
  "nav.backups": "Резервные копии",
  "nav.security": "Безопасность",
  "nav.logs": "Журналы",
  "nav.settings": "Настройки",
  "placeholder.title.sources": "Источники",
  "placeholder.hint.sources":
    "Подключение Git-репозиториев (TZ В§10). В MVP-1.0 доступен локальный импорт; SSH/HTTPS Git появится в 1.x.",
  "placeholder.title.catalog": "Каталог",
  "placeholder.hint.catalog":
    "Просмотр агентов и навыков (TZ §28.1).",
  "placeholder.title.systems": "Системы",
  "placeholder.hint.systems":
    "Сборка систем агентов из зафиксированных снимков каталога.",
  "placeholder.title.deployments": "Развёртывания",
  "placeholder.hint.deployments":
    "Сравнение желаемого и фактического состояния, история операций.",
  "placeholder.title.hermes": "Hermes",
  "placeholder.hint.hermes":
    "Здоровье runtime + жизненный цикл плагинов (TZ В§12).",
  "placeholder.title.backups": "Резервные копии / Откат",
  "placeholder.hint.backups":
    "Восстановление предыдущего снимка развёртывания (TZ В§19).",
  "placeholder.title.security": "Безопасность",
  "placeholder.hint.security":
    "Результаты сканера и политики (TZ В§23, В§24).",
  "placeholder.title.logs": "Журналы",
  "placeholder.hint.logs":
    "Структурированные JSON-диагностики (TZ В§34).",
  "placeholder.title.settings": "Настройки",
  "placeholder.hint.settings":
    "Локаль, путь к политике, каталог Hermes и схема хранилища.",
  "settings.locale.label": "Язык:",
  "settings.locale.en": "English",
  "settings.locale.ru": "Русский",
};

const BUNDLES: Record<Locale, Bundle> = {
  "en-US": EN_US,
  "ru-RU": RU_RU,
};

function pickLocale(): Locale {
  if (typeof localStorage !== "undefined") {
    const stored = localStorage.getItem("agency.locale");
    if (stored === "en-US" || stored === "ru-RU") return stored;
  }
  if (typeof navigator !== "undefined" && navigator.language) {
    if (navigator.language.startsWith("ru")) return "ru-RU";
  }
  return "en-US";
}

let current: Locale = pickLocale();
const listeners = new Set<() => void>();

export function getLocale(): Locale {
  return current;
}

export function setLocale(locale: Locale): void {
  current = locale;
  if (typeof localStorage !== "undefined") {
    localStorage.setItem("agency.locale", locale);
  }
  listeners.forEach((l) => l());
}

export function t(key: string): string {
  return BUNDLES[current][key] ?? `<missing:${key}>`;
}

export function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}
