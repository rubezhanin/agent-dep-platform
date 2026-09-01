<script lang="ts">
  import Placeholder from "../lib/components/Placeholder.svelte";
  import { getLocale, setLocale, t, subscribe } from "../lib/i18n";
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
</script>

<Placeholder titleKey="placeholder.title.settings"
              hintKey="placeholder.hint.settings" />
<fieldset class="locale-picker">
  <legend>{t("settings.locale.label")}</legend>
  <button
    type="button"
    class:active={getLocale() === "en-US"}
    onclick={() => setLocale("en-US")}
  >{t("settings.locale.en")}</button>
  <button
    type="button"
    class:active={getLocale() === "ru-RU"}
    onclick={() => setLocale("ru-RU")}
  >{t("settings.locale.ru")}</button>
</fieldset>
