<script lang="ts">
  import { onMount } from "svelte";
  import { ipc } from "../lib/ipc";
  import { t, subscribe } from "../lib/i18n";
  import type { RuntimeInfo } from "../lib/types.generated";

  let runtime: RuntimeInfo | null = $state(null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  onMount(async () => {
    try {
      runtime = await ipc.hermes.detect();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });
</script>

<section>
  <h1>{t("placeholder.title.hermes")}</h1>
  {#if loading}
    <p class="muted">Loading…</p>
  {:else if error}
    <p class="error">Error: {error}</p>
  {:else if runtime}
    <dl>
      <dt>version</dt>
      <dd>{runtime.version}</dd>
      <dt>home</dt>
      <dd>{runtime.home}</dd>
      <dt>plugin_dir</dt>
      <dd>{runtime.plugin_dir}</dd>
    </dl>
  {:else}
    <p class="muted">{t("placeholder.hint.hermes")}</p>
  {/if}
</section>

<style>
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; }
  dt { font-weight: bold; }
  .muted { color: #888; }
  .error { color: #c33; }
</style>
