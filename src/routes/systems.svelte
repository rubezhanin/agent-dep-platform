<script lang="ts">
  import { onMount } from "svelte";
  import ListView from "../lib/components/ListView.svelte";
  import { ipc } from "../lib/ipc";
  import { t, subscribe } from "../lib/i18n";
  import type { SystemSummary } from "../lib/types.generated";

  let items: SystemSummary[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  onMount(async () => {
    try {
      items = await ipc.systems.list();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });
</script>

<ListView
  title={t("placeholder.title.systems")}
  emptyHint={t("placeholder.hint.systems")}
  {loading}
  {error}
  {items}
>
  {#snippet row(item)}
    {@const sys = item as SystemSummary}
    {sys.name ? `${sys.id} — ${sys.name} (v${sys.version || "?"})` : sys.id}
  {/snippet}
</ListView>
