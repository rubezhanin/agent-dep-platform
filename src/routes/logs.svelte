<script lang="ts">
  import { onMount } from "svelte";
  import ListView from "../lib/components/ListView.svelte";
  import { ipc } from "../lib/ipc";
  import { t, subscribe } from "../lib/i18n";
  import type { LogLine } from "../lib/types.generated";

  let items: LogLine[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  onMount(async () => {
    try {
      items = await ipc.logs.tail(200);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });
</script>

<ListView
  title={t("placeholder.title.logs")}
  emptyHint={t("placeholder.hint.logs")}
  {loading}
  {error}
  {items}
>
  {#snippet row(item)}
    {@const line = item as LogLine}
    {line.ts} [{line.level}] {line.target} — {line.message}
  {/snippet}
</ListView>
