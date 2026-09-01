<script lang="ts">
  import { onMount } from "svelte";
  import ListView from "../lib/components/ListView.svelte";
  import { ipc } from "../lib/ipc";
  import { t, subscribe } from "../lib/i18n";
  import type { SourceSummary } from "../lib/types.generated";

  let items: SourceSummary[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  onMount(async () => {
    try {
      items = await ipc.sources.list();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });
</script>

<ListView
  title={t("placeholder.title.sources")}
  emptyHint={t("placeholder.hint.sources")}
  {loading}
  {error}
  {items}
>
  {#snippet row(item)}
    {@const src = item as SourceSummary}
    {src.id} — {src.url || "(local)"}{src.commit_sha ? " @ " + src.commit_sha.slice(0, 8) : ""}
  {/snippet}
</ListView>
