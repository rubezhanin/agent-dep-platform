<script lang="ts">
  import { onMount } from "svelte";
  import ListView from "../lib/components/ListView.svelte";
  import { ipc } from "../lib/ipc";
  import { t, subscribe } from "../lib/i18n";
  import type { BackupSummary } from "../lib/types.generated";

  let items: BackupSummary[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  onMount(async () => {
    try {
      items = await ipc.backups.list();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });
</script>

<ListView
  title={t("placeholder.title.backups")}
  emptyHint={t("placeholder.hint.backups")}
  {loading}
  {error}
  {items}
>
  {#snippet row(item)}
    {@const bk = item as BackupSummary}
    {bk.path} — {bk.created_at}
  {/snippet}
</ListView>
