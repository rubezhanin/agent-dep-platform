<script lang="ts">
  import { onMount } from "svelte";
  import ListView from "../lib/components/ListView.svelte";
  import { ipc } from "../lib/ipc";
  import { t, subscribe } from "../lib/i18n";
  import type { AgentSummary } from "../lib/types.generated";

  let items: AgentSummary[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  onMount(async () => {
    try {
      items = await ipc.catalog.listAgents();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });
</script>

<ListView
  title={t("placeholder.title.catalog")}
  emptyHint={t("placeholder.hint.catalog")}
  {loading}
  {error}
  {items}
>
  {#snippet row(item)}
    {@const agent = item as AgentSummary}
    {agent.id} — {agent.name} (v{agent.version})
  {/snippet}
</ListView>
