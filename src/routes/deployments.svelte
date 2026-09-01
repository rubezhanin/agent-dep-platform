<script lang="ts">
  import { onMount } from "svelte";
  import ListView from "../lib/components/ListView.svelte";
  import { ipc } from "../lib/ipc";
  import { t, subscribe } from "../lib/i18n";
  import type { DeploymentSummary } from "../lib/types.generated";

  let items: DeploymentSummary[] = $state([]);
  let loading = $state(true);
  let error: string | null = $state(null);
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  onMount(async () => {
    try {
      items = await ipc.deployments.list();
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });
</script>

<ListView
  title={t("placeholder.title.deployments")}
  emptyHint={t("placeholder.hint.deployments")}
  {loading}
  {error}
  {items}
>
  {#snippet row(item)}
    {@const dep = item as DeploymentSummary}
    {dep.id} — {dep.status} @ {dep.created_at}
  {/snippet}
</ListView>
