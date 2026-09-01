<script lang="ts">
  import { onMount } from "svelte";
  import ListView from "../lib/components/ListView.svelte";
  import { ipc } from "../lib/ipc";
  import { t, subscribe } from "../lib/i18n";
  import type { Finding, ScanResult } from "../lib/types.generated";

  let result: ScanResult | null = $state(null as ScanResult | null);
  let loading = $state(true);
  let error: string | null = $state(null);
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  onMount(async () => {
    try {
      result = await ipc.security.scan("active");
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  });

  const items = $derived(result?.findings ?? []);
</script>

<ListView
  title={t("placeholder.title.security")}
  emptyHint={t("placeholder.hint.security")}
  {loading}
  {error}
  {items}
>
  {#snippet row(item)}
    {@const finding = item as Finding}
    [{finding.severity}] {finding.rule} — {finding.path}: {finding.reason}
  {/snippet}
</ListView>
