<script lang="ts">
  import Nav from "./lib/components/Nav.svelte";
  import Sources from "./routes/sources.svelte";
  import Catalog from "./routes/catalog.svelte";
  import Systems from "./routes/systems.svelte";
  import Deployments from "./routes/deployments.svelte";
  import Hermes from "./routes/hermes.svelte";
  import Backups from "./routes/backups.svelte";
  import Security from "./routes/security.svelte";
  import Logs from "./routes/logs.svelte";
  import Settings from "./routes/settings.svelte";

  const routes: Record<string, any> = {
    sources: Sources,
    catalog: Catalog,
    systems: Systems,
    deployments: Deployments,
    hermes: Hermes,
    backups: Backups,
    security: Security,
    logs: Logs,
    settings: Settings,
  };
  let route = $state("sources");
  let Current = $derived(routes[route] ?? Sources);
</script>

<Nav bind:route />
<main>
  <Current />
</main>
