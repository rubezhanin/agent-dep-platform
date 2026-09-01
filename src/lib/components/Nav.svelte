<script lang="ts">
  import { t, subscribe } from "../i18n";
  const items = [
    { id: "sources", key: "nav.sources" },
    { id: "catalog", key: "nav.catalog" },
    { id: "systems", key: "nav.systems" },
    { id: "deployments", key: "nav.deployments" },
    { id: "hermes", key: "nav.hermes" },
    { id: "backups", key: "nav.backups" },
    { id: "security", key: "nav.security" },
    { id: "logs", key: "nav.logs" },
    { id: "settings", key: "nav.settings" },
  ];
  let { route = $bindable() } = $props<{ route: string }>();
  // Re-render when the locale changes.
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
</script>

<nav>
  <h1>Agent Deployment</h1>
  {#each items as item (item.id)}
    <a
      href="#{item.id}"
      class:active={route === item.id}
      onclick={() => (route = item.id)}
    >{t(item.key)}</a>
  {/each}
</nav>
