<script lang="ts">
  const items = [
    { id: "sources", label: "Sources" },
    { id: "catalog", label: "Catalog" },
    { id: "systems", label: "Systems" },
    { id: "deployments", label: "Deployments" },
    { id: "hermes", label: "Hermes" },
    { id: "backups", label: "Backups / Rollback" },
    { id: "security", label: "Security" },
    { id: "logs", label: "Logs" },
    { id: "settings", label: "Settings" },
  ];
  let { route = $bindable() } = $props<{ route: string }>();
</script>

<nav>
  <h1>Agent Deployment</h1>
  {#each items as item (item.id)}
    <a
      href="#{item.id}"
      class:active={route === item.id}
      onclick={() => (route = item.id)}
    >{item.label}</a>
  {/each}
</nav>
