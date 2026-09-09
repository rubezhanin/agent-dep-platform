<!-- 3.0.0 (A4, audit) Test
     wrapper for ListView that
     supplies a row snippet
     inline. Svelte 5 snippets
     are a compile-time
     construct — testing-library
     cannot pass them via
     `props: { row: fn }`. The
     wrapper renders the real
     component with a trivial
     row renderer. -->

<script lang="ts">
  import ListView from "./ListView.svelte";
  let { items }: { items: unknown[] } = $props();
</script>

<ListView title="Items" {items}>
  {#snippet row(item: unknown)}
    <span data-testid="row">{String(item)}</span>
  {/snippet}
</ListView>
