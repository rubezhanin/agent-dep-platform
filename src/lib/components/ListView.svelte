<script lang="ts">
  // Minimal "table-of-rows" component used by the MVP-1.0
  // data-binding slice. Renders a heading, an optional
  // loading / empty hint, and one row per item. The caller
  // supplies the data + a `row` snippet that knows how to
  // render one item.
  import type { Snippet } from "svelte";

  let {
    title = "",
    emptyHint = "",
    loading = false,
    error = null as string | null,
    items = [] as unknown[],
    row,
    children,
  } = $props<{
    title?: string;
    emptyHint?: string;
    loading?: boolean;
    error?: string | null;
    items?: unknown[];
    row: Snippet<[unknown]>;
    children?: Snippet;
  }>();
</script>

<section>
  {#if title}
    <h1>{title}</h1>
  {/if}
  {#if children}{@render children()}{/if}

  {#if loading}
    <p class="muted">Loading…</p>
  {:else if error}
    <p class="error">Error: {error}</p>
  {:else if items.length === 0}
    <p class="muted">{emptyHint || "No data."}</p>
  {:else}
    <ul class="list-view">
      {#each items as item, i (i)}
        <li>{@render row(item)}</li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .list-view {
    list-style: none;
    padding: 0;
    margin: 0;
  }
  .list-view li {
    padding: 0.4rem 0;
    border-bottom: 1px solid var(--border, #eee);
  }
  .list-view li:last-child {
    border-bottom: none;
  }
  .muted {
    color: var(--muted, #888);
  }
  .error {
    color: var(--error, #c33);
  }
</style>
