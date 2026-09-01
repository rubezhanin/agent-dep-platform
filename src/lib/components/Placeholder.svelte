<script lang="ts">
  import { t, subscribe } from "../i18n";
  // Two naming conventions are used across the routes:
  //   <Placeholder title="Sources" />            (legacy)
  //   <Placeholder titleKey="placeholder.title.sources"
  //                 hintKey="placeholder.hint.sources" />
  // The `titleKey` / `hintKey` form is the i18n-aware
  // shape used by the new routes. Both fall back to
  // the literal `title` / `hint` strings when keys are
  // missing or omitted.
  let {
    title = "",
    hint = "",
    titleKey = "",
    hintKey = "",
  } = $props<{
    title?: string;
    hint?: string;
    titleKey?: string;
    hintKey?: string;
  }>();
  let _localeTick = $state(0);
  $effect(() => {
    const off = subscribe(() => (_localeTick += 1));
    return () => off();
  });
  const resolvedTitle = $derived(titleKey ? t(titleKey) : title);
  const resolvedHint = $derived(hintKey ? t(hintKey) : hint);
</script>

<section>
  <h1>{resolvedTitle}</h1>
  <p class="lead">Section under the TZ §28.1 layout.</p>
  <div class="placeholder">{resolvedHint}</div>
</section>
