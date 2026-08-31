<script lang="ts">
  let { title, hint = "MVP-0 placeholder. Real UI lands with the corresponding business-logic milestone." } = $props<{ title: string; hint?: string }>();
</script>

<section>
  <h1>{title}</h1>
  <p class="lead">Section under the TZ §28.1 layout.</p>
  <div class="placeholder">{hint}</div>
</section>
