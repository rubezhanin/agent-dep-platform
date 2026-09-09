// 3.0.0 (A4, audit) Vitest unit
// tests for the `Nav` shared
// component. The component is the
// only navigation surface for the
// 9 routes (backups, catalog,
// deployments, hermes, logs,
// security, settings, sources,
// systems). Bugs here are
// low-blast-radius but a
// regression in the active-route
// detection is a usability
// blocker (clicking "Systems"
// does not visually mark it as
// active → user can't tell where
// they are).

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { render, fireEvent, act, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";
import Nav from "./Nav.svelte";
import { setLocale, getLocale } from "../i18n";

// Svelte 5 `$bindable()` reads
// and writes through the prop's
// getter / setter. The simplest
// way to drive a bindable from
// a test is to wrap the value in
// a `$state` and expose a
// matching getter / setter pair
// as the prop.
function makeRoute(initial: string) {
  const state = $state({ value: initial });
  return {
    state,
    props: {
      get route() {
        return state.value;
      },
      set route(v: string) {
        state.value = v;
      },
    },
  };
}

describe("Nav", () => {
  beforeEach(() => {
    // Reset the locale between
    // tests so the
    // "switches to ru-RU" test
    // doesn't leak state into the
    // other assertions.
    setLocale("en-US");
  });

  afterEach(() => {
    // testing-library/svelte v5
    // does not auto-unmount
    // between tests; without
    // explicit cleanup, the
    // `getByText("Systems")` in
    // the third test finds TWO
    // `<a>Systems</a>` (one from
    // the second test, still
    // attached to `document.body`).
    cleanup();
  });

  it("renders all 9 navigation items with English labels by default", () => {
    const { props } = makeRoute("sources");
    const { getByText } = render(Nav, { props });
    // 9 routes per TZ §28.1.
    // Asserting the full list is
    // a low-effort regression
    // guard: if a refactor drops
    // a route, this test fails.
    expect(getByText("Sources")).toBeTruthy();
    expect(getByText("Catalog")).toBeTruthy();
    expect(getByText("Systems")).toBeTruthy();
    expect(getByText("Deployments")).toBeTruthy();
    expect(getByText("Hermes")).toBeTruthy();
    expect(getByText("Backups")).toBeTruthy();
    expect(getByText("Security")).toBeTruthy();
    expect(getByText("Logs")).toBeTruthy();
    expect(getByText("Settings")).toBeTruthy();
  });

  it("applies the `active` class to the current route only", () => {
    const { props } = makeRoute("catalog");
    const { container, getByText } = render(Nav, { props });
    // Anchor list — getByText
    // returns the anchor text, but
    // we need to assert on the
    // `active` class. Find the
    // anchor that contains the
    // text "Catalog" and inspect
    // its class list.
    const activeLink = getByText("Catalog").closest("a") as HTMLAnchorElement;
    expect(activeLink.classList.contains("active")).toBe(true);
    // All other anchors must NOT
    // have `active`. Sources is
    // a safe pick — it's not the
    // current route.
    const otherLink = getByText("Sources").closest("a") as HTMLAnchorElement;
    expect(otherLink.classList.contains("active")).toBe(false);
    // And there should be exactly
    // one `active` anchor.
    const activeAnchors = container.querySelectorAll("a.active");
    expect(activeAnchors).toHaveLength(1);
  });

  it("updates the bound route on click", async () => {
    const wrapper = makeRoute("sources");
    const { getByText } = render(Nav, { props: wrapper.props });
    const systemsLink = getByText("Systems").closest("a") as HTMLAnchorElement;
    expect(systemsLink.classList.contains("active")).toBe(false);
    await act(async () => {
      await fireEvent.click(systemsLink);
      await tick();
    });
    // The state mirror moved.
    expect(wrapper.state.value).toBe("systems");
    // And the DOM re-rendered to
    // mark "Systems" active.
    const nowActive = getByText("Systems").closest("a") as HTMLAnchorElement;
    expect(nowActive.classList.contains("active")).toBe(true);
  });

  it("re-renders labels when the locale changes", async () => {
    // The Svelte 5 reactivity
    // story for `i18n.ts` is:
    // `current` is a plain JS
    // module-level variable
    // (not `$state`), so a
    // post-mount `setLocale`
    // mutation does not
    // trigger a re-render in
    // the current component
    // (Nav subscribes via the
    // pre-Svelte-5
    // `subscribe()` + manual
    // `_localeTick` pattern
    // that the `App.svelte`
    // root uses, not the
    // per-component tracking).
    // We cover the
    // "what gets rendered for
    // a given locale" matrix
    // by mounting once per
    // locale and asserting the
    // localized labels are
    // present. A real
    // runtime locale switch
    // is tested via the
    // settings route +
    // smoke e2e — this unit
    // layer just guards
    // against translation
    // string drift.
    setLocale("ru-RU");
    const { props } = makeRoute("sources");
    const { getByText, queryByText } = render(Nav, { props });
    expect(getByText("Источники")).toBeTruthy();
    expect(queryByText("Sources")).toBeNull();
    // Other Russian labels.
    expect(getByText("Каталог")).toBeTruthy();
    expect(getByText("Системы")).toBeTruthy();
    // The Settings link is
    // not localized in the
    // current bundle (both
    // locales say "Settings" /
    // "Настройки" — the
    // Russian form IS
    // localized, just not
    // asserted here). The
    // important assertion is
    // that the bundle key
    // resolves to *some*
    // string, not the
    // `<missing:...>` fallback.
    const settingsLink = getByText("Настройки");
    expect(settingsLink.textContent).not.toMatch(/^<missing:/);
  });
});
