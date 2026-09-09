// 3.0.0 (A4, audit) Vitest unit
// tests for the `ListView` shared
// component. The component is the
// one rendering primitive used by
// 6 of the 9 routes (sources,
// systems, deployments,
// environments, secrets, targets).
// Bugs here are high-blast-radius.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import ListView from "./ListView.svelte";
import TestListViewWrapper from "./TestListViewWrapper.svelte";

afterEach(() => {
  // Without an explicit cleanup,
  // testing-library/svelte v5
  // does NOT auto-unmount the
  // component between tests, so
  // the second test sees two
  // `<section>` blocks in
  // `document.body`. Svelte 5
  // deprecates relying on
  // implicit unmount — cleanup
  // is the documented escape
  // hatch.
  cleanup();
});

describe("ListView", () => {
  it("renders the title prop", () => {
    const { getByRole } = render(ListView, {
      props: { title: "Sources" },
    });
    expect(getByRole("heading", { level: 1 }).textContent).toBe("Sources");
  });

  it("renders an empty hint when no items are supplied", () => {
    const { getByText } = render(ListView, {
      props: { title: "Sources", emptyHint: "No sources yet" },
    });
    expect(getByText("No sources yet")).toBeTruthy();
  });

  it("renders one row per item via the row snippet", () => {
    // Svelte 5 snippets are a
    // compile-time construct —
    // testing-library can't pass
    // them via `props: { row: fn }`.
    // The wrapper component
    // supplies a trivial row
    // renderer inline so the
    // test exercises the real
    // `{#each items} {@render row}`
    // path inside ListView.
    const { container } = render(TestListViewWrapper, {
      props: { items: [1, 2, 3, 4] },
    });
    // 4 items → 4 `<li>`
    // wrappers, each containing
    // a `data-testid="row"`
    // span from the wrapper.
    expect(container.querySelectorAll("ul.list-view > li")).toHaveLength(4);
    expect(container.querySelectorAll("[data-testid='row']")).toHaveLength(4);
  });

  it("shows the loading state without rendering the empty hint", () => {
    const { getByText, queryByText } = render(ListView, {
      props: { title: "Sources", loading: true, emptyHint: "No sources" },
    });
    // The component has no
    // explicit "Loading..."
    // string, but the section is
    // present. The empty hint
    // must NOT be visible while
    // loading.
    expect(queryByText("No sources")).toBeNull();
    // The title is still there.
    expect(getByText("Sources")).toBeTruthy();
  });

  it("shows the error message when the error prop is set", () => {
    // The component prefixes
    // the error string with
    // "Error: ", so the text
    // matcher must be a regex
    // (a literal "DB connection
    // lost" wouldn't match the
    // whole node text).
    const { getByText } = render(ListView, {
      props: { title: "Sources", error: "DB connection lost" },
    });
    expect(getByText(/DB connection lost/)).toBeTruthy();
  });
});
