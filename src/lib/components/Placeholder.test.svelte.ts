// 3.0.0 (A4) Vitest unit tests
// for the `Placeholder` shared
// component. Used by 5 routes
// (backups, catalog, hermes,
// logs, security) for "section
// under construction" pages.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import Placeholder from "./Placeholder.svelte";

afterEach(() => {
  // Without an explicit cleanup,
  // the second test sees a
  // duplicate `<section>` (the
  // first is left over from the
  // previous render). The
  // `getByText(/Section under
  // the TZ/)` regex match then
  // finds two elements and
  // throws "TestingLibraryElementError:
  // Found multiple elements".
  cleanup();
});

describe("Placeholder", () => {
  it("renders the literal title when no titleKey is given", () => {
    const { getByRole } = render(Placeholder, {
      props: { title: "Catalog" },
    });
    expect(getByRole("heading", { level: 1 }).textContent).toBe("Catalog");
  });

  it("falls back to the literal hint when no hintKey is given", () => {
    const { getByText } = render(Placeholder, {
      props: { title: "X", hint: "WIP" },
    });
    expect(getByText("WIP")).toBeTruthy();
  });

  it("renders the placeholder section marker (audit A4: snapshot test for the 9 routes pattern)", () => {
    // Every route's placeholder
    // includes the
    // "Section under the TZ
    // §28.1 layout" copy. If a
    // refactor accidentally drops
    // that, the test fails — this
    // is a low-effort guardrail.
    const { getByText } = render(Placeholder, {
      props: { title: "X" },
    });
    expect(getByText(/Section under the TZ/)).toBeTruthy();
  });
});
