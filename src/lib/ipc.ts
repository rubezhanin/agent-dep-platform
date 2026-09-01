import { invoke } from "@tauri-apps/api/core";
import type { RuntimeInfo } from "./types.generated";

// MVP-1.0: only the Hermes-detect call has a backing
// IPC handler. Every other Tauri command is a placeholder
// until the corresponding backend service lands. We
// keep the surface here so the Svelte routes can refer
// to `ipc.hermes.detect()` and the type-checker is
// happy; the data-binding work is the Phase 6 follow-up.
export const ipc = {
  hermes: {
    detect: () => invoke<RuntimeInfo>("detect_hermes"),
  },
};
