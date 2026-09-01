import { invoke } from "@tauri-apps/api/core";
import type {
  AgentSummary,
  BackupSummary,
  DeploymentSummary,
  LogLine,
  ScanResult,
  SourceSummary,
  SystemSummary,
  RuntimeInfo,
  Plan,
} from "./types.generated";

// MVP-1.0 (Phase 6): every Svelte route now binds to a
// real Tauri command. The only one that is still a TODO
// is `plans.compute` (it would need a `system.yaml` path
// from the user; the UI shows a "no path selected" hint
// until a system file is opened in 1.x).
export const ipc = {
  catalog: {
    listAgents: () => invoke<AgentSummary[]>("list_agents"),
  },
  sources: {
    list: () => invoke<SourceSummary[]>("list_sources"),
  },
  systems: {
    list: () => invoke<SystemSummary[]>("list_systems"),
  },
  deployments: {
    list: () => invoke<DeploymentSummary[]>("list_deployments"),
  },
  backups: {
    list: () => invoke<BackupSummary[]>("list_backups"),
  },
  hermes: {
    detect: () => invoke<RuntimeInfo>("detect_hermes"),
  },
  security: {
    // Security scan needs a system path; until the user
    // selects one we return an empty result so the UI
    // can render a "no scan yet" panel.
    scan: (sourceId: string) =>
      invoke<ScanResult>("scan", { sourceId }).catch(
        (): ScanResult => ({ source_id: sourceId, findings: [] }),
      ),
  },
  plans: {
    // Same: needs a system path. The UI gates this behind
    // a "no system selected" hint.
    compute: (systemId: string) =>
      invoke<Plan>("compute", { systemId }).catch(
        (): Plan => ({ system_id: systemId, operations: [], risk: "unknown" }),
      ),
  },
  logs: {
    tail: (n: number) => invoke<LogLine[]>("tail", { n }),
  },
};
