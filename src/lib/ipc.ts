import { invoke } from "@tauri-apps/api/core";
import type {
  AgentSummary,
  BackupSummary,
  DeploymentSummary,
  LogLine,
  Plan,
  ScanResult,
  SourceSummary,
  SystemSummary,
  RuntimeInfo,
} from "./types.generated";

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
  plans: {
    compute: (systemId: string) => invoke<Plan>("compute", { systemId }),
  },
  deployments: {
    list: () => invoke<DeploymentSummary[]>("list_deployments"),
  },
  backups: {
    list: () => invoke<BackupSummary[]>("list_backups"),
  },
  hermes: {
    detect: () => invoke<RuntimeInfo>("detect"),
  },
  security: {
    scan: (sourceId: string) => invoke<ScanResult>("scan", { sourceId }),
  },
  logs: {
    tail: (n: number) => invoke<LogLine[]>("tail", { n }),
  },
};
