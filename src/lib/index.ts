// Re-export the generated TypeScript DTOs
// (produced by `cargo test -p agent_dep_core
// --test ts_export` in CI step "ts-rs drift")
// through a barrel so the Svelte routes can
// write `import type { Foo } from "../lib"`. The
// import-without-extension path is the only one
// svelte-check on the Linux GitHub-hosted runner
// reliably resolves with
// `"verbatimModuleSyntax": true` +
// `"moduleResolution": "Bundler"`; pointing the
// route imports at the generated file directly
// (`../lib/types.generated` or
// `../lib/types.generated.ts`) sometimes resolves
// in `tsc` / `vite build` and sometimes does not
// in svelte-check, which led to 16 phantom
// `no exported member` errors in CI runs
// 34484876269, 34486167058, 34487082397.

export type {
  AgentSummary,
  ArtifactHealth,
  ArtifactHealthStatus,
  BackupSummary,
  DeploymentSummary,
  Finding,
  HealthReport,
  LogLine,
  McpAuth,
  McpServerSpec,
  McpTransport,
  Plan,
  PlanOperation,
  ProbeCheck,
  ProbeReport,
  ProbeStatus,
  RuntimeInfo,
  ScanResult,
  SourceSummary,
  SystemSummary,
} from "./types.generated";
