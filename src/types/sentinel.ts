export type Severity = "medium" | "high" | "critical";

export type ViolatedMetric =
  | "cpu"
  | "ram"
  | "disk_active"
  | "disk_latency"
  | "network";

export type HealthStatus = "stable" | "warning" | "critical";

export type TimelineItemType = "event" | "snapshot";

export interface TelemetrySample {
  timestampUtc: string;
  timestampMs: number;
  cpuPercent: number;
  ramPercent: number;
  ramUsedGb: number;
  ramFreeGb: number;
  ramTotalGb: number;
  diskActivePercent: number;
  diskLatencyMs: number;
  netRxKbps: number;
  netTxKbps: number;
  netLatencyMs: number | null;
  netLossPercent: number | null;
  healthStatus: HealthStatus;
}

export interface OffendingProcess {
  pid: number;
  name: string;
  exePath: string | null;
  cpuPercent: number;
  memoryMb: number;
  memoryPercent: number;
  diskReadKbps: number;
  diskWriteKbps: number;
}

export interface BottleneckSnapshot {
  id: number;
  timestampUtc: string;
  timestampMs: number;
  violatedMetric: ViolatedMetric;
  peakValue: number;
  thresholdValue: number;
  durationSecs: number;
  cpuPercent: number;
  ramPercent: number;
  ramFreeGb: number;
  diskActivePercent: number;
  diskLatencyMs: number;
  netRxKbps: number;
  netTxKbps: number;
  netLatencyMs: number | null;
  netLossPercent: number | null;
  topProcesses: OffendingProcess[];
  severity: Severity;
}

export interface WindowsEventRecord {
  id: number;
  recordId: number | null;
  channel: string;
  providerName: string;
  eventId: number;
  level: number;
  timestampUtc: string;
  timestampMs: number;
  kbId: string | null;
  category: string;
  severity: Severity;
  friendlyTitle: string;
  whatHappened: string;
  probableCauses: string[];
  solutions: string[];
  rawXml: string;
  correlationSnapshotId: number | null;
  diagnosticNote: string | null;
}

export interface TimelineItem {
  uid: string;
  itemType: TimelineItemType;
  sourceId: number;
  timestampUtc: string;
  timestampMs: number;
  category: string;
  severity: Severity;
  title: string;
  summary: string;
  eventId: number | null;
  providerName: string | null;
  violatedMetric: ViolatedMetric | null;
  peakValue: number | null;
  hasCorrelation: boolean;
  diagnosticNote: string | null;
  detailsText?: string | null;
}

export interface ImportHistoryResult {
  scanned: number;
  imported: number;
  skippedDuplicates: number;
  days: number;
}

export interface KnowledgeBaseEntry {
  id: string;
  category: string;
  logName: string;
  sources: string[];
  eventId: number;
  severity: Severity;
  friendlyTitle: string;
  whatHappened: string;
  probableCauses: string[];
  solutions: string[];
}

export interface IncidentDetail {
  itemType: TimelineItemType;
  event: WindowsEventRecord | null;
  snapshot: BottleneckSnapshot | null;
  correlatedSnapshots: BottleneckSnapshot[];
  correlatedEvents: WindowsEventRecord[];
  diagnosticNote: string | null;
}

export interface CollectorStatus {
  paused: boolean;
  uptimeSecs: number;
  ringBufferLen: number;
  eventWatcherActive: boolean;
  isElevated: boolean;
  healthStatus: HealthStatus;
}

export interface RemoteServerStatus {
  enabled: boolean;
  port: number;
  lanUrls: string[];
  pin: string | null;
  activeClients: number;
}

export type WsEnvelope =
  | { type: "telemetry"; payload: TelemetrySample }
  | { type: "snapshot"; payload: BottleneckSnapshot }
  | { type: "windows_event"; payload: WindowsEventRecord }
  | { type: "status"; payload: CollectorStatus };

export interface IncidentFilterQuery {
  query: string;
  categories: string[];
  severities: string[];
  itemTypes: string[];
  onlyCorrelated: boolean;
  fromTimestampMs?: number | null;
  toTimestampMs?: number | null;
}

export interface ClientCorrelationMatch {
  eventUid: string;
  snapshotUid: string;
  deltaMs: number;
  diagnosticNote: string;
}

export interface IncidentFacetCounts {
  total: number;
  byCategory: Record<string, number>;
  bySeverity: Record<string, number>;
}

export type AiProviderKind = "cloud_proxy" | "gemini_byok" | "ollama_local";

export interface AiSettings {
  provider: AiProviderKind;
  ollamaUrl: string;
  ollamaModel: string;
  hasByokKey: boolean;
  maskedByokKey: string | null;
  proxyUrl: string;
}

export interface SaveAiSettingsInput {
  provider: AiProviderKind;
  ollamaUrl?: string;
  ollamaModel?: string;
}

export interface OllamaProbeResult {
  available: boolean;
  baseUrl: string;
  models: string[];
  selectedModel: string | null;
  error: string | null;
}

export type CommandShell = "powershell" | "cmd";
export type CommandRiskLevel = "read_only" | "moderate";
export type CommandSource = "ai" | "catalog" | "mcp";
export type CommandAuditStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "rejected"
  | "cancelled"
  | "timed_out";

export interface ProposedCommand {
  label: string;
  shell: CommandShell;
  command: string;
  rationale: string;
  requiresAdmin: boolean;
  riskLevel: CommandRiskLevel;
}

export interface AiDiagnosisResponse {
  summary: string;
  rootCause: string;
  confidence: "high" | "medium" | "low" | string;
  steps: string[];
  proposedCommands: ProposedCommand[];
  warnings: string[];
  modelUsed: string;
  providerUsed: string;
}

export interface DiagnoseRequest {
  incidentSummary: string;
  eventId: number | null;
  providerName: string | null;
  channel: string | null;
  sanitizedXml: string | null;
  telemetryContext: string | null;
  executionFeedback: string | null;
}

export interface StagedCommandTicket {
  approvalId: string;
  source: CommandSource;
  shell: CommandShell;
  command: string;
  rationale: string;
  riskLevel: CommandRiskLevel;
  requiresAdmin: boolean;
  createdAtMs: number;
  expiresAtMs: number;
}

export interface CommandExecutionResult {
  approvalId: string;
  status: CommandAuditStatus;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  truncated: boolean;
}

export interface CommandAuditEntry {
  id: number;
  approvalId: string;
  source: CommandSource;
  shell: CommandShell;
  command: string;
  rationale: string;
  riskLevel: CommandRiskLevel;
  requiresAdmin: boolean;
  status: CommandAuditStatus;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number | null;
  createdAtMs: number;
  completedAtMs: number | null;
}

export interface CommandOutputEvent {
  approvalId: string;
  stream: string;
  chunk: string;
  finished: boolean;
  exitCode: number | null;
  status: CommandAuditStatus;
}

export interface McpServerStatus {
  enabled: boolean;
  port: number;
  endpointUrl: string;
  tokenPreview: string;
  stdioBinaryName: string;
}
