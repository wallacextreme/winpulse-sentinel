import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AiDiagnosisResponse,
  AiSettings,
  BottleneckSnapshot,
  CollectorStatus,
  CommandAuditEntry,
  CommandExecutionResult,
  CommandOutputEvent,
  CommandShell,
  CommandSource,
  DiagnoseRequest,
  ImportHistoryResult,
  IncidentDetail,
  KnowledgeBaseEntry,
  McpServerStatus,
  OllamaProbeResult,
  RemoteServerStatus,
  SaveAiSettingsInput,
  StagedCommandTicket,
  TelemetrySample,
  TimelineItem,
  TimelineItemType,
  WindowsEventRecord,
} from "../types/sentinel";
import type {
  SentinelTransport,
  TimelineQueryParams,
  TransportEventHandlers,
} from "./types";

export class TauriTransport implements SentinelTransport {
  readonly mode = "tauri" as const;
  readonly supportsExecution = true;
  private unlisteners: UnlistenFn[] = [];

  async connect(handlers: TransportEventHandlers): Promise<void> {
    this.disconnect();
    handlers.onConnectionStateChange("connecting");

    const subs = await Promise.all([
      listen<TelemetrySample>("sentinel://telemetry", (event) => {
        handlers.onTelemetry(event.payload);
      }),
      listen<BottleneckSnapshot>("sentinel://snapshot", (event) => {
        handlers.onSnapshot(event.payload);
      }),
      listen<WindowsEventRecord>("sentinel://event", (event) => {
        handlers.onWindowsEvent(event.payload);
      }),
      listen<CollectorStatus>("sentinel://status", (event) => {
        handlers.onStatus(event.payload);
      }),
      listen<RemoteServerStatus>("sentinel://remote-status", (event) => {
        handlers.onRemoteStatus?.(event.payload);
      }),
      listen<ImportHistoryResult>("sentinel://history-imported", (event) => {
        handlers.onHistoryImported?.(event.payload);
      }),
      listen<StagedCommandTicket>("sentinel://approval-requested", (event) => {
        handlers.onApprovalRequested?.(event.payload);
      }),
      listen<CommandOutputEvent>("sentinel://command-output", (event) => {
        handlers.onCommandOutput?.(event.payload);
      }),
    ]);

    this.unlisteners = subs;
    handlers.onConnectionStateChange("connected");
  }

  disconnect(): void {
    for (const unlisten of this.unlisteners) {
      unlisten();
    }
    this.unlisteners = [];
  }

  async authenticateWithPin(_pin: string, _serverUrl?: string): Promise<void> {
    // Desktop IPC does not use LAN PIN authentication.
  }

  continueOffline(): boolean {
    return false;
  }

  getServerUrl(): string {
    return "tauri://localhost";
  }

  hasOfflineCache(): boolean {
    return false;
  }

  getCollectorStatus(): Promise<CollectorStatus> {
    return invoke<CollectorStatus>("get_collector_status");
  }

  getRecentTelemetry(): Promise<TelemetrySample[]> {
    return invoke<TelemetrySample[]>("get_recent_telemetry");
  }

  getTimeline(params?: TimelineQueryParams): Promise<TimelineItem[]> {
    return invoke<TimelineItem[]>("get_timeline", {
      limit: params?.limit,
      offset: params?.offset,
      category: params?.category,
      severity: params?.severity,
    });
  }

  getIncidentDetail(
    itemType: TimelineItemType,
    id: number,
  ): Promise<IncidentDetail> {
    return invoke<IncidentDetail>("get_incident_detail", {
      itemType,
      id,
    });
  }

  getKnowledgeBase(): Promise<KnowledgeBaseEntry[]> {
    return invoke<KnowledgeBaseEntry[]>("get_knowledge_base");
  }

  importWindowsHistory(days = 30): Promise<ImportHistoryResult> {
    return invoke<ImportHistoryResult>("import_windows_history", { days });
  }

  setCollectionPaused(paused: boolean): Promise<CollectorStatus> {
    return invoke<CollectorStatus>("set_collection_paused", { paused });
  }

  getRemoteServerStatus(): Promise<RemoteServerStatus> {
    return invoke<RemoteServerStatus>("get_remote_server_status");
  }

  toggleRemoteServer(
    enabled: boolean,
    port?: number,
  ): Promise<RemoteServerStatus> {
    return invoke<RemoteServerStatus>("toggle_remote_server", {
      enabled,
      port,
    });
  }

  regenerateRemotePin(): Promise<RemoteServerStatus> {
    return invoke<RemoteServerStatus>("regenerate_remote_pin");
  }

  getAiSettings(): Promise<AiSettings> {
    return invoke<AiSettings>("get_ai_settings");
  }

  saveAiSettings(input: SaveAiSettingsInput): Promise<AiSettings> {
    return invoke<AiSettings>("save_ai_settings", { input });
  }

  setByokApiKey(apiKey: string): Promise<AiSettings> {
    return invoke<AiSettings>("set_byok_api_key", { apiKey });
  }

  clearByokApiKey(): Promise<AiSettings> {
    return invoke<AiSettings>("clear_byok_api_key");
  }

  probeOllama(baseUrl?: string): Promise<OllamaProbeResult> {
    return invoke<OllamaProbeResult>("probe_ollama", { baseUrl });
  }

  previewSanitizedIncident(
    itemType: TimelineItemType,
    id: number,
  ): Promise<DiagnoseRequest> {
    return invoke<DiagnoseRequest>("preview_sanitized_incident", {
      itemType,
      id,
    });
  }

  analyzeIncidentWithAi(
    itemType: TimelineItemType,
    id: number,
    executionFeedback?: string,
  ): Promise<AiDiagnosisResponse> {
    return invoke<AiDiagnosisResponse>("analyze_incident_with_ai", {
      itemType,
      id,
      executionFeedback,
    });
  }

  analyzeErrorTextWithAi(
    errorText: string,
    executionFeedback?: string,
  ): Promise<AiDiagnosisResponse> {
    return invoke<AiDiagnosisResponse>("analyze_error_text_with_ai", {
      errorText,
      executionFeedback,
    });
  }

  stageCommandExecution(params: {
    source: CommandSource;
    shell: CommandShell;
    command: string;
    rationale: string;
    requiresAdmin: boolean;
  }): Promise<StagedCommandTicket> {
    return invoke<StagedCommandTicket>("stage_command_execution", {
      source: params.source,
      shell: params.shell,
      command: params.command,
      rationale: params.rationale,
      requiresAdmin: params.requiresAdmin,
    });
  }

  approveCommandExecution(
    approvalId: string,
    expectedCommand: string,
    timeoutSecs?: number,
  ): Promise<CommandExecutionResult> {
    return invoke<CommandExecutionResult>("approve_command_execution", {
      approvalId,
      expectedCommand,
      timeoutSecs,
    });
  }

  rejectCommandExecution(approvalId: string): Promise<void> {
    return invoke<void>("reject_command_execution", { approvalId });
  }

  cancelCommandExecution(approvalId: string): Promise<boolean> {
    return invoke<boolean>("cancel_command_execution", { approvalId });
  }

  getCommandAuditLog(limit = 50): Promise<CommandAuditEntry[]> {
    return invoke<CommandAuditEntry[]>("get_command_audit_log", { limit });
  }

  getMcpStatus(): Promise<McpServerStatus> {
    return invoke<McpServerStatus>("get_mcp_status");
  }

  toggleMcpServer(enabled: boolean, port?: number): Promise<McpServerStatus> {
    return invoke<McpServerStatus>("toggle_mcp_server", { enabled, port });
  }

  rotateMcpToken(): Promise<McpServerStatus> {
    return invoke<McpServerStatus>("rotate_mcp_token");
  }
}
