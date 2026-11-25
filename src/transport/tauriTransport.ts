import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  BottleneckSnapshot,
  CollectorStatus,
  ImportHistoryResult,
  IncidentDetail,
  KnowledgeBaseEntry,
  RemoteServerStatus,
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
}
