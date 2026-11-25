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
  ViolatedMetric,
  WindowsEventRecord,
  WsEnvelope,
} from "../types/sentinel";

export type TransportMode = "tauri" | "pwa" | "demo";

export type ConnectionState =
  | "connecting"
  | "connected"
  | "auth_required"
  | "disconnected"
  | "offline";

export interface TimelineQueryParams {
  limit?: number;
  offset?: number;
  category?: string;
  severity?: string;
}

export interface TransportEventHandlers {
  onTelemetry: (sample: TelemetrySample) => void;
  onSnapshot: (snapshot: BottleneckSnapshot) => void;
  onWindowsEvent: (event: WindowsEventRecord) => void;
  onStatus: (status: CollectorStatus) => void;
  onRemoteStatus?: (remoteStatus: RemoteServerStatus) => void;
  onHistoryImported?: (result: ImportHistoryResult) => void;
  onConnectionStateChange: (state: ConnectionState) => void;
}

export interface SentinelTransport {
  readonly mode: TransportMode;
  connect(handlers: TransportEventHandlers): Promise<void>;
  disconnect(): void;
  authenticateWithPin(pin: string, serverUrl?: string): Promise<void>;
  continueOffline(): boolean;
  getServerUrl(): string;
  hasOfflineCache(): boolean;
  getCollectorStatus(): Promise<CollectorStatus>;
  getRecentTelemetry(): Promise<TelemetrySample[]>;
  getTimeline(params?: TimelineQueryParams): Promise<TimelineItem[]>;
  getIncidentDetail(
    itemType: TimelineItemType,
    id: number,
  ): Promise<IncidentDetail>;
  getKnowledgeBase(): Promise<KnowledgeBaseEntry[]>;
  importWindowsHistory(days?: number): Promise<ImportHistoryResult>;
  setCollectionPaused(paused: boolean): Promise<CollectorStatus>;
  getRemoteServerStatus(): Promise<RemoteServerStatus>;
  toggleRemoteServer(
    enabled: boolean,
    port?: number,
  ): Promise<RemoteServerStatus>;
  regenerateRemotePin(): Promise<RemoteServerStatus>;
}

export function isTauriRuntime(): boolean {
  return (
    typeof window !== "undefined" &&
    ("__TAURI_INTERNALS__" in window || "__TAURI__" in window)
  );
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isWsEnvelope(value: unknown): value is WsEnvelope {
  if (!isRecord(value)) {
    return false;
  }
  const type = value.type;
  const payload = value.payload;
  if (!isRecord(payload)) {
    return false;
  }
  switch (type) {
    case "telemetry":
      return (
        typeof payload.timestampMs === "number" &&
        typeof payload.cpuPercent === "number" &&
        typeof payload.ramPercent === "number"
      );
    case "snapshot":
      return (
        typeof payload.id === "number" &&
        typeof payload.timestampMs === "number" &&
        typeof payload.violatedMetric === "string"
      );
    case "windows_event":
      return (
        typeof payload.id === "number" &&
        typeof payload.timestampMs === "number" &&
        typeof payload.eventId === "number"
      );
    case "status":
      return (
        typeof payload.paused === "boolean" &&
        typeof payload.uptimeSecs === "number"
      );
    default:
      return false;
  }
}

export function metricLabelPt(metric: ViolatedMetric): string {
  switch (metric) {
    case "cpu":
      return "CPU";
    case "ram":
      return "Memória RAM";
    case "disk_active":
      return "Uso de Disco";
    case "disk_latency":
      return "Latência de Disco";
    case "network":
      return "Rede";
  }
}

export function snapshotCategoryPt(metric: ViolatedMetric): string {
  switch (metric) {
    case "cpu":
      return "Processador (CPU)";
    case "ram":
      return "Memória RAM";
    case "disk_active":
    case "disk_latency":
      return "Disco (HD / SSD)";
    case "network":
      return "Rede e Internet";
  }
}

export function timelineItemFromEvent(ev: WindowsEventRecord): TimelineItem {
  const dataMatches = Array.from(
    ev.rawXml.matchAll(/<Data[^>]*>([^<]+)<\/Data>/gi),
  )
    .map((m) => (m[1] ?? "").trim())
    .filter((v) => v.length > 0 && v !== "0" && v !== "NULL")
    .slice(0, 10);
  const detailsText = dataMatches.length > 0 ? dataMatches.join(" · ") : null;

  return {
    uid: `event-${ev.id}`,
    itemType: "event",
    sourceId: ev.id,
    timestampUtc: ev.timestampUtc,
    timestampMs: ev.timestampMs,
    category: ev.category,
    severity: ev.severity,
    title: ev.friendlyTitle,
    summary: ev.whatHappened,
    eventId: ev.eventId,
    providerName: ev.providerName,
    violatedMetric: null,
    peakValue: null,
    hasCorrelation:
      ev.correlationSnapshotId !== null || ev.diagnosticNote !== null,
    diagnosticNote: ev.diagnosticNote,
    detailsText,
  };
}

export function timelineItemFromSnapshot(
  snap: BottleneckSnapshot,
): TimelineItem {
  const topName = snap.topProcesses[0]?.name ?? "Sistema";
  const unit = snap.violatedMetric === "disk_latency" ? "ms" : "%";
  return {
    uid: `snapshot-${snap.id}`,
    itemType: "snapshot",
    sourceId: snap.id,
    timestampUtc: snap.timestampUtc,
    timestampMs: snap.timestampMs,
    category: snapshotCategoryPt(snap.violatedMetric),
    severity: snap.severity,
    title: `Pico de ${metricLabelPt(snap.violatedMetric)} (${snap.peakValue.toFixed(1)}${unit}) por ${snap.durationSecs}s`,
    summary: `Gargalo sustentado detectado pela Caixa-Preta. Principal ofensor: ${topName}.`,
    eventId: null,
    providerName: topName,
    violatedMetric: snap.violatedMetric,
    peakValue: snap.peakValue,
    hasCorrelation: false,
    diagnosticNote: null,
  };
}
