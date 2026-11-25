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
import {
  isRecord,
  isWsEnvelope,
  timelineItemFromEvent,
  timelineItemFromSnapshot,
  type SentinelTransport,
  type TimelineQueryParams,
  type TransportEventHandlers,
} from "./types";

const TOKEN_STORAGE_KEY = "winpulse_auth_token";
const SERVER_URL_STORAGE_KEY = "winpulse_server_url";
const OFFLINE_CACHE_KEY = "winpulse_offline_cache_v1";
const MAX_CACHED_TIMELINE = 500;
const MAX_CACHED_TELEMETRY = 120;

interface OfflineCachePayload {
  telemetry: TelemetrySample[];
  timeline: TimelineItem[];
  events: Record<string, WindowsEventRecord>;
  snapshots: Record<string, BottleneckSnapshot>;
  updatedAtMs: number;
}

function emptyCache(): OfflineCachePayload {
  return {
    telemetry: [],
    timeline: [],
    events: {},
    snapshots: {},
    updatedAtMs: Date.now(),
  };
}

function readOfflineCache(): OfflineCachePayload {
  try {
    const raw = localStorage.getItem(OFFLINE_CACHE_KEY);
    if (!raw) {
      return emptyCache();
    }
    const parsed: unknown = JSON.parse(raw);
    if (!isRecord(parsed)) {
      return emptyCache();
    }
    return {
      telemetry: Array.isArray(parsed.telemetry)
        ? (parsed.telemetry as TelemetrySample[])
        : [],
      timeline: Array.isArray(parsed.timeline)
        ? (parsed.timeline as TimelineItem[])
        : [],
      events: isRecord(parsed.events)
        ? (parsed.events as Record<string, WindowsEventRecord>)
        : {},
      snapshots: isRecord(parsed.snapshots)
        ? (parsed.snapshots as Record<string, BottleneckSnapshot>)
        : {},
      updatedAtMs:
        typeof parsed.updatedAtMs === "number" ? parsed.updatedAtMs : Date.now(),
    };
  } catch {
    return emptyCache();
  }
}

function writeOfflineCache(cache: OfflineCachePayload): void {
  try {
    localStorage.setItem(
      OFFLINE_CACHE_KEY,
      JSON.stringify({
        ...cache,
        telemetry: cache.telemetry.slice(-MAX_CACHED_TELEMETRY),
        timeline: cache.timeline.slice(0, MAX_CACHED_TIMELINE),
        updatedAtMs: Date.now(),
      }),
    );
  } catch {
    // Ignore storage quota errors cleanly.
  }
}

function normalizeServerUrl(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, "");
  const parsed = new URL(trimmed);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("URL do servidor inválida. Utilize apenas http:// ou https://.");
  }
  return `${parsed.protocol}//${parsed.host}`;
}

function toWebSocketUrl(httpBase: string, ticket: string): string {
  const parsed = new URL(httpBase);
  const wsProto = parsed.protocol === "https:" ? "wss:" : "ws:";
  return `${wsProto}//${parsed.host}/ws?ticket=${encodeURIComponent(ticket)}`;
}

export class PwaWebSocketTransport implements SentinelTransport {
  readonly mode = "pwa" as const;
  private handlers: TransportEventHandlers | null = null;
  private ws: WebSocket | null = null;
  private reconnectTimer: number | null = null;
  private reconnectDelayMs = 1500;
  private manualClose = false;
  private offlineMode = false;
  private serverUrl: string;
  private token: string | null;

  constructor() {
    const savedUrl =
      typeof localStorage !== "undefined"
        ? localStorage.getItem(SERVER_URL_STORAGE_KEY)
        : null;
    const defaultOrigin =
      typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8420";
    this.serverUrl = normalizeServerUrl(savedUrl || defaultOrigin);
    this.token =
      typeof sessionStorage !== "undefined"
        ? sessionStorage.getItem(TOKEN_STORAGE_KEY)
        : null;
  }

  getServerUrl(): string {
    return this.serverUrl;
  }

  hasOfflineCache(): boolean {
    const cache = readOfflineCache();
    return cache.timeline.length > 0 || cache.telemetry.length > 0;
  }

  async connect(handlers: TransportEventHandlers): Promise<void> {
    this.handlers = handlers;
    this.manualClose = false;
    this.offlineMode = false;

    if (typeof navigator !== "undefined" && !navigator.onLine) {
      this.offlineMode = true;
      handlers.onConnectionStateChange("offline");
      return;
    }

    if (!this.token) {
      handlers.onConnectionStateChange("auth_required");
      return;
    }

    handlers.onConnectionStateChange("connecting");
    try {
      await this.getCollectorStatus();
      await this.openWebSocket();
    } catch (err) {
      if (err instanceof Error && err.message === "UNAUTHORIZED") {
        this.clearToken();
        handlers.onConnectionStateChange("auth_required");
        return;
      }
      if (this.hasOfflineCache()) {
        this.offlineMode = true;
        handlers.onConnectionStateChange("offline");
      } else {
        handlers.onConnectionStateChange("disconnected");
      }
    }
  }

  disconnect(): void {
    this.manualClose = true;
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  async authenticateWithPin(pin: string, serverUrl?: string): Promise<void> {
    if (serverUrl && serverUrl.trim().length > 0) {
      this.serverUrl = normalizeServerUrl(serverUrl);
      localStorage.setItem(SERVER_URL_STORAGE_KEY, this.serverUrl);
    }

    const res = await fetch(`${this.serverUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pin: pin.trim() }),
    });

    if (res.status === 401) {
      throw new Error("PIN inválido. Confira o código exibido no aplicativo desktop.");
    }
    if (res.status === 429) {
      throw new Error("Muitas tentativas incorretas. Aguarde 1 minuto e tente novamente.");
    }
    if (!res.ok) {
      throw new Error(`Falha ao autenticar (HTTP ${res.status}).`);
    }

    const body: unknown = await res.json();
    if (!isRecord(body) || typeof body.token !== "string" || !body.token) {
      throw new Error("Resposta de autenticação inválida do servidor.");
    }

    this.token = body.token;
    sessionStorage.setItem(TOKEN_STORAGE_KEY, body.token);
    this.offlineMode = false;
    this.manualClose = false;
    await this.openWebSocket();
  }

  continueOffline(): boolean {
    if (!this.hasOfflineCache()) {
      return false;
    }
    this.offlineMode = true;
    this.handlers?.onConnectionStateChange("offline");
    return true;
  }

  private clearToken(): void {
    this.token = null;
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  }

  private async requestWsTicket(): Promise<string> {
    if (!this.token) {
      throw new Error("UNAUTHORIZED");
    }
    const res = await fetch(`${this.serverUrl}/api/auth/ws-ticket`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token}` },
    });
    if (res.status === 401) {
      this.clearToken();
      this.handlers?.onConnectionStateChange("auth_required");
      throw new Error("UNAUTHORIZED");
    }
    if (!res.ok) {
      throw new Error(`Falha ao obter ticket WebSocket (HTTP ${res.status}).`);
    }
    const data: unknown = await res.json();
    if (!isRecord(data) || typeof data.ticket !== "string" || !data.ticket) {
      throw new Error("Ticket WebSocket inválido.");
    }
    return data.ticket;
  }

  private async openWebSocket(): Promise<void> {
    if (!this.token || !this.handlers) {
      return;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    const ticket = await this.requestWsTicket();
    const wsUrl = toWebSocketUrl(this.serverUrl, ticket);
    const socket = new WebSocket(wsUrl);
    this.ws = socket;

    socket.onopen = () => {
      this.reconnectDelayMs = 1500;
      this.offlineMode = false;
      this.handlers?.onConnectionStateChange("connected");
    };

    socket.onmessage = (msg) => {
      try {
        const parsed: unknown = JSON.parse(String(msg.data));
        if (!isWsEnvelope(parsed)) {
          return;
        }
        const cache = readOfflineCache();
        switch (parsed.type) {
          case "telemetry": {
            cache.telemetry.push(parsed.payload);
            writeOfflineCache(cache);
            this.handlers?.onTelemetry(parsed.payload);
            break;
          }
          case "snapshot": {
            cache.snapshots[String(parsed.payload.id)] = parsed.payload;
            const item = timelineItemFromSnapshot(parsed.payload);
            cache.timeline = [
              item,
              ...cache.timeline.filter((i) => i.uid !== item.uid),
            ];
            writeOfflineCache(cache);
            this.handlers?.onSnapshot(parsed.payload);
            break;
          }
          case "windows_event": {
            cache.events[String(parsed.payload.id)] = parsed.payload;
            const item = timelineItemFromEvent(parsed.payload);
            cache.timeline = [
              item,
              ...cache.timeline.filter((i) => i.uid !== item.uid),
            ];
            writeOfflineCache(cache);
            this.handlers?.onWindowsEvent(parsed.payload);
            break;
          }
          case "status": {
            this.handlers?.onStatus(parsed.payload);
            break;
          }
        }
      } catch {
        // Ignore malformed frame safely.
      }
    };

    socket.onclose = () => {
      if (this.manualClose) {
        return;
      }
      if (typeof navigator !== "undefined" && !navigator.onLine) {
        this.offlineMode = true;
        this.handlers?.onConnectionStateChange("offline");
        return;
      }
      this.handlers?.onConnectionStateChange("disconnected");
      this.scheduleReconnect();
    };
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer !== null || this.manualClose || !this.token) {
      return;
    }
    const delay = this.reconnectDelayMs;
    this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 1.6, 10_000);
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      void this.openWebSocket().catch(() => {
        if (!this.manualClose && this.token) {
          this.scheduleReconnect();
        }
      });
    }, delay);
  }

  private async authedGet<T>(path: string): Promise<T> {
    if (!this.token) {
      throw new Error("UNAUTHORIZED");
    }
    const res = await fetch(`${this.serverUrl}${path}`, {
      headers: { Authorization: `Bearer ${this.token}` },
    });
    if (res.status === 401) {
      this.clearToken();
      this.handlers?.onConnectionStateChange("auth_required");
      throw new Error("UNAUTHORIZED");
    }
    if (!res.ok) {
      throw new Error(`Erro HTTP ${res.status} ao consultar ${path}`);
    }
    return (await res.json()) as T;
  }

  async getCollectorStatus(): Promise<CollectorStatus> {
    if (this.offlineMode) {
      return {
        paused: false,
        uptimeSecs: 0,
        ringBufferLen: readOfflineCache().telemetry.length,
        eventWatcherActive: false,
        isElevated: false,
        healthStatus: "warning",
      };
    }
    return this.authedGet<CollectorStatus>("/api/status");
  }

  async getRecentTelemetry(): Promise<TelemetrySample[]> {
    if (this.offlineMode) {
      return readOfflineCache().telemetry;
    }
    try {
      const samples = await this.authedGet<TelemetrySample[]>(
        "/api/telemetry/recent",
      );
      const cache = readOfflineCache();
      cache.telemetry = samples;
      writeOfflineCache(cache);
      return samples;
    } catch {
      return readOfflineCache().telemetry;
    }
  }

  async getTimeline(params?: TimelineQueryParams): Promise<TimelineItem[]> {
    if (this.offlineMode) {
      return readOfflineCache().timeline;
    }
    const sp = new URLSearchParams();
    if (params?.limit !== undefined) sp.set("limit", String(params.limit));
    if (params?.offset !== undefined) sp.set("offset", String(params.offset));
    if (params?.category) sp.set("category", params.category);
    if (params?.severity) sp.set("severity", params.severity);
    const qs = sp.toString();
    const path = qs ? `/api/timeline?${qs}` : "/api/timeline";

    try {
      const items = await this.authedGet<TimelineItem[]>(path);
      const cache = readOfflineCache();
      cache.timeline = items;
      writeOfflineCache(cache);
      return items;
    } catch {
      return readOfflineCache().timeline;
    }
  }

  async getIncidentDetail(
    itemType: TimelineItemType,
    id: number,
  ): Promise<IncidentDetail> {
    if (!this.offlineMode) {
      try {
        const detail = await this.authedGet<IncidentDetail>(
          `/api/incidents/${itemType}/${id}`,
        );
        const cache = readOfflineCache();
        if (detail.event) {
          cache.events[String(detail.event.id)] = detail.event;
        }
        if (detail.snapshot) {
          cache.snapshots[String(detail.snapshot.id)] = detail.snapshot;
        }
        writeOfflineCache(cache);
        return detail;
      } catch (err) {
        const cached = this.buildOfflineDetail(itemType, id);
        if (cached) {
          return cached;
        }
        throw err;
      }
    }

    const offline = this.buildOfflineDetail(itemType, id);
    if (!offline) {
      throw new Error("Detalhes deste incidente não estão disponíveis no cache offline.");
    }
    return offline;
  }

  private buildOfflineDetail(
    itemType: TimelineItemType,
    id: number,
  ): IncidentDetail | null {
    const cache = readOfflineCache();
    if (itemType === "event") {
      const event = cache.events[String(id)];
      if (!event) {
        return null;
      }
      const linkedSnap =
        event.correlationSnapshotId !== null
          ? cache.snapshots[String(event.correlationSnapshotId)] ?? null
          : null;
      return {
        itemType,
        event,
        snapshot: linkedSnap,
        correlatedSnapshots: linkedSnap ? [linkedSnap] : [],
        correlatedEvents: [],
        diagnosticNote: event.diagnosticNote,
      };
    }
    const snapshot = cache.snapshots[String(id)];
    if (!snapshot) {
      return null;
    }
    return {
      itemType,
      event: null,
      snapshot,
      correlatedSnapshots: [],
      correlatedEvents: [],
      diagnosticNote: null,
    };
  }

  async getKnowledgeBase(): Promise<KnowledgeBaseEntry[]> {
    if (this.offlineMode) {
      return [];
    }
    try {
      return await this.authedGet<KnowledgeBaseEntry[]>("/api/knowledge-base");
    } catch {
      return [];
    }
  }

  async importWindowsHistory(_days?: number): Promise<ImportHistoryResult> {
    throw new Error(
      "A importação do histórico do Windows Event Log só pode ser executada no aplicativo Desktop.",
    );
  }

  async setCollectionPaused(_paused: boolean): Promise<CollectorStatus> {
    throw new Error(
      "Pausar ou retomar coleta é controlado apenas pelo aplicativo Desktop Windows.",
    );
  }

  async getRemoteServerStatus(): Promise<RemoteServerStatus> {
    return {
      enabled: true,
      port: 8420,
      lanUrls: [this.serverUrl],
      pin: null,
      activeClients: 1,
    };
  }

  async toggleRemoteServer(
    _enabled: boolean,
    _port?: number,
  ): Promise<RemoteServerStatus> {
    throw new Error(
      "O servidor LAN só pode ser ligado ou desligado no aplicativo Desktop Windows.",
    );
  }

  async regenerateRemotePin(): Promise<RemoteServerStatus> {
    throw new Error(
      "A geração de um novo PIN só está disponível no aplicativo Desktop Windows.",
    );
  }
}
