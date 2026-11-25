import rawKnowledgeBase from "../../knowledge_base.json";
import type {
  BottleneckSnapshot,
  CollectorStatus,
  ImportHistoryResult,
  IncidentDetail,
  KnowledgeBaseEntry,
  OffendingProcess,
  RemoteServerStatus,
  Severity,
  TelemetrySample,
  TimelineItem,
  TimelineItemType,
  WindowsEventRecord,
} from "../types/sentinel";
import {
  timelineItemFromEvent,
  timelineItemFromSnapshot,
  type SentinelTransport,
  type TimelineQueryParams,
  type TransportEventHandlers,
} from "./types";

interface RawKbEvent {
  id: string;
  category: string;
  log_name: string;
  sources: string[];
  event_id: number;
  severity: string;
  friendly_title: string;
  what_happened: string;
  probable_causes: string[];
  solutions: string[];
}

function normalizeSeverity(sev: string): Severity {
  if (sev === "critical" || sev === "high" || sev === "medium") {
    return sev;
  }
  return "medium";
}

function loadKnowledgeBaseEntries(): KnowledgeBaseEntry[] {
  const rawEvents = (rawKnowledgeBase as { events?: RawKbEvent[] }).events ?? [];
  return rawEvents.map((e) => ({
    id: e.id,
    category: e.category,
    logName: e.log_name,
    sources: e.sources,
    eventId: e.event_id,
    severity: normalizeSeverity(e.severity),
    friendlyTitle: e.friendly_title,
    whatHappened: e.what_happened,
    probableCauses: e.probable_causes,
    solutions: e.solutions,
  }));
}

const DEMO_PROCESSES: OffendingProcess[] = [
  {
    pid: 4242,
    name: "chrome.exe",
    exePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    cpuPercent: 34.8,
    memoryMb: 6420.0,
    memoryPercent: 40.1,
    diskReadKbps: 185.0,
    diskWriteKbps: 72.0,
  },
  {
    pid: 8112,
    name: "Code.exe",
    exePath: "C:\\Users\\Wallace\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    cpuPercent: 18.4,
    memoryMb: 2340.0,
    memoryPercent: 14.6,
    diskReadKbps: 92.0,
    diskWriteKbps: 44.0,
  },
  {
    pid: 3180,
    name: "MsMpEng.exe",
    exePath: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
    cpuPercent: 24.6,
    memoryMb: 680.0,
    memoryPercent: 4.3,
    diskReadKbps: 14200.0,
    diskWriteKbps: 1800.0,
  },
  {
    pid: 5510,
    name: "rust-analyzer.exe",
    exePath: "C:\\Users\\Wallace\\.cargo\\bin\\rust-analyzer.exe",
    cpuPercent: 14.2,
    memoryMb: 1890.0,
    memoryPercent: 11.8,
    diskReadKbps: 410.0,
    diskWriteKbps: 95.0,
  },
  {
    pid: 1492,
    name: "svchost.exe",
    exePath: "C:\\Windows\\System32\\svchost.exe",
    cpuPercent: 4.1,
    memoryMb: 420.0,
    memoryPercent: 2.6,
    diskReadKbps: 310.0,
    diskWriteKbps: 120.0,
  },
];

export class DemoTransport implements SentinelTransport {
  readonly mode = "demo" as const;
  private handlers: TransportEventHandlers | null = null;
  private timerId: number | null = null;
  private tickCount = 0;
  private paused = false;
  private uptimeSecs = 1842;
  private remoteEnabled = true;
  private remotePin = "482910";
  private historyImported = false;

  private readonly kb: KnowledgeBaseEntry[] = loadKnowledgeBaseEntries();
  private telemetry: TelemetrySample[] = [];
  private snapshots: BottleneckSnapshot[] = [];
  private events: WindowsEventRecord[] = [];
  private nextSnapshotId = 510;
  private nextEventId = 90;

  constructor() {
    this.seedInitialData();
  }

  private findKb(id: string): KnowledgeBaseEntry {
    return (
      this.kb.find((entry) => entry.id === id) ?? {
        id,
        category: "Sistema",
        logName: "System",
        sources: ["System"],
        eventId: 1000,
        severity: "high",
        friendlyTitle: "Evento de sistema registrado",
        whatHappened: "O Windows registrou um evento técnico no log.",
        probableCauses: ["Carga elevada momentânea no sistema."],
        solutions: ["Verifique a correlação na linha do tempo."],
      }
    );
  }

  private seedInitialData(): void {
    const now = Date.now();
    // 60 seconds of realistic telemetry with a Disk + RAM spike around -20s
    for (let i = 59; i >= 0; i--) {
      const ts = now - i * 1000;
      const inSpike = i >= 17 && i <= 23;
      const cpu = inSpike
        ? 88 + Math.sin(i) * 6
        : 24 + Math.sin(i * 0.35) * 9 + (i % 5);
      const ram = inSpike ? 93.4 : 62 + Math.cos(i * 0.15) * 4;
      const disk = inSpike ? 97.2 : 12 + Math.abs(Math.sin(i * 0.4)) * 18;
      const diskLat = inSpike ? 138.5 : 4.2 + Math.abs(Math.cos(i * 0.3)) * 8;
      const netRx = 180 + Math.abs(Math.sin(i * 0.5)) * 420;
      const netTx = 48 + Math.abs(Math.cos(i * 0.4)) * 90;

      this.telemetry.push({
        timestampUtc: new Date(ts).toISOString(),
        timestampMs: ts,
        cpuPercent: Number(Math.min(99, Math.max(4, cpu)).toFixed(1)),
        ramPercent: Number(Math.min(98, Math.max(20, ram)).toFixed(1)),
        ramUsedGb: Number(((ram / 100) * 16).toFixed(2)),
        ramFreeGb: Number((16 - (ram / 100) * 16).toFixed(2)),
        ramTotalGb: 16,
        diskActivePercent: Number(Math.min(100, disk).toFixed(1)),
        diskLatencyMs: Number(diskLat.toFixed(1)),
        netRxKbps: Number(netRx.toFixed(1)),
        netTxKbps: Number(netTx.toFixed(1)),
        netLatencyMs: inSpike ? 42 : 14,
        netLossPercent: 0,
        healthStatus: inSpike ? "critical" : "stable",
      });
    }

    const snap1Ts = now - 20_000;
    const snap2Ts = now - 185_000;

    const snap1: BottleneckSnapshot = {
      id: 501,
      timestampUtc: new Date(snap1Ts).toISOString(),
      timestampMs: snap1Ts,
      violatedMetric: "disk_latency",
      peakValue: 138.5,
      thresholdValue: 100.0,
      durationSecs: 6,
      cpuPercent: 91.4,
      ramPercent: 93.4,
      ramFreeGb: 1.05,
      diskActivePercent: 97.2,
      diskLatencyMs: 138.5,
      netRxKbps: 540.0,
      netTxKbps: 112.0,
      netLatencyMs: 42.0,
      netLossPercent: 0.0,
      topProcesses: DEMO_PROCESSES,
      severity: "critical",
    };

    const snap2: BottleneckSnapshot = {
      id: 502,
      timestampUtc: new Date(snap2Ts).toISOString(),
      timestampMs: snap2Ts,
      violatedMetric: "cpu",
      peakValue: 96.2,
      thresholdValue: 90.0,
      durationSecs: 5,
      cpuPercent: 96.2,
      ramPercent: 78.4,
      ramFreeGb: 3.45,
      diskActivePercent: 42.0,
      diskLatencyMs: 14.2,
      netRxKbps: 220.0,
      netTxKbps: 55.0,
      netLatencyMs: 16.0,
      netLossPercent: 0.0,
      topProcesses: DEMO_PROCESSES,
      severity: "high",
    };

    this.snapshots = [snap1, snap2];

    const kbApp1002 = this.findKb("APP_1002");
    const kbDisk153 = this.findKb("DISK_153");
    const kbNet1014 = this.findKb("NET_1014");
    const kbApp1000 = this.findKb("APP_1000");
    const kbSys41 = this.findKb("SYS_41");

    this.events = [
      {
        id: 77,
        recordId: 9012,
        channel: kbApp1002.logName,
        providerName: kbApp1002.sources[0] ?? "Application Hang",
        eventId: kbApp1002.eventId,
        level: 2,
        timestampUtc: new Date(snap1Ts + 3000).toISOString(),
        timestampMs: snap1Ts + 3000,
        kbId: kbApp1002.id,
        category: kbApp1002.category,
        severity: "critical",
        friendlyTitle: kbApp1002.friendlyTitle,
        whatHappened: kbApp1002.whatHappened,
        probableCauses: kbApp1002.probableCauses,
        solutions: kbApp1002.solutions,
        rawXml:
          '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Application Hang"/><EventID>1002</EventID><EventRecordID>9012</EventRecordID></System><EventData><Data>Code.exe</Data><Data>1.98.2.0</Data></EventData></Event>',
        correlationSnapshotId: 501,
        diagnosticNote:
          "3 segundos antes deste evento (ID 1002), a Caixa-Preta registrou pico de 138.5ms de latência de disco e 93.4% de RAM (principal ofensor: chrome.exe / MsMpEng.exe).",
      },
      {
        id: 78,
        recordId: 9010,
        channel: kbDisk153.logName,
        providerName: kbDisk153.sources[0] ?? "disk",
        eventId: kbDisk153.eventId,
        level: 3,
        timestampUtc: new Date(snap1Ts - 2000).toISOString(),
        timestampMs: snap1Ts - 2000,
        kbId: kbDisk153.id,
        category: kbDisk153.category,
        severity: kbDisk153.severity,
        friendlyTitle: kbDisk153.friendlyTitle,
        whatHappened: kbDisk153.whatHappened,
        probableCauses: kbDisk153.probableCauses,
        solutions: kbDisk153.solutions,
        rawXml:
          '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="disk"/><EventID>153</EventID><EventRecordID>9010</EventRecordID></System><EventData><Data>\\Device\\Harddisk0\\DR0</Data></EventData></Event>',
        correlationSnapshotId: 501,
        diagnosticNote:
          "Correlacionado ao gargalo sustentado de Disco (97.2% ativo · 138.5ms) capturado na janela [T - 15s, T + 5s].",
      },
      {
        id: 79,
        recordId: 8994,
        channel: kbApp1000.logName,
        providerName: kbApp1000.sources[0] ?? "Application Error",
        eventId: kbApp1000.eventId,
        level: 2,
        timestampUtc: new Date(snap2Ts + 4000).toISOString(),
        timestampMs: snap2Ts + 4000,
        kbId: kbApp1000.id,
        category: kbApp1000.category,
        severity: kbApp1000.severity,
        friendlyTitle: kbApp1000.friendlyTitle,
        whatHappened: kbApp1000.whatHappened,
        probableCauses: kbApp1000.probableCauses,
        solutions: kbApp1000.solutions,
        rawXml:
          '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Application Error"/><EventID>1000</EventID><EventRecordID>8994</EventRecordID></System><EventData><Data>mspaint.exe</Data><Data>ucrtbase.dll</Data><Data>c0000409</Data></EventData></Event>',
        correlationSnapshotId: 502,
        diagnosticNote:
          "4 segundos após pico de CPU de 96.2% (snapshot #502).",
      },
      {
        id: 80,
        recordId: 8941,
        channel: kbNet1014.logName,
        providerName: kbNet1014.sources[0] ?? "Microsoft-Windows-DNS-Client",
        eventId: kbNet1014.eventId,
        level: 3,
        timestampUtc: new Date(now - 420_000).toISOString(),
        timestampMs: now - 420_000,
        kbId: kbNet1014.id,
        category: kbNet1014.category,
        severity: kbNet1014.severity,
        friendlyTitle: kbNet1014.friendlyTitle,
        whatHappened: kbNet1014.whatHappened,
        probableCauses: kbNet1014.probableCauses,
        solutions: kbNet1014.solutions,
        rawXml:
          '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-DNS-Client"/><EventID>1014</EventID><EventRecordID>8941</EventRecordID></System><EventData><Data>api.github.com</Data></EventData></Event>',
        correlationSnapshotId: null,
        diagnosticNote: null,
      },
      {
        id: 81,
        recordId: 8810,
        channel: kbSys41.logName,
        providerName: kbSys41.sources[0] ?? "Microsoft-Windows-Kernel-Power",
        eventId: kbSys41.eventId,
        level: 1,
        timestampUtc: new Date(now - 3_600_000).toISOString(),
        timestampMs: now - 3_600_000,
        kbId: kbSys41.id,
        category: kbSys41.category,
        severity: kbSys41.severity,
        friendlyTitle: kbSys41.friendlyTitle,
        whatHappened: kbSys41.whatHappened,
        probableCauses: kbSys41.probableCauses,
        solutions: kbSys41.solutions,
        rawXml:
          '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>41</EventID><EventRecordID>8810</EventRecordID></System></Event>',
        correlationSnapshotId: null,
        diagnosticNote: null,
      },
    ];
  }

  async connect(handlers: TransportEventHandlers): Promise<void> {
    this.handlers = handlers;
    handlers.onConnectionStateChange("connected");
    handlers.onStatus(this.buildStatus());

    if (this.timerId !== null) {
      window.clearInterval(this.timerId);
    }

    this.timerId = window.setInterval(() => {
      this.uptimeSecs += 1;
      if (this.paused || !this.handlers) {
        return;
      }
      this.tickCount += 1;
      const now = Date.now();
      const simulatedSpike = this.tickCount % 25 >= 20;
      const cpu = simulatedSpike
        ? 91.5 + Math.random() * 6
        : 22 + Math.sin(this.tickCount * 0.4) * 12 + Math.random() * 6;
      const ram = simulatedSpike
        ? 86 + Math.random() * 6
        : 61 + Math.cos(this.tickCount * 0.2) * 5;
      const disk = simulatedSpike
        ? 88 + Math.random() * 10
        : 10 + Math.abs(Math.sin(this.tickCount * 0.3)) * 18;
      const diskLat = simulatedSpike ? 64 + Math.random() * 45 : 4 + Math.random() * 7;

      const sample: TelemetrySample = {
        timestampUtc: new Date(now).toISOString(),
        timestampMs: now,
        cpuPercent: Number(Math.min(99.4, cpu).toFixed(1)),
        ramPercent: Number(Math.min(97.5, ram).toFixed(1)),
        ramUsedGb: Number(((ram / 100) * 16).toFixed(2)),
        ramFreeGb: Number((16 - (ram / 100) * 16).toFixed(2)),
        ramTotalGb: 16,
        diskActivePercent: Number(Math.min(100, disk).toFixed(1)),
        diskLatencyMs: Number(diskLat.toFixed(1)),
        netRxKbps: Number((140 + Math.random() * 380).toFixed(1)),
        netTxKbps: Number((40 + Math.random() * 90).toFixed(1)),
        netLatencyMs: simulatedSpike ? 36 : 13,
        netLossPercent: 0,
        healthStatus: cpu > 90 ? "critical" : cpu > 75 ? "warning" : "stable",
      };

      this.telemetry.push(sample);
      if (this.telemetry.length > 120) {
        this.telemetry.shift();
      }
      this.handlers.onTelemetry(sample);

      // On tick 24 of each cycle, emit a live BottleneckSnapshot so recruiters see real-time alerts
      if (this.tickCount % 25 === 24) {
        const snapId = this.nextSnapshotId++;
        const snap: BottleneckSnapshot = {
          id: snapId,
          timestampUtc: sample.timestampUtc,
          timestampMs: sample.timestampMs,
          violatedMetric: "cpu",
          peakValue: sample.cpuPercent,
          thresholdValue: 90.0,
          durationSecs: 5,
          cpuPercent: sample.cpuPercent,
          ramPercent: sample.ramPercent,
          ramFreeGb: sample.ramFreeGb,
          diskActivePercent: sample.diskActivePercent,
          diskLatencyMs: sample.diskLatencyMs,
          netRxKbps: sample.netRxKbps,
          netTxKbps: sample.netTxKbps,
          netLatencyMs: sample.netLatencyMs,
          netLossPercent: sample.netLossPercent,
          topProcesses: DEMO_PROCESSES,
          severity: "high",
        };
        this.snapshots.unshift(snap);
        this.handlers.onSnapshot(snap);
      }
    }, 1000);
  }

  disconnect(): void {
    if (this.timerId !== null) {
      window.clearInterval(this.timerId);
      this.timerId = null;
    }
    this.handlers?.onConnectionStateChange("disconnected");
  }

  async authenticateWithPin(_pin: string, _serverUrl?: string): Promise<void> {
    this.handlers?.onConnectionStateChange("connected");
  }

  continueOffline(): boolean {
    this.handlers?.onConnectionStateChange("connected");
    return true;
  }

  getServerUrl(): string {
    return "demo://winpulse-sentinel-sandbox";
  }

  hasOfflineCache(): boolean {
    return true;
  }

  private buildStatus(): CollectorStatus {
    const latest = this.telemetry[this.telemetry.length - 1];
    return {
      paused: this.paused,
      uptimeSecs: this.uptimeSecs,
      ringBufferLen: this.telemetry.length,
      eventWatcherActive: !this.paused,
      isElevated: true,
      healthStatus: latest?.healthStatus ?? "stable",
    };
  }

  async getCollectorStatus(): Promise<CollectorStatus> {
    return this.buildStatus();
  }

  async getRecentTelemetry(): Promise<TelemetrySample[]> {
    return [...this.telemetry];
  }

  async getTimeline(params?: TimelineQueryParams): Promise<TimelineItem[]> {
    const items: TimelineItem[] = [
      ...this.events.map(timelineItemFromEvent),
      ...this.snapshots.map(timelineItemFromSnapshot),
    ].sort((a, b) => b.timestampMs - a.timestampMs);

    const filtered = items.filter((item) => {
      if (params?.category && item.category !== params.category) return false;
      if (params?.severity && item.severity !== params.severity) return false;
      return true;
    });

    const offset = params?.offset ?? 0;
    const limit = params?.limit ?? 200;
    return filtered.slice(offset, offset + limit);
  }

  async getIncidentDetail(
    itemType: TimelineItemType,
    id: number,
  ): Promise<IncidentDetail> {
    if (itemType === "event") {
      const event = this.events.find((e) => e.id === id) ?? null;
      const correlatedSnapshots = event
        ? this.snapshots.filter(
            (s) =>
              s.id === event.correlationSnapshotId ||
              (s.timestampMs >= event.timestampMs - 15_000 &&
                s.timestampMs <= event.timestampMs + 5_000),
          )
        : [];
      return {
        itemType: "event",
        event,
        snapshot: null,
        correlatedSnapshots,
        correlatedEvents: [],
        diagnosticNote: event?.diagnosticNote ?? null,
      };
    }

    const snapshot = this.snapshots.find((s) => s.id === id) ?? null;
    const correlatedEvents = snapshot
      ? this.events.filter(
          (e) =>
            e.correlationSnapshotId === snapshot.id ||
            (e.timestampMs >= snapshot.timestampMs - 15_000 &&
              e.timestampMs <= snapshot.timestampMs + 5_000),
        )
      : [];
    return {
      itemType: "snapshot",
      event: null,
      snapshot,
      correlatedSnapshots: [],
      correlatedEvents,
      diagnosticNote:
        correlatedEvents[0]?.diagnosticNote ??
        "Gargalo sustentado capturado pela Caixa-Preta em memória.",
    };
  }

  async getKnowledgeBase(): Promise<KnowledgeBaseEntry[]> {
    return this.kb;
  }

  async importWindowsHistory(days = 7): Promise<ImportHistoryResult> {
    if (this.historyImported) {
      return { scanned: 42, imported: 0, skippedDuplicates: 42, days };
    }
    this.historyImported = true;
    const extraKb = this.kb[Math.min(4, this.kb.length - 1)] ?? this.findKb("APP_1000");
    const ts = Date.now() - 86_400_000;
    const ev: WindowsEventRecord = {
      id: this.nextEventId++,
      recordId: 8420,
      channel: extraKb.logName,
      providerName: extraKb.sources[0] ?? "System",
      eventId: extraKb.eventId,
      level: 2,
      timestampUtc: new Date(ts).toISOString(),
      timestampMs: ts,
      kbId: extraKb.id,
      category: extraKb.category,
      severity: extraKb.severity,
      friendlyTitle: extraKb.friendlyTitle,
      whatHappened: extraKb.whatHappened,
      probableCauses: extraKb.probableCauses,
      solutions: extraKb.solutions,
      rawXml: `<Event><System><EventID>${extraKb.eventId}</EventID></System></Event>`,
      correlationSnapshotId: null,
      diagnosticNote: null,
    };
    this.events.push(ev);
    this.handlers?.onWindowsEvent(ev);
    const result = { scanned: 42, imported: 1, skippedDuplicates: 41, days };
    this.handlers?.onHistoryImported?.(result);
    return result;
  }

  async setCollectionPaused(paused: boolean): Promise<CollectorStatus> {
    this.paused = paused;
    const status = this.buildStatus();
    this.handlers?.onStatus(status);
    return status;
  }

  async getRemoteServerStatus(): Promise<RemoteServerStatus> {
    return {
      enabled: this.remoteEnabled,
      port: 8420,
      pin: this.remotePin,
      lanUrls: ["http://192.168.1.42:8420"],
      activeClients: 1,
    };
  }

  async toggleRemoteServer(
    enabled: boolean,
    _port?: number,
  ): Promise<RemoteServerStatus> {
    this.remoteEnabled = enabled;
    return this.getRemoteServerStatus();
  }

  async regenerateRemotePin(): Promise<RemoteServerStatus> {
    this.remotePin = String(Math.floor(100000 + Math.random() * 900000));
    return this.getRemoteServerStatus();
  }
}
