import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createTransport,
  timelineItemFromEvent,
  timelineItemFromSnapshot,
  type ConnectionState,
  type SentinelTransport,
  type TransportMode,
} from "../transport";
import type {
  AiDiagnosisResponse,
  AiSettings,
  BottleneckSnapshot,
  CollectorStatus,
  CommandAuditEntry,
  CommandAuditStatus,
  CommandExecutionResult,
  CommandShell,
  CommandSource,
  DiagnoseRequest,
  IncidentDetail,
  IncidentFacetCounts,
  IncidentFilterQuery,
  KnowledgeBaseEntry,
  McpServerStatus,
  OllamaProbeResult,
  RemoteServerStatus,
  SaveAiSettingsInput,
  Severity,
  StagedCommandTicket,
  TelemetrySample,
  TimelineItem,
  TimelineItemType,
  WindowsEventRecord,
} from "../types/sentinel";
import {
  createIncidentSearchEngine,
  initSentinelWasm,
  type IncidentSearchEngine,
} from "../wasm/sentinelWasm";

const MAX_TELEMETRY_POINTS = 120;
const TOAST_TTL_MS = 8000;

export interface AlertToast {
  id: string;
  title: string;
  body: string;
  severity: Severity;
  createdAtMs: number;
  targetItem?: TimelineItem;
}

const DEFAULT_FILTER: IncidentFilterQuery = {
  query: "",
  categories: [],
  severities: [],
  itemTypes: [],
  onlyCorrelated: false,
};

const EMPTY_FACETS: IncidentFacetCounts = {
  total: 0,
  byCategory: {},
  bySeverity: {},
};

function enrichWithOfflineCorrelation(
  items: TimelineItem[],
  engine: IncidentSearchEngine | null,
): TimelineItem[] {
  if (!engine || items.length === 0) {
    return items;
  }
  const matches = engine.correlateOffline(15_000, 5_000);
  if (matches.length === 0) {
    return items;
  }
  const byEventUid = new Map(matches.map((m) => [m.eventUid, m]));
  const matchedSnapUids = new Set(matches.map((m) => m.snapshotUid));

  return items.map((item) => {
    if (item.itemType === "event" && !item.hasCorrelation) {
      const match = byEventUid.get(item.uid);
      if (match) {
        return {
          ...item,
          hasCorrelation: true,
          diagnosticNote: item.diagnosticNote ?? match.diagnosticNote,
        };
      }
    }
    if (item.itemType === "snapshot" && !item.hasCorrelation) {
      if (matchedSnapUids.has(item.uid)) {
        return { ...item, hasCorrelation: true };
      }
    }
    return item;
  });
}

function fallbackFilter(
  items: TimelineItem[],
  filter: IncidentFilterQuery,
): TimelineItem[] {
  const q = filter.query.trim().toLowerCase();
  return items.filter((item) => {
    if (filter.onlyCorrelated && !item.hasCorrelation) return false;
    if (
      filter.categories.length > 0 &&
      !filter.categories.includes(item.category)
    ) {
      return false;
    }
    if (
      filter.severities.length > 0 &&
      !filter.severities.includes(item.severity)
    ) {
      return false;
    }
    if (
      filter.itemTypes.length > 0 &&
      !filter.itemTypes.includes(item.itemType)
    ) {
      return false;
    }
    if (q.length > 0) {
      const hay =
        `${item.title} ${item.summary} ${item.category} ${item.providerName ?? ""} ${item.eventId ?? ""} ${item.detailsText ?? ""}`.toLowerCase();
      return q.split(/\s+/).every((tok) => hay.includes(tok));
    }
    return true;
  });
}

export function useSentinelStore() {
  const transportRef = useRef<SentinelTransport | null>(null);
  if (!transportRef.current) {
    transportRef.current = createTransport();
  }
  const transport = transportRef.current;

  const engineRef = useRef<IncidentSearchEngine | null>(null);

  const [wasmReady, setWasmReady] = useState(false);
  const [connectionState, setConnectionState] =
    useState<ConnectionState>("connecting");
  const [collectorStatus, setCollectorStatus] =
    useState<CollectorStatus | null>(null);
  const [remoteStatus, setRemoteStatus] = useState<RemoteServerStatus | null>(
    null,
  );
  const [telemetryHistory, setTelemetryHistory] = useState<TelemetrySample[]>(
    [],
  );
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [filter, setFilter] = useState<IncidentFilterQuery>(DEFAULT_FILTER);
  const [facetCounts, setFacetCounts] =
    useState<IncidentFacetCounts>(EMPTY_FACETS);

  const [selectedItem, setSelectedItem] = useState<TimelineItem | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<IncidentDetail | null>(
    null,
  );
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [authError, setAuthError] = useState<string | null>(null);
  const [authBusy, setAuthBusy] = useState(false);
  const [remoteModalOpen, setRemoteModalOpen] = useState(false);
  const [remoteActionError, setRemoteActionError] = useState<string | null>(
    null,
  );
  const [toasts, setToasts] = useState<AlertToast[]>([]);
  const [timelineRevision, setTimelineRevision] = useState(0);
  const [knowledgeBase, setKnowledgeBase] = useState<KnowledgeBaseEntry[]>([]);
  const [importingHistory, setImportingHistory] = useState(false);
  const [lastImportMessage, setLastImportMessage] = useState<string | null>(
    null,
  );

  const [aiModalOpen, setAiModalOpen] = useState(false);
  const [aiSettings, setAiSettings] = useState<AiSettings | null>(null);
  const [ollamaProbe, setOllamaProbe] = useState<OllamaProbeResult | null>(null);
  const [mcpStatus, setMcpStatus] = useState<McpServerStatus | null>(null);
  const [auditLog, setAuditLog] = useState<CommandAuditEntry[]>([]);
  const [aiBusy, setAiBusy] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiQuotaExhausted, setAiQuotaExhausted] = useState(false);
  const [aiDiagnosis, setAiDiagnosis] = useState<AiDiagnosisResponse | null>(null);
  const [sanitizedPreview, setSanitizedPreview] = useState<DiagnoseRequest | null>(null);

  const [activeTicket, setActiveTicket] = useState<StagedCommandTicket | null>(null);
  const [commandStatus, setCommandStatus] = useState<CommandAuditStatus | null>(null);
  const [commandOutput, setCommandOutput] = useState("");
  const [commandBusy, setCommandBusy] = useState(false);
  const [commandResult, setCommandResult] = useState<CommandExecutionResult | null>(null);
  const [commandError, setCommandError] = useState<string | null>(null);
  const activeTicketIdRef = useRef<string | null>(null);
  activeTicketIdRef.current = activeTicket?.approvalId ?? null;

  const pushToast = useCallback(
    (title: string, body: string, severity: Severity, targetItem?: TimelineItem) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const toast: AlertToast = {
        id,
        title,
        body,
        severity,
        createdAtMs: Date.now(),
        targetItem,
      };
      setToasts((prev) => [toast, ...prev].slice(0, 4));
      window.setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, TOAST_TTL_MS);
    },
    [],
  );

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const syncEngineWithItems = useCallback((rawItems: TimelineItem[]) => {
    const engine = engineRef.current;
    if (!engine) {
      setTimeline(rawItems);
      return;
    }
    engine.load(rawItems);
    const enriched = enrichWithOfflineCorrelation(rawItems, engine);
    if (enriched !== rawItems) {
      engine.load(enriched);
    }
    setFacetCounts(engine.facetCounts());
    setTimeline(enriched);
    setTimelineRevision((r) => r + 1);
  }, []);

  const hydrateData = useCallback(async () => {
    try {
      const [status, recent, items, kb] = await Promise.all([
        transport.getCollectorStatus(),
        transport.getRecentTelemetry(),
        transport.getTimeline({ limit: 400 }),
        transport.getKnowledgeBase().catch(() => [] as KnowledgeBaseEntry[]),
      ]);
      setCollectorStatus(status);
      if (kb.length > 0) {
        setKnowledgeBase(kb);
      }
      setTelemetryHistory((prev) => {
        const byTs = new Map<number, TelemetrySample>();
        for (const s of recent) byTs.set(s.timestampMs, s);
        for (const s of prev) byTs.set(s.timestampMs, s);
        return Array.from(byTs.values())
          .sort((a, b) => a.timestampMs - b.timestampMs)
          .slice(-MAX_TELEMETRY_POINTS);
      });
      setTimeline((prev) => {
        const byUid = new Map<string, TimelineItem>();
        for (const item of items) byUid.set(item.uid, item);
        for (const item of prev) byUid.set(item.uid, item);
        const merged = Array.from(byUid.values()).sort(
          (a, b) => b.timestampMs - a.timestampMs,
        );
        const engine = engineRef.current;
        if (!engine) {
          return merged;
        }
        engine.load(merged);
        const enriched = enrichWithOfflineCorrelation(merged, engine);
        if (enriched !== merged) {
          engine.load(enriched);
        }
        setFacetCounts(engine.facetCounts());
        setTimelineRevision((r) => r + 1);
        return enriched;
      });

      if (transport.mode === "tauri") {
        const remote = await transport.getRemoteServerStatus();
        setRemoteStatus(remote);
      }
      if (transport.supportsExecution) {
        const [aiCfg, mcp, audit, ollama] = await Promise.all([
          transport.getAiSettings().catch(() => null),
          transport.getMcpStatus().catch(() => null),
          transport.getCommandAuditLog(30).catch(() => [] as CommandAuditEntry[]),
          transport.probeOllama().catch(() => null),
        ]);
        if (aiCfg) setAiSettings(aiCfg);
        if (mcp) setMcpStatus(mcp);
        setAuditLog(audit);
        if (ollama) setOllamaProbe(ollama);
      }
    } catch {
      // Handled by connectionState or auth_required flow.
    }
  }, [transport]);

  // Initialize WebAssembly once
  useEffect(() => {
    let cancelled = false;
    void initSentinelWasm()
      .then(() => {
        if (cancelled) return;
        engineRef.current = createIncidentSearchEngine();
        setWasmReady(true);
      })
      .catch(() => {
        if (!cancelled) {
          setWasmReady(false);
        }
      });

    return () => {
      cancelled = true;
      engineRef.current?.dispose();
      engineRef.current = null;
    };
  }, []);

  // Re-index existing timeline when Wasm becomes ready
  useEffect(() => {
    if (wasmReady && timeline.length > 0 && engineRef.current) {
      syncEngineWithItems(timeline);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wasmReady]);

  // Connect transport & subscribe to real-time streams
  useEffect(() => {
    void transport.connect({
      onConnectionStateChange: (nextState) => {
        setConnectionState(nextState);
        if (nextState === "connected" || nextState === "offline") {
          void hydrateData();
        }
      },
      onTelemetry: (sample) => {
        setTelemetryHistory((prev) => {
          if (
            prev.length > 0 &&
            prev[prev.length - 1]?.timestampMs === sample.timestampMs
          ) {
            return prev;
          }
          return [...prev, sample].slice(-MAX_TELEMETRY_POINTS);
        });
        setCollectorStatus((prev) =>
          prev
            ? {
                ...prev,
                healthStatus: sample.healthStatus,
                ringBufferLen: Math.min(prev.ringBufferLen + 1, 60),
              }
            : prev,
        );
      },
      onSnapshot: (snap: BottleneckSnapshot) => {
        const item = timelineItemFromSnapshot(snap);
        setTimeline((prev) => {
          const merged = [item, ...prev.filter((x) => x.uid !== item.uid)];
          merged.sort((a, b) => b.timestampMs - a.timestampMs);
          if (engineRef.current) {
            engineRef.current.load(merged);
            const enriched = enrichWithOfflineCorrelation(
              merged,
              engineRef.current,
            );
            engineRef.current.load(enriched);
            setFacetCounts(engineRef.current.facetCounts());
            setTimelineRevision((r) => r + 1);
            return enriched;
          }
          return merged;
        });

        if (snap.severity === "critical") {
          pushToast(
            `Gargalo Crítico — ${item.category}`,
            item.title,
            "critical",
            item,
          );
        }
      },
      onWindowsEvent: (ev: WindowsEventRecord) => {
        const item = timelineItemFromEvent(ev);
        setTimeline((prev) => {
          const merged = [item, ...prev.filter((x) => x.uid !== item.uid)];
          merged.sort((a, b) => b.timestampMs - a.timestampMs);
          if (engineRef.current) {
            engineRef.current.load(merged);
            const enriched = enrichWithOfflineCorrelation(
              merged,
              engineRef.current,
            );
            engineRef.current.load(enriched);
            setFacetCounts(engineRef.current.facetCounts());
            setTimelineRevision((r) => r + 1);
            return enriched;
          }
          return merged;
        });

        if (ev.severity === "critical") {
          pushToast(
            `Evento Crítico (ID ${ev.eventId})`,
            ev.friendlyTitle,
            "critical",
            item,
          );
        }
      },
      onStatus: (status) => {
        setCollectorStatus(status);
      },
      onRemoteStatus: (remote) => {
        setRemoteStatus(remote);
      },
      onHistoryImported: (res) => {
        if (res.imported > 0) {
          setLastImportMessage(
            `Importados ${res.imported} eventos dos últimos ${res.days} dias do Windows Event Log.`,
          );
          void hydrateData();
        }
      },
      onApprovalRequested: (ticket) => {
        setActiveTicket(ticket);
        setCommandStatus("pending");
        setCommandOutput("");
        setCommandResult(null);
        setCommandError(null);
        setCommandBusy(false);
      },
      onCommandOutput: (ev) => {
        if (activeTicketIdRef.current && ev.approvalId !== activeTicketIdRef.current) {
          return;
        }
        if (ev.chunk) {
          setCommandOutput((prev) => prev + ev.chunk);
        }
        if (ev.finished) {
          setCommandStatus(ev.status);
        }
      },
    });

    return () => {
      transport.disconnect();
    };
  }, [hydrateData, pushToast, transport]);

  const filteredTimeline = useMemo(() => {
    const engine = engineRef.current;
    if (wasmReady && engine && engine.size() > 0) {
      const uids = engine.searchUids(filter);
      const byUid = new Map(timeline.map((item) => [item.uid, item]));
      const ordered: TimelineItem[] = [];
      for (const uid of uids) {
        const hit = byUid.get(uid);
        if (hit) {
          ordered.push(hit);
        }
      }
      return ordered;
    }
    return fallbackFilter(timeline, filter);
    // timelineRevision triggers memo refresh after in-place engine load/upsert
  }, [filter, timeline, timelineRevision, wasmReady]);

  const openIncident = useCallback(
    async (item: TimelineItem) => {
      setSelectedItem(item);
      setDetailLoading(true);
      setDetailError(null);
      setSelectedDetail(null);
      setAiDiagnosis(null);
      setAiError(null);
      setAiQuotaExhausted(false);
      setSanitizedPreview(null);

      try {
        const detail = await transport.getIncidentDetail(
          item.itemType,
          item.sourceId,
        );
        // Apply client correlation note if backend record lacks one
        if (!detail.diagnosticNote && item.diagnosticNote) {
          setSelectedDetail({
            ...detail,
            diagnosticNote: item.diagnosticNote,
          });
        } else {
          setSelectedDetail(detail);
        }
      } catch (err) {
        setDetailError(
          err instanceof Error
            ? err.message
            : "Não foi possível carregar os detalhes completos.",
        );
      } finally {
        setDetailLoading(false);
      }
    },
    [transport],
  );

  const closeDrawer = useCallback(() => {
    setSelectedItem(null);
    setSelectedDetail(null);
    setDetailError(null);
    setAiDiagnosis(null);
    setAiError(null);
    setAiQuotaExhausted(false);
    setSanitizedPreview(null);
  }, []);

  const refreshAiContext = useCallback(async () => {
    if (!transport.supportsExecution) return;
    const [aiCfg, mcp, audit, ollama] = await Promise.all([
      transport.getAiSettings().catch(() => null),
      transport.getMcpStatus().catch(() => null),
      transport.getCommandAuditLog(30).catch(() => [] as CommandAuditEntry[]),
      transport.probeOllama().catch(() => null),
    ]);
    if (aiCfg) setAiSettings(aiCfg);
    if (mcp) setMcpStatus(mcp);
    setAuditLog(audit);
    if (ollama) setOllamaProbe(ollama);
  }, [transport]);

  const saveAiSettings = useCallback(
    async (input: SaveAiSettingsInput) => {
      const updated = await transport.saveAiSettings(input);
      setAiSettings(updated);
      return updated;
    },
    [transport],
  );

  const saveByokApiKey = useCallback(
    async (apiKey: string) => {
      const updated = await transport.setByokApiKey(apiKey);
      setAiSettings(updated);
      return updated;
    },
    [transport],
  );

  const clearByokApiKey = useCallback(async () => {
    const updated = await transport.clearByokApiKey();
    setAiSettings(updated);
    return updated;
  }, [transport]);

  const refreshOllamaProbe = useCallback(
    async (baseUrl?: string) => {
      const res = await transport.probeOllama(baseUrl);
      setOllamaProbe(res);
      return res;
    },
    [transport],
  );

  const toggleMcpServer = useCallback(
    async (enabled: boolean, port?: number) => {
      const updated = await transport.toggleMcpServer(enabled, port);
      setMcpStatus(updated);
      return updated;
    },
    [transport],
  );

  const rotateMcpToken = useCallback(async () => {
    const updated = await transport.rotateMcpToken();
    setMcpStatus(updated);
    return updated;
  }, [transport]);

  const loadSanitizedPreview = useCallback(
    async (itemType: TimelineItemType, id: number) => {
      const preview = await transport.previewSanitizedIncident(itemType, id);
      setSanitizedPreview(preview);
      return preview;
    },
    [transport],
  );

  const analyzeSelectedIncident = useCallback(
    async (executionFeedback?: string) => {
      if (!selectedItem) return null;
      setAiBusy(true);
      setAiError(null);
      setAiQuotaExhausted(false);
      try {
        const res = await transport.analyzeIncidentWithAi(
          selectedItem.itemType,
          selectedItem.sourceId,
          executionFeedback,
        );
        setAiDiagnosis(res);
        return res;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setAiError(msg);
        if (
          msg.toLowerCase().includes("cota") ||
          msg.toLowerCase().includes("quota") ||
          msg.toLowerCase().includes("limite")
        ) {
          setAiQuotaExhausted(true);
        }
        return null;
      } finally {
        setAiBusy(false);
      }
    },
    [selectedItem, transport],
  );

  const analyzeErrorText = useCallback(
    async (errorText: string, executionFeedback?: string) => {
      return transport.analyzeErrorTextWithAi(errorText, executionFeedback);
    },
    [transport],
  );

  const requestCommandExecution = useCallback(
    async (params: {
      source: CommandSource;
      shell: CommandShell;
      command: string;
      rationale: string;
      requiresAdmin: boolean;
    }) => {
      setCommandError(null);
      setCommandResult(null);
      setCommandOutput("");
      const ticket = await transport.stageCommandExecution(params);
      setActiveTicket(ticket);
      setCommandStatus("pending");
      return ticket;
    },
    [transport],
  );

  const approveActiveCommand = useCallback(async () => {
    if (!activeTicket) return null;
    setCommandBusy(true);
    setCommandError(null);
    setCommandStatus("running");
    setCommandOutput("");
    try {
      const res = await transport.approveCommandExecution(
        activeTicket.approvalId,
        activeTicket.command,
      );
      setCommandResult(res);
      setCommandStatus(res.status);
      if (res.stdout && !commandOutput) {
        setCommandOutput(res.stdout + (res.stderr ? `\n${res.stderr}` : ""));
      }
      const log = await transport.getCommandAuditLog(30).catch(() => null);
      if (log) setAuditLog(log);
      return res;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setCommandError(msg);
      setCommandStatus("failed");
      return null;
    } finally {
      setCommandBusy(false);
    }
  }, [activeTicket, commandOutput, transport]);

  const rejectActiveCommand = useCallback(async () => {
    if (!activeTicket) return;
    await transport.rejectCommandExecution(activeTicket.approvalId).catch(() => {});
    setActiveTicket(null);
    setCommandStatus(null);
    setCommandOutput("");
    setCommandResult(null);
    setCommandError(null);
    const log = await transport.getCommandAuditLog(30).catch(() => null);
    if (log) setAuditLog(log);
  }, [activeTicket, transport]);

  const cancelActiveCommand = useCallback(async () => {
    if (!activeTicket) return;
    await transport.cancelCommandExecution(activeTicket.approvalId).catch(() => {});
  }, [activeTicket, transport]);

  const closeCommandModal = useCallback(() => {
    if (commandBusy) return;
    if (activeTicket && commandStatus === "pending") {
      void transport.rejectCommandExecution(activeTicket.approvalId).catch(() => {});
    }
    setActiveTicket(null);
    setCommandStatus(null);
    setCommandOutput("");
    setCommandResult(null);
    setCommandError(null);
  }, [activeTicket, commandBusy, commandStatus, transport]);

  const authenticateWithPin = useCallback(
    async (pin: string, serverUrl?: string) => {
      setAuthBusy(true);
      setAuthError(null);
      try {
        await transport.authenticateWithPin(pin, serverUrl);
      } catch (err) {
        setAuthError(
          err instanceof Error ? err.message : "Falha na autenticação.",
        );
        throw err;
      } finally {
        setAuthBusy(false);
      }
    },
    [transport],
  );

  const continueOffline = useCallback(() => {
    setAuthError(null);
    return transport.continueOffline();
  }, [transport]);

  const togglePause = useCallback(async () => {
    if (!collectorStatus) return;
    const updated = await transport.setCollectionPaused(!collectorStatus.paused);
    setCollectorStatus(updated);
  }, [collectorStatus, transport]);

  const toggleRemoteServer = useCallback(
    async (enabled: boolean) => {
      setRemoteActionError(null);
      try {
        const status = await transport.toggleRemoteServer(enabled);
        setRemoteStatus(status);
      } catch (err) {
        setRemoteActionError(
          err instanceof Error ? err.message : "Falha ao alterar servidor LAN.",
        );
      }
    },
    [transport],
  );

  const regenerateRemotePin = useCallback(async () => {
    setRemoteActionError(null);
    try {
      const status = await transport.regenerateRemotePin();
      setRemoteStatus(status);
    } catch (err) {
      setRemoteActionError(
        err instanceof Error ? err.message : "Falha ao gerar novo PIN.",
      );
    }
  }, [transport]);

  const importHistory = useCallback(
    async (days = 30) => {
      setImportingHistory(true);
      setLastImportMessage(null);
      try {
        const res = await transport.importWindowsHistory(days);
        setLastImportMessage(
          res.imported > 0
            ? `Importados ${res.imported} novo(s) evento(s) dos últimos ${res.days} dias (${res.scanned} analisados).`
            : `Histórico dos últimos ${res.days} dias já está atualizado (${res.scanned} eventos verificados).`,
        );
        await hydrateData();
      } catch (err) {
        setLastImportMessage(
          err instanceof Error
            ? err.message
            : "Não foi possível importar o histórico do Windows.",
        );
      } finally {
        setImportingHistory(false);
      }
    },
    [hydrateData, transport],
  );

  const latestTelemetry =
    telemetryHistory.length > 0
      ? telemetryHistory[telemetryHistory.length - 1] ?? null
      : null;

  return {
    mode: transport.mode as TransportMode,
    wasmReady,
    connectionState,
    collectorStatus,
    remoteStatus,
    telemetryHistory,
    latestTelemetry,
    timeline,
    filteredTimeline,
    facetCounts,
    filter,
    setFilter,
    selectedItem,
    selectedDetail,
    detailLoading,
    detailError,
    openIncident,
    closeDrawer,
    refresh: hydrateData,
    togglePause,
    remoteModalOpen,
    setRemoteModalOpen,
    toggleRemoteServer,
    regenerateRemotePin,
    remoteActionError,
    authenticateWithPin,
    continueOffline,
    hasOfflineCache: transport.hasOfflineCache(),
    defaultServerUrl: transport.getServerUrl(),
    authError,
    authBusy,
    toasts,
    dismissToast,
    knowledgeBase,
    importingHistory,
    lastImportMessage,
    importHistory,
    supportsExecution: transport.supportsExecution,
    aiModalOpen,
    setAiModalOpen,
    aiSettings,
    ollamaProbe,
    mcpStatus,
    auditLog,
    aiBusy,
    aiError,
    aiQuotaExhausted,
    aiDiagnosis,
    sanitizedPreview,
    refreshAiContext,
    saveAiSettings,
    saveByokApiKey,
    clearByokApiKey,
    refreshOllamaProbe,
    toggleMcpServer,
    rotateMcpToken,
    loadSanitizedPreview,
    analyzeSelectedIncident,
    analyzeErrorText,
    activeTicket,
    commandStatus,
    commandOutput,
    commandBusy,
    commandResult,
    commandError,
    requestCommandExecution,
    approveActiveCommand,
    rejectActiveCommand,
    cancelActiveCommand,
    closeCommandModal,
  };
}
