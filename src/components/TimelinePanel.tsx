import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  AlertTriangle,
  Cpu,
  History,
  Link2,
  Loader2,
  Search,
  SlidersHorizontal,
  Terminal,
} from "lucide-react";
import type { TransportMode } from "../transport";
import type {
  IncidentFacetCounts,
  IncidentFilterQuery,
  Severity,
  TimelineItem,
} from "../types/sentinel";

interface TimelinePanelProps {
  mode: TransportMode;
  items: TimelineItem[];
  totalUnfilteredCount: number;
  facetCounts: IncidentFacetCounts;
  filter: IncidentFilterQuery;
  selectedUid: string | null;
  wasmReady: boolean;
  importingHistory: boolean;
  lastImportMessage: string | null;
  onImportHistory: (days: number) => void;
  onFilterChange: (next: IncidentFilterQuery) => void;
  onSelectItem: (item: TimelineItem) => void;
}

const SEVERITY_OPTIONS: Array<{ value: Severity; label: string }> = [
  { value: "critical", label: "Crítico" },
  { value: "high", label: "Alto" },
  { value: "medium", label: "Médio" },
];

function severityBadge(sev: Severity): { label: string; cls: string; rail: string } {
  switch (sev) {
    case "critical":
      return {
        label: "CRÍTICO",
        cls: "border-rose-500/40 bg-rose-500/15 text-rose-300",
        rail: "bg-rose-500",
      };
    case "high":
      return {
        label: "ALTO",
        cls: "border-amber-500/40 bg-amber-500/15 text-amber-300",
        rail: "bg-amber-400",
      };
    default:
      return {
        label: "MÉDIO",
        cls: "border-cyan-500/35 bg-cyan-500/10 text-cyan-300",
        rail: "bg-cyan-400",
      };
  }
}

function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("pt-BR", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function TimelinePanel({
  mode,
  items,
  totalUnfilteredCount,
  facetCounts,
  filter,
  selectedUid,
  wasmReady,
  importingHistory,
  lastImportMessage,
  onImportHistory,
  onFilterChange,
  onSelectItem,
}: TimelinePanelProps) {
  const scrollParentRef = useRef<HTMLDivElement | null>(null);

  const categories = useMemo(() => {
    return Object.keys(facetCounts.byCategory).sort((a, b) =>
      a.localeCompare(b, "pt-BR"),
    );
  }, [facetCounts.byCategory]);

  const rowVirtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => scrollParentRef.current,
    estimateSize: () => 96,
    overscan: 8,
    getItemKey: (index) => items[index]?.uid ?? index,
  });

  const toggleSeverity = (sev: Severity) => {
    const exists = filter.severities.includes(sev);
    onFilterChange({
      ...filter,
      severities: exists
        ? filter.severities.filter((s) => s !== sev)
        : [...filter.severities, sev],
    });
  };

  const toggleType = (itemType: "event" | "snapshot") => {
    const exists = filter.itemTypes.includes(itemType);
    onFilterChange({
      ...filter,
      itemTypes: exists
        ? filter.itemTypes.filter((t) => t !== itemType)
        : [...filter.itemTypes, itemType],
    });
  };

  return (
    <section
      aria-label="Linha do Tempo Unificada"
      className="flex flex-col rounded-xl border border-slate-800/80 bg-[#0b111e]"
    >
      <div className="border-b border-slate-800/80 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-slate-100">
              Linha do Tempo Unificada de Incidentes
            </h2>
            <p className="text-xs text-slate-400 tabular-nums">
              {items.length} de {totalUnfilteredCount} registro(s) exibido(s)
              {wasmReady ? " · Busca e correlação indexadas em WebAssembly" : ""}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {mode === "tauri" && (
              <button
                type="button"
                data-testid="import-history-btn"
                disabled={importingHistory}
                onClick={() => onImportHistory(30)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-xs font-medium text-cyan-200 transition hover:bg-cyan-500/20 disabled:opacity-50"
              >
                {importingHistory ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <History className="h-3.5 w-3.5" />
                )}
                <span>
                  {importingHistory ? "Importando..." : "Importar Histórico (30d)"}
                </span>
              </button>
            )}
            <button
              type="button"
              onClick={() => toggleType("event")}
              className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                filter.itemTypes.includes("event")
                  ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200"
                  : "border-slate-800 bg-slate-900/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              <Terminal className="h-3.5 w-3.5" />
              Logs Windows
            </button>
            <button
              type="button"
              onClick={() => toggleType("snapshot")}
              className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                filter.itemTypes.includes("snapshot")
                  ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200"
                  : "border-slate-800 bg-slate-900/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              <Cpu className="h-3.5 w-3.5" />
              Snapshots Caixa-Preta
            </button>
            <button
              type="button"
              onClick={() =>
                onFilterChange({
                  ...filter,
                  onlyCorrelated: !filter.onlyCorrelated,
                })
              }
              className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                filter.onlyCorrelated
                  ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-200"
                  : "border-slate-800 bg-slate-900/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              <Link2 className="h-3.5 w-3.5" />
              Correlacionados
            </button>
          </div>
        </div>

        <div className="mt-3 flex flex-col gap-2.5 lg:flex-row lg:items-center">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="search"
              data-testid="timeline-search"
              value={filter.query}
              onChange={(e) =>
                onFilterChange({ ...filter, query: e.target.value })
              }
              placeholder="Buscar por ID (1000, 1002, 129), programa (mspaint.exe), DLL (ucrtbase.dll) ou código (c0000409)..."
              className="w-full rounded-lg border border-slate-800 bg-[#060911] py-2 pr-3 pl-9 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500/60 focus:outline-none sm:text-sm"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#060911] px-2 py-1">
              <SlidersHorizontal className="h-3.5 w-3.5 text-slate-500" />
              <select
                aria-label="Filtrar por categoria"
                value={filter.categories[0] ?? ""}
                onChange={(e) =>
                  onFilterChange({
                    ...filter,
                    categories: e.target.value ? [e.target.value] : [],
                  })
                }
                className="bg-transparent text-xs text-slate-200 focus:outline-none"
              >
                <option value="" className="bg-[#0b111e]">
                  Todas as categorias
                </option>
                {categories.map((cat) => (
                  <option key={cat} value={cat} className="bg-[#0b111e]">
                    {cat} ({facetCounts.byCategory[cat] ?? 0})
                  </option>
                ))}
              </select>
            </div>

            {SEVERITY_OPTIONS.map((opt) => {
              const active = filter.severities.includes(opt.value);
              const count = facetCounts.bySeverity[opt.value] ?? 0;
              return (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => toggleSeverity(opt.value)}
                  className={`rounded-lg border px-2.5 py-1 text-xs font-medium tabular-nums transition ${
                    active
                      ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200"
                      : "border-slate-800 bg-[#060911] text-slate-400 hover:border-slate-700 hover:text-slate-200"
                  }`}
                >
                  {opt.label} ({count})
                </button>
              );
            })}
          </div>
        </div>
          {lastImportMessage && (
            <p className="mt-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs text-cyan-200">
              {lastImportMessage}
            </p>
          )}
      </div>

      {items.length === 0 ? (
        <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
          <AlertTriangle className="h-8 w-8 text-slate-600" />
          <p className="mt-3 text-sm font-medium text-slate-300">
            Nenhum incidente encontrado para os filtros atuais
          </p>
          <p className="mt-1 max-w-md text-xs text-slate-500">
            Quando o Windows registrar falhas críticas ou algum recurso exceder 90% por 5 segundos consecutivos, os eventos traduzidos aparecerão aqui em tempo real.
          </p>
          {mode === "tauri" && totalUnfilteredCount === 0 && (
            <button
              type="button"
              disabled={importingHistory}
              onClick={() => onImportHistory(30)}
              className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/15 px-3.5 py-2 text-xs font-semibold text-cyan-200 transition hover:bg-cyan-500/25 disabled:opacity-50"
            >
              {importingHistory ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <History className="h-3.5 w-3.5" />
              )}
              Importar Histórico do Windows (últimos 30 dias)
            </button>
          )}
        </div>
      ) : (
        <div
          ref={scrollParentRef}
          className="h-[480px] overflow-y-auto px-3 py-2"
        >
          <div
            style={{
              height: `${rowVirtualizer.getTotalSize()}px`,
              width: "100%",
              position: "relative",
            }}
          >
            {rowVirtualizer.getVirtualItems().map((virtualRow) => {
              const item = items[virtualRow.index];
              if (!item) return null;
              const sev = severityBadge(item.severity);
              const selected = selectedUid === item.uid;

              return (
                <div
                  key={virtualRow.key}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    transform: `translateY(${virtualRow.start}px)`,
                  }}
                  className="pb-2"
                >
                  <button
                    type="button"
                    data-testid="timeline-item"
                    onClick={() => onSelectItem(item)}
                    className={`group relative flex w-full items-start gap-3 overflow-hidden rounded-xl border p-3 text-left transition ${
                      selected
                        ? "border-cyan-500/60 bg-cyan-950/20"
                        : "border-slate-800/80 bg-[#080d18] hover:border-slate-700 hover:bg-[#0e1526]"
                    }`}
                  >
                    <span
                      className={`absolute top-0 bottom-0 left-0 w-1 ${sev.rail}`}
                    />
                    <div className="min-w-0 flex-1 pl-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold tracking-wider ${sev.cls}`}
                        >
                          {sev.label}
                        </span>
                        <span className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 text-[10px] font-medium text-slate-300">
                          {item.category}
                        </span>
                        {item.eventId !== null ? (
                          <span className="font-mono text-[11px] text-slate-400">
                            ID {item.eventId}
                          </span>
                        ) : (
                          <span className="font-mono text-[11px] text-amber-300/90">
                            SNAPSHOT
                          </span>
                        )}
                        {item.hasCorrelation && (
                          <span className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-300">
                            <Link2 className="h-2.5 w-2.5" />
                            CORRELACIONADO
                          </span>
                        )}
                        <span className="ml-auto font-mono text-[11px] text-slate-500 tabular-nums">
                          {formatTime(item.timestampUtc)}
                        </span>
                      </div>

                      <h3 className="mt-1.5 truncate text-xs font-semibold text-slate-100 group-hover:text-cyan-200 sm:text-sm">
                        {item.title}
                      </h3>

                      <p className="mt-0.5 truncate text-xs text-slate-400">
                        {item.diagnosticNote ?? item.summary}
                      </p>
                    </div>
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}
