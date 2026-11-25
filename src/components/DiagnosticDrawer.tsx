import { useEffect, useMemo, useState } from "react";
import {
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Link2,
  Loader2,
  Terminal,
  Wrench,
  X,
} from "lucide-react";
import {
  analyzeErrorInput,
  buildUnifiedFixCatalog,
} from "../data/fixCatalog";
import { metricLabelPt } from "../transport";
import type {
  BottleneckSnapshot,
  IncidentDetail,
  KnowledgeBaseEntry,
  TimelineItem,
} from "../types/sentinel";

interface DiagnosticDrawerProps {
  item: TimelineItem | null;
  detail: IncidentDetail | null;
  knowledgeBase: KnowledgeBaseEntry[];
  loading: boolean;
  error: string | null;
  onClose: () => void;
}

export function DiagnosticDrawer({
  item,
  detail,
  knowledgeBase,
  loading,
  error,
  onClose,
}: DiagnosticDrawerProps) {
  const [checkedSteps, setCheckedSteps] = useState<Record<number, boolean>>({});
  const [showRawXml, setShowRawXml] = useState(false);
  const [copiedXml, setCopiedXml] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const catalog = useMemo(
    () => buildUnifiedFixCatalog(knowledgeBase),
    [knowledgeBase],
  );

  const smartDiagnosis = useMemo(() => {
    const raw = detail?.event?.rawXml ?? item?.detailsText ?? "";
    if (!raw) return null;
    const result = analyzeErrorInput(raw, catalog);
    if (
      result &&
      (result.detectedApp || result.detectedModule || result.detectedCode)
    ) {
      return result;
    }
    return null;
  }, [catalog, detail?.event?.rawXml, item?.detailsText]);

  useEffect(() => {
    setCheckedSteps({});
    setShowRawXml(false);
    setCopiedXml(false);
  }, [item?.uid]);

  useEffect(() => {
    if (!item) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [item, onClose]);

  if (!item) return null;

  const eventRec = detail?.event ?? null;
  const primarySnapshot: BottleneckSnapshot | null =
    detail?.snapshot ?? detail?.correlatedSnapshots[0] ?? null;
  const diagnosticNote = detail?.diagnosticNote ?? item.diagnosticNote;

  const copyXml = async (xml: string) => {
    try {
      await navigator.clipboard.writeText(xml);
      setCopiedXml(true);
      window.setTimeout(() => setCopiedXml(false), 1800);
    } catch {
      // Clipboard unavailable.
    }
  };

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/65 backdrop-blur-xs">
      <div
        className="flex-1"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Diagnóstico do Incidente"
        data-testid="diagnostic-drawer"
        className="flex h-full w-full max-w-xl flex-col border-l border-slate-800 bg-[#0b111e] shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-[11px] font-medium text-slate-300">
                {item.category}
              </span>
              {item.eventId !== null && (
                <span className="rounded border border-cyan-500/35 bg-cyan-500/10 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
                  Event ID {item.eventId}
                </span>
              )}
              {primarySnapshot && (
                <span className="rounded border border-amber-500/35 bg-amber-500/10 px-2 py-0.5 font-mono text-[11px] text-amber-300">
                  {metricLabelPt(primarySnapshot.violatedMetric)}
                </span>
              )}
            </div>
            <h2 className="mt-2 text-base font-semibold text-slate-100">
              {eventRec?.friendlyTitle ?? item.title}
            </h2>
            <p className="mt-0.5 font-mono text-xs text-slate-400">
              {item.providerName ?? "Sistema"} ·{" "}
              {new Date(item.timestampUtc).toLocaleString("pt-BR")}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            data-testid="drawer-close"
            aria-label="Fechar diagnóstico"
            className="rounded-lg border border-slate-800 p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 space-y-5 overflow-y-auto px-5 py-4">
          {loading && (
            <div className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/50 p-3 text-xs text-slate-300">
              <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
              Carregando correlação e telemetria detalhada...
            </div>
          )}

          {error && (
            <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">
              {error}
            </div>
          )}

          {diagnosticNote && (
            <div
              data-testid="diagnostic-note"
              className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3.5"
            >
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-emerald-300">
                <Link2 className="h-3.5 w-3.5" />
                Nota de Diagnóstico Automática
              </div>
              <p className="mt-1.5 text-sm leading-relaxed text-emerald-100">
                {diagnosticNote}
              </p>
            </div>
          )}

          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              O que aconteceu
            </h3>
            <p className="mt-1.5 text-sm leading-relaxed text-slate-200">
              {smartDiagnosis?.whatHappened ?? eventRec?.whatHappened ?? item.summary}
            </p>
          </section>

          {smartDiagnosis && (
            <section className="rounded-xl border border-cyan-500/30 bg-cyan-950/15 p-3.5">
              <div className="flex flex-wrap items-center gap-1.5">
                <Wrench className="h-3.5 w-3.5 text-cyan-400" />
                <span className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                  Assinatura Técnica Identificada
                </span>
                {smartDiagnosis.detectedApp && (
                  <span className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-slate-200">
                    {smartDiagnosis.detectedApp}
                  </span>
                )}
                {smartDiagnosis.detectedModule && (
                  <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[11px] text-amber-200">
                    {smartDiagnosis.detectedModule}
                  </span>
                )}
                {smartDiagnosis.detectedCode && (
                  <span className="rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[11px] text-rose-200">
                    {smartDiagnosis.detectedCode}
                  </span>
                )}
              </div>
              {smartDiagnosis.commands.length > 0 && (
                <div className="mt-2.5 flex flex-wrap gap-1.5">
                  {smartDiagnosis.commands.map((cmd) => (
                    <button
                      key={cmd.command}
                      type="button"
                      onClick={() => {
                        void navigator.clipboard
                          .writeText(cmd.command)
                          .then(() => {
                            setCopiedCmd(cmd.command);
                            window.setTimeout(() => setCopiedCmd(null), 1800);
                          })
                          .catch(() => {});
                      }}
                      className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#05080f] px-2 py-1 font-mono text-[11px] text-cyan-200 hover:border-cyan-500/50"
                    >
                      <Terminal className="h-3 w-3 text-cyan-400" />
                      <span>{cmd.command}</span>
                      {copiedCmd === cmd.command ? (
                        <Check className="h-3 w-3 text-emerald-400" />
                      ) : (
                        <Copy className="h-3 w-3 text-slate-500" />
                      )}
                    </button>
                  ))}
                </div>
              )}
            </section>
          )}

          {eventRec && eventRec.probableCauses.length > 0 && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Causas Prováveis
              </h3>
              <ul className="mt-2 space-y-1.5 text-sm text-slate-300">
                {eventRec.probableCauses.map((cause, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
                    <span>{cause}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {eventRec && eventRec.solutions.length > 0 && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Checklist de Solução
              </h3>
              <div className="mt-2 space-y-2">
                {eventRec.solutions.map((step, idx) => {
                  const checked = checkedSteps[idx] ?? false;
                  return (
                    <label
                      key={idx}
                      className={`flex cursor-pointer items-start gap-2.5 rounded-lg border p-2.5 text-sm transition ${
                        checked
                          ? "border-emerald-500/35 bg-emerald-500/10 text-slate-400 line-through"
                          : "border-slate-800 bg-[#070b14] text-slate-200 hover:border-slate-700"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() =>
                          setCheckedSteps((prev) => ({
                            ...prev,
                            [idx]: !checked,
                          }))
                        }
                        className="mt-0.5 h-4 w-4 rounded border-slate-700 bg-slate-900 accent-cyan-500"
                      />
                      <span>{step}</span>
                    </label>
                  );
                })}
              </div>
            </section>
          )}

          {primarySnapshot && (
            <section className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Contexto de Hardware na Janela do Gargalo
              </h3>

              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <div className="rounded-lg border border-slate-800 bg-[#070b14] p-2.5">
                  <span className="text-[10px] uppercase text-slate-500">CPU</span>
                  <p className="mt-0.5 font-mono text-sm font-semibold text-slate-100 tabular-nums">
                    {primarySnapshot.cpuPercent.toFixed(1)}%
                  </p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-[#070b14] p-2.5">
                  <span className="text-[10px] uppercase text-slate-500">RAM</span>
                  <p className="mt-0.5 font-mono text-sm font-semibold text-slate-100 tabular-nums">
                    {primarySnapshot.ramPercent.toFixed(1)}%
                  </p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-[#070b14] p-2.5">
                  <span className="text-[10px] uppercase text-slate-500">Disco</span>
                  <p className="mt-0.5 font-mono text-sm font-semibold text-slate-100 tabular-nums">
                    {primarySnapshot.diskActivePercent.toFixed(0)}% ·{" "}
                    {primarySnapshot.diskLatencyMs.toFixed(0)}ms
                  </p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-[#070b14] p-2.5">
                  <span className="text-[10px] uppercase text-slate-500">RAM Livre</span>
                  <p className="mt-0.5 font-mono text-sm font-semibold text-slate-100 tabular-nums">
                    {primarySnapshot.ramFreeGb.toFixed(1)} GB
                  </p>
                </div>
              </div>

              {primarySnapshot.topProcesses.length > 0 && (
                <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#070b14]">
                  <div className="border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-300">
                    Top 5 Processos Ofensores
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs tabular-nums">
                      <thead className="border-b border-slate-800/80 text-[10px] uppercase text-slate-500">
                        <tr>
                          <th className="px-3 py-2">PID</th>
                          <th className="px-3 py-2">Processo</th>
                          <th className="px-3 py-2 text-right">CPU</th>
                          <th className="px-3 py-2 text-right">RAM</th>
                          <th className="px-3 py-2 text-right">Disco</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {primarySnapshot.topProcesses.map((proc) => (
                          <tr key={proc.pid} className="hover:bg-slate-900/50">
                            <td className="px-3 py-2 font-mono text-slate-400">
                              {proc.pid}
                            </td>
                            <td className="px-3 py-2">
                              <div className="font-medium text-slate-200">
                                {proc.name}
                              </div>
                              {proc.exePath && (
                                <div className="max-w-[220px] truncate font-mono text-[10px] text-slate-500">
                                  {proc.exePath}
                                </div>
                              )}
                            </td>
                            <td className="px-3 py-2 text-right font-mono text-slate-200">
                              {proc.cpuPercent.toFixed(1)}%
                            </td>
                            <td className="px-3 py-2 text-right font-mono text-slate-200">
                              {proc.memoryMb.toFixed(0)} MB
                            </td>
                            <td className="px-3 py-2 text-right font-mono text-slate-400">
                              {(proc.diskReadKbps + proc.diskWriteKbps).toFixed(0)} KB/s
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          )}

          {eventRec && (
            <section className="rounded-xl border border-slate-800 bg-[#070b14]">
              <button
                type="button"
                data-testid="raw-xml-toggle"
                onClick={() => setShowRawXml((v) => !v)}
                className="flex w-full items-center justify-between px-3.5 py-2.5 text-xs font-medium text-slate-300 hover:text-slate-100"
              >
                <span className="flex items-center gap-1.5">
                  {showRawXml ? (
                    <ChevronDown className="h-4 w-4" />
                  ) : (
                    <ChevronRight className="h-4 w-4" />
                  )}
                  XML Bruto do Evento Windows
                </span>
                <span className="font-mono text-[10px] text-slate-500">
                  {eventRec.channel}
                </span>
              </button>

              {showRawXml && (
                <div className="border-t border-slate-800 p-3">
                  <div className="mb-2 flex justify-end">
                    <button
                      type="button"
                      onClick={() => copyXml(eventRec.rawXml)}
                      className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] text-slate-200 hover:bg-slate-700"
                    >
                      {copiedXml ? (
                        <>
                          <Check className="h-3 w-3 text-emerald-400" />
                          Copiado
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          Copiar XML
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="max-h-60 overflow-auto rounded-lg bg-[#04070d] p-2.5 font-mono text-[11px] leading-relaxed text-cyan-200/90">
                    {eventRec.rawXml}
                  </pre>
                </div>
              )}
            </section>
          )}
        </div>
      </aside>
    </div>
  );
}
