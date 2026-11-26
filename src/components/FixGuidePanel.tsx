import { useMemo, useState } from "react";
import {
  BookOpen,
  Bot,
  Check,
  Copy,
  Loader2,
  Play,
  Search,
  Sparkles,
  Terminal,
  Wrench,
} from "lucide-react";
import {
  analyzeErrorInput,
  buildUnifiedFixCatalog,
  type FixCommand,
  type FixGuideEntry,
} from "../data/fixCatalog";
import type {
  AiDiagnosisResponse,
  CommandShell,
  CommandSource,
  KnowledgeBaseEntry,
  Severity,
} from "../types/sentinel";

interface FixGuidePanelProps {
  knowledgeBase: KnowledgeBaseEntry[];
  supportsExecution: boolean;
  onAnalyzeTextWithAi: (
    errorText: string,
    executionFeedback?: string,
  ) => Promise<AiDiagnosisResponse>;
  onOpenAiSettings: () => void;
  onExecuteCommand: (params: {
    source: CommandSource;
    shell: CommandShell;
    command: string;
    rationale: string;
    requiresAdmin: boolean;
  }) => Promise<void>;
}

const QUICK_EXAMPLES = [
  {
    label: "Paint / ucrtbase.dll / c0000409",
    value:
      "mspaint.exe | MoBEX | Microsoft.Paint_11.2609.401.0 | ucrtbase.dll | c0000409",
  },
  { label: "0xc0000005 (Access Violation)", value: "chrome.exe 0xc0000005" },
  { label: "Driver GPU (nvlddmkm.sys)", value: "nvlddmkm.sys VIDEO_TDR_FAILURE" },
  { label: "Disco 100% (Event ID 129)", value: "Event ID 129 storahci" },
  { label: "Tela Azul / Kernel-Power 41", value: "Event ID 41 Kernel-Power" },
];

function severityBadge(sev: Severity): { label: string; cls: string } {
  switch (sev) {
    case "critical":
      return {
        label: "CRÍTICO",
        cls: "border-rose-500/40 bg-rose-500/15 text-rose-300",
      };
    case "high":
      return {
        label: "ALTO",
        cls: "border-amber-500/40 bg-amber-500/15 text-amber-300",
      };
    default:
      return {
        label: "MÉDIO",
        cls: "border-cyan-500/35 bg-cyan-500/10 text-cyan-300",
      };
  }
}

function foldPt(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

function CommandChips({
  commands,
  copiedCmd,
  supportsExecution,
  onCopy,
  onExecute,
}: {
  commands: FixCommand[];
  copiedCmd: string | null;
  supportsExecution: boolean;
  onCopy: (cmd: string) => void;
  onExecute: (item: FixCommand) => void;
}) {
  if (commands.length === 0) return null;
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      {commands.map((item) => (
        <div key={item.command} className="inline-flex items-center gap-1">
          <button
            type="button"
            onClick={() => onCopy(item.command)}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700/80 bg-[#05080f] px-2.5 py-1.5 text-left text-xs text-slate-200 transition hover:border-cyan-500/50 hover:bg-slate-900"
            title={`Copiar comando: ${item.command}`}
          >
            <Terminal className="h-3.5 w-3.5 shrink-0 text-cyan-400" />
            <code className="font-mono text-[11px] text-cyan-200">
              {item.command}
            </code>
            {item.requiresAdmin && (
              <span className="rounded bg-amber-500/15 px-1 py-0.5 text-[9px] font-semibold uppercase text-amber-300">
                Admin
              </span>
            )}
            {copiedCmd === item.command ? (
              <Check className="h-3.5 w-3.5 text-emerald-400" />
            ) : (
              <Copy className="h-3.5 w-3 text-slate-500" />
            )}
          </button>
          {supportsExecution && (
            <button
              type="button"
              data-testid="fix-execute-cmd-btn"
              onClick={() => onExecute(item)}
              className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-2 py-1.5 text-[11px] font-semibold text-emerald-200 transition hover:bg-emerald-500/25"
            >
              <Play className="h-3 w-3" />
              Executar
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

export function FixGuidePanel({
  knowledgeBase,
  supportsExecution,
  onAnalyzeTextWithAi,
  onOpenAiSettings,
  onExecuteCommand,
}: FixGuidePanelProps) {
  const catalog = useMemo(
    () => buildUnifiedFixCatalog(knowledgeBase),
    [knowledgeBase],
  );

  const [pastedError, setPastedError] = useState("");
  const [catalogSearch, setCatalogSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("Todas");
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [checkedMap, setCheckedMap] = useState<Record<string, boolean>>({});
  const [aiBusy, setAiBusy] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiResult, setAiResult] = useState<AiDiagnosisResponse | null>(null);

  const handleAnalyzeWithAi = async () => {
    if (pastedError.trim().length < 3) return;
    setAiBusy(true);
    setAiError(null);
    try {
      const res = await onAnalyzeTextWithAi(pastedError.trim());
      setAiResult(res);
    } catch (err) {
      setAiError(err instanceof Error ? err.message : String(err));
    } finally {
      setAiBusy(false);
    }
  };

  const diagnosis = useMemo(
    () => analyzeErrorInput(pastedError, catalog),
    [catalog, pastedError],
  );

  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const entry of catalog) {
      set.add(entry.category);
    }
    return ["Todas", ...Array.from(set).sort((a, b) => a.localeCompare(b, "pt-BR"))];
  }, [catalog]);

  const filteredCatalog = useMemo(() => {
    const q = foldPt(catalogSearch.trim());
    const tokens = q ? q.split(/\s+/) : [];
    return catalog.filter((entry: FixGuideEntry) => {
      if (selectedCategory !== "Todas" && entry.category !== selectedCategory) {
        return false;
      }
      if (tokens.length === 0) return true;
      const hay = foldPt(
        `${entry.title} ${entry.category} ${entry.whatHappened} ${entry.codes.join(" ")} ${entry.solutions.join(" ")}`,
      );
      return tokens.every((tok) => hay.includes(tok));
    });
  }, [catalog, catalogSearch, selectedCategory]);

  const handleCopyCommand = async (cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedCmd(cmd);
      window.setTimeout(() => setCopiedCmd(null), 1800);
    } catch {
      // Clipboard unavailable.
    }
  };

  return (
    <div data-testid="fix-guide-panel" className="space-y-5">
      {/* Analisador Rápido */}
      <section className="rounded-xl border border-cyan-500/30 bg-[#0b111e] p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/35 bg-cyan-500/10 text-cyan-300">
              <Sparkles className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-100 sm:text-base">
                Tradutor e Analisador Rápido de Erros do Windows
              </h2>
              <p className="text-xs text-slate-400">
                Cole um código de erro (ex.:{" "}
                <code className="text-cyan-300">c0000409</code>,{" "}
                <code className="text-cyan-300">MoBEX</code>,{" "}
                <code className="text-cyan-300">ucrtbase.dll</code>,{" "}
                <code className="text-cyan-300">mspaint.exe</code> ou Event ID{" "}
                <code className="text-cyan-300">1000</code>) ou o texto inteiro do
                Monitor de Confiabilidade.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-3.5">
          <textarea
            data-testid="fix-analyzer-input"
            rows={3}
            value={pastedError}
            onChange={(e) => setPastedError(e.target.value)}
            placeholder="Cole aqui os detalhes do problema (ex: mspaint.exe, ucrtbase.dll, c0000409, MoBEX, nvlddmkm.sys, 129...)"
            className="w-full rounded-xl border border-slate-800 bg-[#060911] p-3 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500/60 focus:outline-none sm:text-sm"
          />
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-slate-500">Testar exemplo:</span>
            {QUICK_EXAMPLES.map((ex) => (
              <button
                key={ex.label}
                type="button"
                onClick={() => setPastedError(ex.value)}
                className="rounded-md border border-slate-800 bg-slate-900/80 px-2 py-0.5 text-[11px] text-slate-300 transition hover:border-cyan-500/40 hover:text-cyan-200"
              >
                {ex.label}
              </button>
            ))}
            {pastedError && (
              <button
                type="button"
                onClick={() => {
                  setPastedError("");
                  setAiResult(null);
                  setAiError(null);
                }}
                className="ml-auto text-[11px] text-slate-400 hover:text-slate-200"
              >
                Limpar
              </button>
            )}
            {supportsExecution && pastedError.trim().length >= 3 && (
              <button
                type="button"
                data-testid="fix-analyze-ai-btn"
                disabled={aiBusy}
                onClick={() => void handleAnalyzeWithAi()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-500/15 px-3 py-1 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/25 disabled:opacity-50"
              >
                {aiBusy ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Bot className="h-3.5 w-3.5" />
                )}
                {aiBusy ? "Diagnosticando..." : "Diagnosticar com IA"}
              </button>
            )}
          </div>
        </div>

        {aiError && (
          <div className="mt-3 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">
            <p>{aiError}</p>
            {(aiError.toLowerCase().includes("cota") ||
              aiError.toLowerCase().includes("quota") ||
              aiError.toLowerCase().includes("limite")) && (
              <button
                type="button"
                onClick={onOpenAiSettings}
                className="mt-2 rounded border border-cyan-500/40 bg-cyan-500/15 px-2.5 py-1 font-semibold text-cyan-200"
              >
                Configurar BYOK ou Ollama
              </button>
            )}
          </div>
        )}

        {aiResult && (
          <div
            data-testid="fix-ai-result"
            className="mt-4 rounded-xl border border-cyan-500/35 bg-cyan-950/15 p-4 text-xs"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 font-semibold text-cyan-200">
                <Bot className="h-4 w-4 text-cyan-400" />
                Diagnóstico por IA ({aiResult.modelUsed})
              </span>
              <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 uppercase text-slate-300">
                {aiResult.confidence}
              </span>
            </div>
            <p className="mt-2 text-sm font-medium text-slate-100">{aiResult.summary}</p>
            <p className="mt-1 text-slate-300">
              <strong>Causa provável:</strong> {aiResult.rootCause}
            </p>
            {aiResult.steps.length > 0 && (
              <ol className="mt-2 list-decimal space-y-1 pl-4 text-slate-300">
                {aiResult.steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            )}
            {aiResult.proposedCommands.length > 0 && (
              <div className="mt-3 space-y-2">
                {aiResult.proposedCommands.map((cmd, idx) => (
                  <div
                    key={`${cmd.command}-${idx}`}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-[#05080f] p-2.5"
                  >
                    <div>
                      <p className="font-medium text-slate-200">{cmd.label}</p>
                      <code className="font-mono text-[11px] text-cyan-300">{cmd.command}</code>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        void onExecuteCommand({
                          source: "ai",
                          shell: cmd.shell,
                          command: cmd.command,
                          rationale: cmd.rationale,
                          requiresAdmin: cmd.requiresAdmin,
                        })
                      }
                      className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-1 font-semibold text-emerald-200 hover:bg-emerald-500/25"
                    >
                      <Play className="h-3 w-3" />
                      Executar
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {diagnosis && (
          <div
            data-testid="fix-analyzer-result"
            className="mt-4 rounded-xl border border-emerald-500/35 bg-emerald-950/15 p-4"
          >
            <div className="flex flex-wrap items-center gap-2">
              <Wrench className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-emerald-200">
                {diagnosis.headline}
              </h3>
              {diagnosis.detectedApp && (
                <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-[11px] text-slate-200">
                  App: {diagnosis.detectedApp}
                </span>
              )}
              {diagnosis.detectedModule && (
                <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-[11px] text-amber-200">
                  Módulo: {diagnosis.detectedModule}
                </span>
              )}
              {diagnosis.detectedCode && (
                <span className="rounded border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 font-mono text-[11px] text-rose-200">
                  Código: {diagnosis.detectedCode}
                </span>
              )}
            </div>

            <div className="mt-3 space-y-3 text-sm">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  O que aconteceu
                </p>
                <p className="mt-1 leading-relaxed text-slate-100">
                  {diagnosis.whatHappened}
                </p>
              </div>

              {diagnosis.probableCauses.length > 0 && (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Causas prováveis
                  </p>
                  <ul className="mt-1 space-y-1 text-xs text-slate-300 sm:text-sm">
                    {diagnosis.probableCauses.map((cause, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
                        <span>{cause}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-emerald-300">
                  Como corrigir (passo a passo)
                </p>
                <div className="mt-1.5 space-y-1.5">
                  {diagnosis.solutions.map((step, idx) => {
                    const key = `diag-${idx}-${step.slice(0, 16)}`;
                    const checked = checkedMap[key] ?? false;
                    return (
                      <label
                        key={key}
                        className={`flex cursor-pointer items-start gap-2.5 rounded-lg border p-2.5 text-xs transition sm:text-sm ${
                          checked
                            ? "border-emerald-500/40 bg-emerald-500/10 text-slate-400 line-through"
                            : "border-slate-800 bg-[#060911] text-slate-100 hover:border-slate-700"
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() =>
                            setCheckedMap((prev) => ({
                              ...prev,
                              [key]: !checked,
                            }))
                          }
                          className="mt-0.5 h-4 w-4 rounded border-slate-700 bg-slate-900 accent-emerald-500"
                        />
                        <span>{step}</span>
                      </label>
                    );
                  })}
                </div>

                <CommandChips
                  commands={diagnosis.commands}
                  copiedCmd={copiedCmd}
                  supportsExecution={supportsExecution}
                  onCopy={(cmd) => {
                    void handleCopyCommand(cmd);
                  }}
                  onExecute={(cmdItem) => {
                    void onExecuteCommand({
                      source: "catalog",
                      shell: cmdItem.command.trim().startsWith("Get-")
                        ? "powershell"
                        : "cmd",
                      command: cmdItem.command,
                      rationale: cmdItem.label,
                      requiresAdmin: Boolean(cmdItem.requiresAdmin),
                    });
                  }}
                />
              </div>
            </div>
          </div>
        )}
      </section>

      {/* Catálogo Completo de Erros */}
      <section className="rounded-xl border border-slate-800/80 bg-[#0b111e] p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-cyan-400" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Guia Completo: Como Corrigir Erros do Windows e Programas
              </h2>
              <p className="text-xs text-slate-400 tabular-nums">
                {filteredCatalog.length} de {catalog.length} guias disponíveis
              </p>
            </div>
          </div>

          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              type="search"
              data-testid="fix-catalog-search"
              value={catalogSearch}
              onChange={(e) => setCatalogSearch(e.target.value)}
              placeholder="Filtrar guia (ex: disco, RAM, 41, DLL)..."
              className="w-full rounded-lg border border-slate-800 bg-[#060911] py-1.5 pr-3 pl-8 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500/60 focus:outline-none"
            />
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-1.5">
          {categories.map((cat) => {
            const active = selectedCategory === cat;
            return (
              <button
                key={cat}
                type="button"
                onClick={() => setSelectedCategory(cat)}
                className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                  active
                    ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200"
                    : "border-slate-800 bg-[#060911] text-slate-400 hover:border-slate-700 hover:text-slate-200"
                }`}
              >
                {cat}
              </button>
            );
          })}
        </div>

        <div className="mt-4 grid grid-cols-1 gap-3.5 lg:grid-cols-2">
          {filteredCatalog.map((entry) => {
            const sev = severityBadge(entry.severity);
            return (
              <article
                key={entry.id}
                data-testid="fix-guide-card"
                className="flex flex-col rounded-xl border border-slate-800/90 bg-[#070b14] p-4"
              >
                <div className="flex flex-wrap items-center gap-1.5">
                  <span
                    className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold tracking-wider ${sev.cls}`}
                  >
                    {sev.label}
                  </span>
                  <span className="rounded border border-slate-800 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-300">
                    {entry.category}
                  </span>
                  {entry.codes.slice(0, 3).map((code) => (
                    <span
                      key={code}
                      className="rounded bg-slate-900/90 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300"
                    >
                      {code}
                    </span>
                  ))}
                </div>

                <h3 className="mt-2 text-sm font-semibold text-slate-100">
                  {entry.title}
                </h3>

                <p className="mt-1.5 text-xs leading-relaxed text-slate-300">
                  <strong className="text-slate-200">O que aconteceu:</strong>{" "}
                  {entry.whatHappened}
                </p>

                <div className="mt-2.5">
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-emerald-400">
                    Como corrigir
                  </p>
                  <ol className="mt-1 list-decimal space-y-1 pl-4 text-xs leading-relaxed text-slate-300">
                    {entry.solutions.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </div>

                <CommandChips
                  commands={entry.commands}
                  copiedCmd={copiedCmd}
                  supportsExecution={supportsExecution}
                  onCopy={(cmd) => {
                    void handleCopyCommand(cmd);
                  }}
                  onExecute={(cmdItem) => {
                    void onExecuteCommand({
                      source: "catalog",
                      shell: cmdItem.command.trim().startsWith("Get-")
                        ? "powershell"
                        : "cmd",
                      command: cmdItem.command,
                      rationale: cmdItem.label,
                      requiresAdmin: Boolean(cmdItem.requiresAdmin),
                    });
                  }}
                />
              </article>
            );
          })}
        </div>
      </section>
    </div>
  );
}
