import { useEffect } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Play,
  ShieldAlert,
  Sparkles,
  Square,
  Terminal,
  X,
} from "lucide-react";
import type {
  CommandAuditStatus,
  CommandExecutionResult,
  StagedCommandTicket,
} from "../types/sentinel";

interface CommandApprovalModalProps {
  ticket: StagedCommandTicket | null;
  status: CommandAuditStatus | null;
  output: string;
  busy: boolean;
  result: CommandExecutionResult | null;
  error: string | null;
  isElevated: boolean;
  onApprove: () => Promise<void>;
  onReject: () => Promise<void>;
  onCancelRunning: () => Promise<void>;
  onClose: () => void;
  onSendOutputToAi?: (feedback: string) => void;
}

export function CommandApprovalModal({
  ticket,
  status,
  output,
  busy,
  result,
  error,
  isElevated,
  onApprove,
  onReject,
  onCancelRunning,
  onClose,
  onSendOutputToAi,
}: CommandApprovalModalProps) {
  useEffect(() => {
    if (!ticket) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [busy, onClose, ticket]);

  if (!ticket) return null;

  const isPending = status === "pending";
  const isRunning = status === "running" || busy;
  const isFinished =
    status === "succeeded" ||
    status === "failed" ||
    status === "cancelled" ||
    status === "timed_out";

  const sourceLabel =
    ticket.source === "mcp"
      ? "Agente MCP Externo"
      : ticket.source === "ai"
        ? "Diagnóstico de IA"
        : "Guia de Correções";

  const combinedOutput =
    output ||
    [result?.stdout, result?.stderr].filter(Boolean).join("\n") ||
    "";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center overflow-hidden bg-black/80 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="command-approval-title"
      data-testid="command-approval-modal"
    >
      <div className="flex max-h-[90vh] min-h-0 w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-slate-700/90 bg-[#0b111e] shadow-2xl">
        <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-300">
              <Terminal className="h-4 w-4" />
            </div>
            <div>
              <h2
                id="command-approval-title"
                className="text-sm font-semibold text-slate-100"
              >
                Aprovação Obrigatória de Execução
              </h2>
              <p className="text-xs text-slate-400">
                Origem: <span className="text-cyan-300">{sourceLabel}</span> · Shell:{" "}
                <span className="font-mono uppercase text-slate-200">{ticket.shell}</span>
              </p>
            </div>
          </div>
          <button
            type="button"
            disabled={isRunning}
            onClick={onClose}
            aria-label="Fechar janela de aprovação"
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-slate-100 disabled:opacity-40"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto overscroll-contain p-5">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded border px-2 py-0.5 text-[11px] font-semibold uppercase ${
                ticket.riskLevel === "read_only"
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                  : "border-amber-500/40 bg-amber-500/15 text-amber-300"
              }`}
            >
              {ticket.riskLevel === "read_only" ? "Somente Leitura" : "Modificação / Reparo"}
            </span>
            {(ticket.requiresAdmin || isElevated) && (
              <span className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-200">
                <ShieldAlert className="h-3.5 w-3.5" />
                {isElevated
                  ? "App em modo Admin (herdará privilégios elevados)"
                  : "Requer terminal como Administrador"}
              </span>
            )}
          </div>

          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Motivo informado
            </p>
            <p className="mt-1 text-sm text-slate-200">{ticket.rationale}</p>
          </div>

          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Comando literal que será executado
            </p>
            <pre
              data-testid="approval-command-preview"
              className="mt-1.5 overflow-x-auto rounded-xl border border-cyan-500/30 bg-[#05080f] p-3.5 font-mono text-xs text-cyan-200"
            >
              {ticket.command}
            </pre>
          </div>

          {isPending && (
            <div className="flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              <span>
                Revise o comando acima antes de autorizar. Nenhum comando sugerido por IA ou agente MCP é executado automaticamente.
              </span>
            </div>
          )}

          {error && (
            <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">
              {error}
            </div>
          )}

          {(isRunning || isFinished || combinedOutput) && (
            <div>
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="font-semibold uppercase tracking-wider">
                  Saída do Terminal
                </span>
                {result && (
                  <span className="inline-flex items-center gap-1 font-mono">
                    {result.status === "succeeded" ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    ) : null}
                    Exit code: {result.exitCode ?? "n/d"} · {result.durationMs}ms
                  </span>
                )}
              </div>
              <pre
                data-testid="command-terminal-output"
                className="mt-1.5 max-h-56 overflow-auto rounded-xl border border-slate-800 bg-[#04070d] p-3 font-mono text-[11px] leading-relaxed text-emerald-200/95"
              >
                {combinedOutput || "Aguardando saída..."}
              </pre>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-800 bg-[#080d18] px-5 py-3.5">
          {isPending && (
            <>
              <button
                type="button"
                data-testid="reject-command-btn"
                onClick={() => void onReject()}
                className="rounded-lg border border-slate-700 bg-slate-900 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800"
              >
                Recusar
              </button>
              <button
                type="button"
                data-testid="approve-command-btn"
                onClick={() => void onApprove()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/50 bg-emerald-500/20 px-4 py-2 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/30"
              >
                <Play className="h-3.5 w-3.5" />
                Aprovar e Executar
              </button>
            </>
          )}

          {isRunning && (
            <button
              type="button"
              onClick={() => void onCancelRunning()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/20 px-4 py-2 text-xs font-semibold text-rose-200 hover:bg-rose-500/30"
            >
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <Square className="h-3 w-3" />
              Cancelar Execução
            </button>
          )}

          {isFinished && (
            <>
              {onSendOutputToAi && combinedOutput && (
                <button
                  type="button"
                  data-testid="send-output-to-ai-btn"
                  onClick={() => onSendOutputToAi(combinedOutput)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/15 px-3.5 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/25"
                >
                  <Sparkles className="h-3.5 w-3.5" />
                  Enviar saída para a IA avaliar
                </button>
              )}
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-100 hover:bg-slate-700"
              >
                Fechar
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
