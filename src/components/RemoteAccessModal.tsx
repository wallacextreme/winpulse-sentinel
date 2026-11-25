import { useState } from "react";
import { Check, Copy, KeyRound, Radio, RefreshCw, X } from "lucide-react";
import type { RemoteServerStatus } from "../types/sentinel";

interface RemoteAccessModalProps {
  open: boolean;
  status: RemoteServerStatus | null;
  error: string | null;
  onClose: () => void;
  onToggle: (enabled: boolean) => Promise<void>;
  onRegeneratePin: () => Promise<void>;
}

export function RemoteAccessModal({
  open,
  status,
  error,
  onClose,
  onToggle,
  onRegeneratePin,
}: RemoteAccessModalProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!open) return null;

  const copyText = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      window.setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Clipboard unavailable.
    }
  };

  const handleToggle = async () => {
    setBusy(true);
    try {
      await onToggle(!(status?.enabled ?? false));
    } finally {
      setBusy(false);
    }
  };

  const handleRegen = async () => {
    setBusy(true);
    try {
      await onRegeneratePin();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="remote-modal-title"
    >
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-[#0b111e] p-5 shadow-2xl">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
              <Radio className="h-4 w-4" />
            </div>
            <div>
              <h2
                id="remote-modal-title"
                className="text-sm font-semibold text-slate-100"
              >
                Monitoramento Remoto PWA (LAN)
              </h2>
              <p className="text-xs text-slate-400">
                Servidor Axum local protegido por PIN de 6 dígitos
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Fechar janela"
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-5 flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
          <div>
            <p className="text-xs font-medium text-slate-200">
              Servidor LAN ({status?.enabled ? "Ativo" : "Desativado"})
            </p>
            <p className="text-[11px] text-slate-400 tabular-nums">
              Porta {status?.port ?? 8420} · {status?.activeClients ?? 0} cliente(s) conectado(s)
            </p>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={handleToggle}
            className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
              status?.enabled
                ? "border border-rose-500/40 bg-rose-500/15 text-rose-200 hover:bg-rose-500/25"
                : "border border-emerald-500/40 bg-emerald-500/15 text-emerald-200 hover:bg-emerald-500/25"
            }`}
          >
            {status?.enabled ? "Desativar" : "Ativar Agora"}
          </button>
        </div>

        {error && (
          <p className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
            {error}
          </p>
        )}

        {status?.enabled && (
          <div className="mt-4 space-y-3">
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3.5">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-xs font-medium text-slate-300">
                  <KeyRound className="h-3.5 w-3.5 text-cyan-400" />
                  PIN de Acesso Temporário
                </span>
                <button
                  type="button"
                  disabled={busy}
                  onClick={handleRegen}
                  className="inline-flex items-center gap-1 text-[11px] font-medium text-cyan-300 hover:text-cyan-200"
                >
                  <RefreshCw className="h-3 w-3" />
                  Gerar Novo PIN
                </button>
              </div>
              <div className="mt-2 flex items-center justify-between gap-2">
                <span className="font-mono text-2xl font-bold tracking-[0.28em] text-cyan-300 tabular-nums">
                  {status.pin ?? "------"}
                </span>
                {status.pin && (
                  <button
                    type="button"
                    onClick={() => copyText("pin", status.pin ?? "")}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-700"
                  >
                    {copiedKey === "pin" ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                        Copiado
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5" />
                        Copiar PIN
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3.5">
              <p className="text-xs font-medium text-slate-300">
                Endereços na Rede Local (abra no celular ou outro PC):
              </p>
              <div className="mt-2 space-y-1.5">
                {status.lanUrls.map((url) => (
                  <div
                    key={url}
                    className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-[#060911] px-2.5 py-1.5"
                  >
                    <code className="truncate text-xs text-emerald-300">
                      {url}
                    </code>
                    <button
                      type="button"
                      onClick={() => copyText(url, url)}
                      className="shrink-0 text-xs text-slate-400 hover:text-slate-100"
                      aria-label={`Copiar ${url}`}
                    >
                      {copiedKey === url ? (
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
