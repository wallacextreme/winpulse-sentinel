import {
  Activity,
  Pause,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  WifiOff,
  Wrench,
} from "lucide-react";
import type { ConnectionState, TransportMode } from "../transport";
import type { CollectorStatus, HealthStatus } from "../types/sentinel";

export type AppTab = "monitoring" | "fix-guide";

interface TopBarProps {
  activeTab: AppTab;
  onSelectTab: (tab: AppTab) => void;
  mode: TransportMode;
  wasmReady: boolean;
  connectionState: ConnectionState;
  collectorStatus: CollectorStatus | null;
  remoteEnabled: boolean;
  onTogglePause: () => void;
  onOpenRemoteModal: () => void;
  onRefresh: () => void;
}

function healthBadge(health: HealthStatus) {
  switch (health) {
    case "critical":
      return {
        label: "Crítico",
        cls: "border-rose-500/40 bg-rose-500/10 text-rose-300",
        dot: "bg-rose-400 animate-pulse",
      };
    case "warning":
      return {
        label: "Atenção",
        cls: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        dot: "bg-amber-400",
      };
    default:
      return {
        label: "Estável",
        cls: "border-emerald-500/35 bg-emerald-500/10 text-emerald-300",
        dot: "bg-emerald-400",
      };
  }
}

export function TopBar({
  activeTab,
  onSelectTab,
  mode,
  wasmReady,
  connectionState,
  collectorStatus,
  remoteEnabled,
  onTogglePause,
  onOpenRemoteModal,
  onRefresh,
}: TopBarProps) {
  const health = collectorStatus?.healthStatus ?? "stable";
  const badge = healthBadge(health);
  const paused = collectorStatus?.paused ?? false;

  return (
    <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#060911]/95 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
            <Activity className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-semibold tracking-tight text-slate-100 sm:text-base">
                WinPulse Sentinel
              </h1>
              <span className="rounded border border-slate-700/80 bg-slate-900 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-slate-300">
                {mode === "tauri"
                  ? "Desktop"
                  : mode === "demo"
                    ? "Demo Interativa"
                    : "PWA LAN"}
              </span>
              {wasmReady && (
                <span className="hidden rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-cyan-300 sm:inline-block">
                  WASM LTTB
                </span>
              )}
              {mode === "tauri" && collectorStatus && (
                <span
                  className={`hidden items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider sm:inline-flex ${
                    collectorStatus.isElevated
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                      : "border-amber-500/30 bg-amber-500/10 text-amber-300"
                  }`}
                  title={
                    collectorStatus.isElevated
                      ? "Executando como Administrador (Acesso total ao Event Log)"
                      : "Sem elevação UAC — alguns canais protegidos podem requerer Admin"
                  }
                >
                  {collectorStatus.isElevated ? (
                    <ShieldCheck className="h-3 w-3" />
                  ) : (
                    <ShieldAlert className="h-3 w-3" />
                  )}
                  {collectorStatus.isElevated ? "Admin" : "Padrão"}
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-400">
              Caixa-Preta de Hardware &amp; Tradutor de Eventos Windows
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {connectionState === "offline" && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-300">
              <WifiOff className="h-3.5 w-3.5" />
              Modo Offline (Cache)
            </span>
          )}

          <div
            data-testid="health-indicator"
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${badge.cls}`}
          >
            <span className={`h-2 w-2 rounded-full ${badge.dot}`} />
            <span>Saúde: {badge.label}</span>
          </div>

          {mode === "tauri" && (
            <>
              <button
                type="button"
                onClick={onTogglePause}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-900/90 px-2.5 py-1.5 text-xs font-medium text-slate-200 transition hover:border-slate-600 hover:bg-slate-800"
              >
                {paused ? (
                  <>
                    <Play className="h-3.5 w-3.5 text-emerald-400" />
                    <span>Retomar</span>
                  </>
                ) : (
                  <>
                    <Pause className="h-3.5 w-3.5 text-amber-400" />
                    <span>Pausar</span>
                  </>
                )}
              </button>

              <button
                type="button"
                data-testid="remote-access-btn"
                onClick={onOpenRemoteModal}
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition ${
                  remoteEnabled
                    ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25"
                    : "border-slate-700/80 bg-slate-900/90 text-slate-200 hover:border-slate-600 hover:bg-slate-800"
                }`}
              >
                <Smartphone className="h-3.5 w-3.5" />
                <span>{remoteEnabled ? "LAN Ativa" : "Acesso PWA"}</span>
              </button>
            </>
          )}

          <button
            type="button"
            onClick={onRefresh}
            aria-label="Atualizar dados"
            className="inline-flex items-center justify-center rounded-lg border border-slate-700/80 bg-slate-900/90 p-1.5 text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Navegação por Abas */}
      <div className="mx-auto flex max-w-7xl items-center gap-1 border-t border-slate-800/60 px-4 sm:px-6">
        <button
          type="button"
          data-testid="tab-monitoring"
          onClick={() => onSelectTab("monitoring")}
          className={`inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium transition ${
            activeTab === "monitoring"
              ? "border-cyan-400 text-cyan-200"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Activity className="h-3.5 w-3.5" />
          <span>Monitoramento &amp; Logs</span>
        </button>
        <button
          type="button"
          data-testid="tab-fix-guide"
          onClick={() => onSelectTab("fix-guide")}
          className={`inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium transition ${
            activeTab === "fix-guide"
              ? "border-emerald-400 text-emerald-200"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Wrench className="h-3.5 w-3.5" />
          <span>Como Corrigir</span>
        </button>
      </div>
    </header>
  );
}
