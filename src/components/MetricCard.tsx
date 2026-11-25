import type { ReactNode } from "react";
import { Sparkline } from "./Sparkline";

interface MetricCardProps {
  testId: string;
  label: string;
  primaryValue: string;
  unit?: string;
  secondaryDetail: string;
  peakLabel: string;
  icon: ReactNode;
  timestamps: number[];
  values: number[];
  maxY: number;
  thresholdY?: number;
  accentColor: string;
  alertState: "normal" | "warning" | "critical";
  wasmReady: boolean;
}

export function MetricCard({
  testId,
  label,
  primaryValue,
  unit,
  secondaryDetail,
  peakLabel,
  icon,
  timestamps,
  values,
  maxY,
  thresholdY,
  accentColor,
  alertState,
  wasmReady,
}: MetricCardProps) {
  const borderClass =
    alertState === "critical"
      ? "border-rose-500/50 bg-rose-950/15"
      : alertState === "warning"
        ? "border-amber-500/40 bg-amber-950/10"
        : "border-slate-800/80 bg-[#0b111e]";

  const dotClass =
    alertState === "critical"
      ? "bg-rose-400 shadow-[0_0_8px_rgba(251,113,133,0.8)]"
      : alertState === "warning"
        ? "bg-amber-400"
        : "bg-emerald-400";

  return (
    <article
      data-testid={testId}
      className={`rounded-xl border ${borderClass} p-4 transition-colors`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-slate-400">
          <span className="text-slate-300">{icon}</span>
          <span>{label}</span>
        </div>
        <span className={`h-2 w-2 rounded-full ${dotClass}`} />
      </div>

      <div className="mt-2.5 flex items-baseline gap-1.5">
        <span className="tabular-nums text-2xl font-semibold tracking-tight text-slate-50">
          {primaryValue}
        </span>
        {unit && (
          <span className="text-xs font-medium text-slate-400">{unit}</span>
        )}
      </div>

      <p className="mt-1 truncate text-xs text-slate-400 tabular-nums">
        {secondaryDetail}
      </p>

      <div className="mt-3">
        <Sparkline
          timestamps={timestamps}
          values={values}
          maxY={maxY}
          thresholdY={thresholdY}
          color={accentColor}
          wasmReady={wasmReady}
        />
      </div>

      <div className="mt-2 flex items-center justify-between border-t border-slate-800/70 pt-2 text-[11px] text-slate-500 tabular-nums">
        <span>Janela 60s</span>
        <span>{peakLabel}</span>
      </div>
    </article>
  );
}
