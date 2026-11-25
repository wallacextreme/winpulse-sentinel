import { AlertOctagon, X } from "lucide-react";
import type { AlertToast } from "../hooks/useSentinelStore";
import type { TimelineItem } from "../types/sentinel";

interface AlertToastStackProps {
  toasts: AlertToast[];
  onDismiss: (id: string) => void;
  onInspect: (item: TimelineItem) => void;
}

export function AlertToastStack({
  toasts,
  onDismiss,
  onInspect,
}: AlertToastStackProps) {
  if (toasts.length === 0) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed right-4 bottom-4 z-50 flex w-full max-w-sm flex-col gap-2"
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className="flex items-start gap-3 rounded-xl border border-rose-500/45 bg-[#120b14]/95 p-3.5 shadow-2xl backdrop-blur-md"
        >
          <AlertOctagon className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          <div className="min-w-0 flex-1">
            <p className="text-xs font-semibold text-rose-200">{toast.title}</p>
            <p className="mt-0.5 text-xs text-slate-300">{toast.body}</p>
            {toast.targetItem && (
              <button
                type="button"
                onClick={() => {
                  if (toast.targetItem) {
                    onInspect(toast.targetItem);
                    onDismiss(toast.id);
                  }
                }}
                className="mt-1.5 text-[11px] font-semibold text-cyan-300 hover:underline"
              >
                Abrir diagnóstico →
              </button>
            )}
          </div>
          <button
            type="button"
            onClick={() => onDismiss(toast.id)}
            aria-label="Fechar alerta"
            className="text-slate-400 hover:text-slate-100"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}
