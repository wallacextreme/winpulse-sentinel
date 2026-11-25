import { useState, type FormEvent } from "react";
import { KeyRound, Loader2, Shield, WifiOff } from "lucide-react";

interface PinConnectOverlayProps {
  open: boolean;
  defaultServerUrl: string;
  hasOfflineCache: boolean;
  busy: boolean;
  error: string | null;
  onAuthenticate: (pin: string, serverUrl: string) => Promise<void>;
  onContinueOffline: () => void;
}

export function PinConnectOverlay({
  open,
  defaultServerUrl,
  hasOfflineCache,
  busy,
  error,
  onAuthenticate,
  onContinueOffline,
}: PinConnectOverlayProps) {
  const [serverUrl, setServerUrl] = useState(defaultServerUrl);
  const [pin, setPin] = useState("");

  if (!open) return null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!pin.trim()) return;
    await onAuthenticate(pin, serverUrl);
  };

  return (
    <div
      data-testid="pin-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#060911]/95 p-4 backdrop-blur-md"
    >
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-2xl border border-slate-800 bg-[#0b111e] p-6 shadow-2xl"
      >
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/35 bg-cyan-500/10 text-cyan-300">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Conectar ao WinPulse Sentinel
            </h2>
            <p className="text-xs text-slate-400">
              Digite o PIN exibido no PC Windows
            </p>
          </div>
        </div>

        <div className="mt-5 space-y-3.5">
          <div>
            <label
              htmlFor="server-url-input"
              className="block text-xs font-medium text-slate-300"
            >
              Endereço do Servidor LAN
            </label>
            <input
              id="server-url-input"
              type="url"
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              placeholder="http://192.168.1.10:8420"
              className="mt-1 w-full rounded-lg border border-slate-800 bg-[#060911] px-3 py-2 font-mono text-xs text-slate-100 focus:border-cyan-500/60 focus:outline-none"
            />
          </div>

          <div>
            <label
              htmlFor="pin-input"
              className="block text-xs font-medium text-slate-300"
            >
              PIN de 6 dígitos
            </label>
            <div className="relative mt-1">
              <KeyRound className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500" />
              <input
                id="pin-input"
                data-testid="pin-input"
                type="text"
                inputMode="numeric"
                maxLength={8}
                value={pin}
                onChange={(e) => setPin(e.target.value)}
                placeholder="000000"
                className="w-full rounded-lg border border-slate-800 bg-[#060911] py-2 pr-3 pl-9 font-mono text-base tracking-[0.25em] text-cyan-200 focus:border-cyan-500/60 focus:outline-none"
              />
            </div>
          </div>
        </div>

        {error && (
          <p className="mt-3 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
            {error}
          </p>
        )}

        <button
          type="submit"
          data-testid="pin-submit"
          disabled={busy || pin.trim().length < 4}
          className="mt-5 flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy && <Loader2 className="h-4 w-4 animate-spin" />}
          Conectar Sessão
        </button>

        {hasOfflineCache && (
          <button
            type="button"
            data-testid="continue-offline-btn"
            onClick={onContinueOffline}
            className="mt-2.5 flex w-full items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2 text-xs font-medium text-slate-300 transition hover:bg-slate-800"
          >
            <WifiOff className="h-3.5 w-3.5" />
            Continuar Offline com Cache Local
          </button>
        )}

        <button
          type="button"
          data-testid="enter-demo-btn"
          onClick={() => {
            const url = new URL(window.location.href);
            url.searchParams.set("demo", "1");
            window.location.assign(url.toString());
          }}
          className="mt-2.5 flex w-full items-center justify-center gap-2 rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-xs font-medium text-cyan-200 transition hover:bg-cyan-500/20"
        >
          Explorar Demo Interativa (Recrutadores)
        </button>
      </form>
    </div>
  );
}
