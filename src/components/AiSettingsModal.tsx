import { useEffect, useState } from "react";
import {
  Bot,
  Check,
  Cloud,
  Copy,
  Cpu,
  History,
  KeyRound,
  Plug,
  RefreshCw,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import type {
  AiProviderKind,
  AiSettings,
  CommandAuditEntry,
  McpServerStatus,
  OllamaProbeResult,
  SaveAiSettingsInput,
} from "../types/sentinel";

interface AiSettingsModalProps {
  open: boolean;
  supportsExecution: boolean;
  aiSettings: AiSettings | null;
  ollamaProbe: OllamaProbeResult | null;
  mcpStatus: McpServerStatus | null;
  auditLog: CommandAuditEntry[];
  onClose: () => void;
  onRefresh: () => Promise<void>;
  onSaveSettings: (input: SaveAiSettingsInput) => Promise<AiSettings>;
  onSaveByokKey: (apiKey: string) => Promise<AiSettings>;
  onClearByokKey: () => Promise<AiSettings>;
  onProbeOllama: (baseUrl?: string) => Promise<OllamaProbeResult>;
  onToggleMcp: (enabled: boolean, port?: number) => Promise<McpServerStatus>;
  onRotateMcpToken: () => Promise<McpServerStatus>;
}

type ModalTab = "ai" | "mcp" | "audit";

export function AiSettingsModal({
  open,
  supportsExecution,
  aiSettings,
  ollamaProbe,
  mcpStatus,
  auditLog,
  onClose,
  onRefresh,
  onSaveSettings,
  onSaveByokKey,
  onClearByokKey,
  onProbeOllama,
  onToggleMcp,
  onRotateMcpToken,
}: AiSettingsModalProps) {
  const [tab, setTab] = useState<ModalTab>("ai");
  const [byokInput, setByokInput] = useState("");
  const [ollamaUrl, setOllamaUrl] = useState("http://127.0.0.1:11434");
  const [ollamaModel, setOllamaModel] = useState("");
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setFeedback(null);
    setError(null);
    if (aiSettings) {
      setOllamaUrl(aiSettings.ollamaUrl);
      setOllamaModel(aiSettings.ollamaModel);
    }
    void onRefresh();
  }, [open, aiSettings, onRefresh]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const activeProvider: AiProviderKind = aiSettings?.provider ?? "cloud_proxy";

  const copyText = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      window.setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Clipboard unavailable.
    }
  };

  const handleSelectProvider = async (provider: AiProviderKind) => {
    setBusy(true);
    setError(null);
    setFeedback(null);
    try {
      await onSaveSettings({
        provider,
        ollamaUrl,
        ollamaModel: ollamaModel || ollamaProbe?.selectedModel || "",
      });
      setFeedback("Provedor de IA atualizado.");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleSaveByok = async () => {
    if (!byokInput.trim()) return;
    setBusy(true);
    setError(null);
    setFeedback(null);
    try {
      await onSaveByokKey(byokInput.trim());
      await onSaveSettings({ provider: "gemini_byok" });
      setByokInput("");
      setFeedback("Chave Gemini salva no Cofre do Windows e ativada.");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleClearByok = async () => {
    setBusy(true);
    setError(null);
    try {
      await onClearByokKey();
      if (activeProvider === "gemini_byok") {
        await onSaveSettings({ provider: "cloud_proxy" });
      }
      setFeedback("Chave BYOK removida do Cofre do Windows.");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const handleProbeOllama = async () => {
    setBusy(true);
    setError(null);
    setFeedback(null);
    try {
      const res = await onProbeOllama(ollamaUrl);
      if (res.available && res.selectedModel && !ollamaModel) {
        setOllamaModel(res.selectedModel);
      }
      setFeedback(
        res.available
          ? `Ollama detectado (${res.models.length} modelo(s) disponível(is)).`
          : "Ollama não detectado em execução neste PC.",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const mcpSnippetJson = JSON.stringify(
    {
      mcpServers: {
        "winpulse-sentinel": {
          command: "winpulse-mcp.exe",
          args: [],
        },
      },
    },
    null,
    2,
  );

  const mcpHttpSnippet = JSON.stringify(
    {
      url: mcpStatus?.endpointUrl ?? "http://127.0.0.1:8421/mcp",
      headers: {
        Authorization: "Bearer <SEU_TOKEN_EM_%APPDATA%\\com.winpulse.sentinel\\mcp_auth.token>",
      },
    },
    null,
    2,
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="ai-settings-title"
      data-testid="ai-settings-modal"
    >
      <div className="flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-slate-800 bg-[#0b111e] shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/35 bg-cyan-500/10 text-cyan-300">
              <Bot className="h-4 w-4" />
            </div>
            <div>
              <h2 id="ai-settings-title" className="text-sm font-semibold text-slate-100">
                Central de IA Híbrida, MCP &amp; Auditoria
              </h2>
              <p className="text-xs text-slate-400">
                Nuvem gratuita pronta de fábrica, chave própria (BYOK), Ollama local e MCP
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Fechar janela de IA e MCP"
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex gap-1 border-b border-slate-800 px-5 pt-2">
          <button
            type="button"
            onClick={() => setTab("ai")}
            className={`inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium ${
              tab === "ai"
                ? "border-cyan-400 text-cyan-200"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Cloud className="h-3.5 w-3.5" />
            Provedor de IA
          </button>
          <button
            type="button"
            onClick={() => setTab("mcp")}
            className={`inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium ${
              tab === "mcp"
                ? "border-emerald-400 text-emerald-200"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Plug className="h-3.5 w-3.5" />
            Servidor MCP
          </button>
          <button
            type="button"
            onClick={() => setTab("audit")}
            className={`inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium ${
              tab === "audit"
                ? "border-amber-400 text-amber-200"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <History className="h-3.5 w-3.5" />
            Auditoria ({auditLog.length})
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto p-5">
          {!supportsExecution && (
            <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
              Você está conectado via PWA LAN (modo somente leitura). Configurações de IA, cofre BYOK e servidor MCP ficam disponíveis apenas no aplicativo Desktop Windows.
            </div>
          )}

          {error && (
            <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">
              {error}
            </div>
          )}

          {feedback && (
            <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-200">
              {feedback}
            </div>
          )}

          {tab === "ai" && (
            <div className="space-y-3.5">
              {/* Modo 1: Proxy Nuvem Gratuito */}
              <div
                className={`rounded-xl border p-4 transition ${
                  activeProvider === "cloud_proxy"
                    ? "border-cyan-500/60 bg-cyan-950/20"
                    : "border-slate-800 bg-[#070b14]"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Cloud className="h-4 w-4 text-cyan-400" />
                    <span className="text-sm font-semibold text-slate-100">
                      1. Nuvem Gratuita Padrão (Zero Configuração)
                    </span>
                  </div>
                  <button
                    type="button"
                    disabled={busy || !supportsExecution || activeProvider === "cloud_proxy"}
                    onClick={() => void handleSelectProvider("cloud_proxy")}
                    className={`rounded-lg px-3 py-1 text-xs font-semibold ${
                      activeProvider === "cloud_proxy"
                        ? "bg-cyan-500/20 text-cyan-200"
                        : "border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700"
                    }`}
                  >
                    {activeProvider === "cloud_proxy" ? "Ativo" : "Usar Padrão"}
                  </button>
                </div>
                <p className="mt-1.5 text-xs text-slate-400">
                  Usa o Cloudflare Worker seguro com cota gratuita compartilhada e redação automática de dados pessoais (PII). Não consome CPU/RAM do seu PC.
                </p>
              </div>

              {/* Modo 2: BYOK Gemini */}
              <div
                className={`rounded-xl border p-4 transition ${
                  activeProvider === "gemini_byok"
                    ? "border-emerald-500/60 bg-emerald-950/20"
                    : "border-slate-800 bg-[#070b14]"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <KeyRound className="h-4 w-4 text-emerald-400" />
                    <span className="text-sm font-semibold text-slate-100">
                      2. Minha Chave Gemini (BYOK)
                    </span>
                  </div>
                  {aiSettings?.hasByokKey && (
                    <button
                      type="button"
                      disabled={busy || !supportsExecution || activeProvider === "gemini_byok"}
                      onClick={() => void handleSelectProvider("gemini_byok")}
                      className={`rounded-lg px-3 py-1 text-xs font-semibold ${
                        activeProvider === "gemini_byok"
                          ? "bg-emerald-500/20 text-emerald-200"
                          : "border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700"
                      }`}
                    >
                      {activeProvider === "gemini_byok" ? "Ativo" : "Ativar BYOK"}
                    </button>
                  )}
                </div>
                <p className="mt-1.5 text-xs text-slate-400">
                  Cole sua chave gratuita do Google AI Studio. Ela é salva no Cofre de Credenciais do Windows e nunca vai para o proxy compartilhado.
                </p>

                {aiSettings?.hasByokKey && (
                  <div className="mt-2.5 flex items-center justify-between rounded-lg border border-slate-800 bg-[#05080f] px-3 py-2 text-xs">
                    <span className="font-mono text-emerald-300">
                      Chave salva: {aiSettings.maskedByokKey}
                    </span>
                    <button
                      type="button"
                      disabled={busy || !supportsExecution}
                      onClick={() => void handleClearByok()}
                      className="inline-flex items-center gap-1 text-rose-300 hover:text-rose-200"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      Remover
                    </button>
                  </div>
                )}

                <div className="mt-2.5 flex gap-2">
                  <input
                    type="password"
                    value={byokInput}
                    onChange={(e) => setByokInput(e.target.value)}
                    placeholder="Cole sua chave do Google AI Studio"
                    disabled={!supportsExecution || busy}
                    className="flex-1 rounded-lg border border-slate-800 bg-[#05080f] px-3 py-1.5 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-emerald-500/60 focus:outline-none"
                  />
                  <button
                    type="button"
                    disabled={!supportsExecution || busy || !byokInput.trim()}
                    onClick={() => void handleSaveByok()}
                    className="rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-3 py-1.5 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/25 disabled:opacity-50"
                  >
                    Salvar no Cofre
                  </button>
                </div>
              </div>

              {/* Modo 3: Ollama Local */}
              <div
                className={`rounded-xl border p-4 transition ${
                  activeProvider === "ollama_local"
                    ? "border-violet-500/60 bg-violet-950/20"
                    : "border-slate-800 bg-[#070b14]"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-violet-400" />
                    <span className="text-sm font-semibold text-slate-100">
                      3. Ollama Local (100% Offline, Auto-Detectado)
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={busy || !supportsExecution}
                      onClick={() => void handleProbeOllama()}
                      className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-700"
                    >
                      <RefreshCw className="h-3 w-3" />
                      Detectar
                    </button>
                    {ollamaProbe?.available && (
                      <button
                        type="button"
                        disabled={busy || !supportsExecution || activeProvider === "ollama_local"}
                        onClick={() => void handleSelectProvider("ollama_local")}
                        className={`rounded-lg px-3 py-1 text-xs font-semibold ${
                          activeProvider === "ollama_local"
                            ? "bg-violet-500/20 text-violet-200"
                            : "border border-violet-500/40 bg-violet-500/15 text-violet-200 hover:bg-violet-500/25"
                        }`}
                      >
                        {activeProvider === "ollama_local" ? "Ativo" : "Usar Ollama"}
                      </button>
                    )}
                  </div>
                </div>
                <p className="mt-1.5 text-xs text-slate-400">
                  {ollamaProbe?.available
                    ? `Ollama detectado em ${ollamaProbe.baseUrl} (${ollamaProbe.models.join(", ") || "sem modelos"}).`
                    : "Nenhum Ollama rodando neste PC. Se você instalar/iniciar o Ollama futuramente, ele aparecerá aqui automaticamente."}
                </p>

                <div className="mt-2.5 grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <input
                    type="text"
                    value={ollamaUrl}
                    onChange={(e) => setOllamaUrl(e.target.value)}
                    disabled={!supportsExecution}
                    placeholder="http://127.0.0.1:11434"
                    className="rounded-lg border border-slate-800 bg-[#05080f] px-3 py-1.5 font-mono text-xs text-slate-200"
                  />
                  <select
                    value={ollamaModel}
                    onChange={(e) => setOllamaModel(e.target.value)}
                    disabled={!supportsExecution || !(ollamaProbe?.models.length)}
                    className="rounded-lg border border-slate-800 bg-[#05080f] px-3 py-1.5 font-mono text-xs text-slate-200"
                  >
                    <option value="">
                      {ollamaProbe?.models.length
                        ? "Selecionar modelo..."
                        : "Sem modelos detectados"}
                    </option>
                    {ollamaProbe?.models.map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
          )}

          {tab === "mcp" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-[#070b14] p-4">
                <div>
                  <p className="text-sm font-semibold text-slate-100">
                    Servidor MCP Loopback ({mcpStatus?.enabled ? "Ativo" : "Desativado"})
                  </p>
                  <p className="mt-0.5 font-mono text-xs text-slate-400">
                    {mcpStatus?.endpointUrl ?? "http://127.0.0.1:8421/mcp"} · Token:{" "}
                    {mcpStatus?.tokenPreview ?? "••••••"}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={busy || !supportsExecution}
                    onClick={() => void onRotateMcpToken()}
                    className="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs text-slate-200 hover:bg-slate-700"
                  >
                    Novo Token
                  </button>
                  <button
                    type="button"
                    disabled={busy || !supportsExecution}
                    onClick={() =>
                      void onToggleMcp(!(mcpStatus?.enabled ?? false), mcpStatus?.port)
                    }
                    className={`rounded-lg px-3 py-1.5 text-xs font-semibold ${
                      mcpStatus?.enabled
                        ? "border border-rose-500/40 bg-rose-500/15 text-rose-200"
                        : "border border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
                    }`}
                  >
                    {mcpStatus?.enabled ? "Desativar" : "Ativar"}
                  </button>
                </div>
              </div>

              <div className="rounded-xl border border-slate-800 bg-[#070b14] p-4">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                    Configuração stdio (Antigravity / Claude Desktop / Cursor)
                  </span>
                  <button
                    type="button"
                    onClick={() => void copyText("mcp-stdio", mcpSnippetJson)}
                    className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] text-slate-200"
                  >
                    {copiedKey === "mcp-stdio" ? (
                      <Check className="h-3 w-3 text-emerald-400" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                    Copiar JSON
                  </button>
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  O bridge <code className="text-cyan-300">winpulse-mcp.exe</code> roda sem privilégio Admin e conversa com o Sentinel via loopback autenticado. Comandos sugeridos pela IA externa abrem o modal de aprovação humana aqui no app.
                </p>
                <pre className="mt-2 overflow-x-auto rounded-lg bg-[#04070d] p-3 font-mono text-[11px] text-cyan-200">
                  {mcpSnippetJson}
                </pre>
              </div>

              <div className="rounded-xl border border-slate-800 bg-[#070b14] p-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-200">
                    Configuração HTTP Loopback Direto (127.0.0.1)
                  </span>
                  <button
                    type="button"
                    onClick={() => void copyText("mcp-http", mcpHttpSnippet)}
                    className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] text-slate-200"
                  >
                    {copiedKey === "mcp-http" ? (
                      <Check className="h-3 w-3 text-emerald-400" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                    Copiar
                  </button>
                </div>
                <pre className="mt-2 overflow-x-auto rounded-lg bg-[#04070d] p-3 font-mono text-[11px] text-slate-300">
                  {mcpHttpSnippet}
                </pre>
              </div>
            </div>
          )}

          {tab === "audit" && (
            <div className="space-y-2.5">
              {auditLog.length === 0 ? (
                <p className="rounded-xl border border-slate-800 bg-[#070b14] p-4 text-xs text-slate-400">
                  Nenhum comando foi submetido à fila de aprovação ainda.
                </p>
              ) : (
                auditLog.map((entry) => (
                  <div
                    key={entry.approvalId}
                    className="rounded-xl border border-slate-800 bg-[#070b14] p-3.5 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] uppercase text-cyan-300">
                          {entry.source} · {entry.shell}
                        </span>
                        <span className="font-mono text-[11px] text-slate-400">
                          {new Date(entry.createdAtMs).toLocaleString("pt-BR")}
                        </span>
                      </div>
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-semibold uppercase ${
                          entry.status === "succeeded"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : entry.status === "rejected" || entry.status === "cancelled"
                              ? "bg-amber-500/15 text-amber-300"
                              : "bg-rose-500/15 text-rose-300"
                        }`}
                      >
                        {entry.status}
                        {entry.exitCode !== null ? ` (${entry.exitCode})` : ""}
                      </span>
                    </div>
                    <pre className="mt-2 overflow-x-auto rounded bg-[#04070d] p-2 font-mono text-[11px] text-slate-200">
                      {entry.command}
                    </pre>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
