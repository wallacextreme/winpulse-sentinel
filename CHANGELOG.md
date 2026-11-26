# Changelog

Todas as mudanças relevantes do **WinPulse Sentinel** são documentadas neste arquivo.

## [0.2.0] - 2026-11-26

### Adicionado
- **Motor de IA Híbrida (`src-tauri/src/ai.rs` & `proxy-worker/`):** Diagnóstico assistido em PT-BR com 3 modos — Proxy Nuvem Gratuito (`winpulse-ai-proxy` no Cloudflare Workers com Rate Limiting nativo), Gemini BYOK (chave salva no Windows Credential Manager via `CredWriteW`/`CredReadW`) e detecção automática silenciosa de Ollama local (`127.0.0.1:11434`, protegido contra SSRF).
- **Sanitização Determinística de PII (`src-tauri/src/sanitizer.rs`):** Redação automática de caminhos `C:\Users\*`, `<Computer>`, SIDs (`S-1-5-*`), e-mails, IPs privados e tokens antes de qualquer envio externo ou resposta MCP, com pré-visualização na interface.
- **Executor PowerShell/CMD Human-in-the-Loop (`src-tauri/src/executor.rs` & `CommandApprovalModal.tsx`):** Policy Gate bloqueando vetores destrutivos/ofuscados, ticket criptográfico de 2 fases (TTL 5 min), aprovação explícita na tela, streaming em tempo real e trilha de auditoria SQLite (`migrations/002_ai_and_audit.sql`).
- **Servidor MCP Loopback & Bridge `stdio` (`src-tauri/src/mcp.rs` & `crates/sentinel-mcp`):** Endpoint JSON-RPC 2.0 em `127.0.0.1:8421` protegido por Bearer Token (`subtle::ConstantTimeEq`) e binário não-elevado `winpulse-mcp.exe` para clientes MCP (`Antigravity`, `Claude Desktop`, `Cursor`).

### Segurança
- Mantido o servidor PWA LAN (`0.0.0.0:8420`) 100% somente-leitura, a CSP estrita de `tauri.conf.json` e a ausência de `tauri-plugin-shell`.
- Nenhuma chave de API embutida no executável ou no repositório Git.

## [0.1.0] - 2026-11-25

### Adicionado
- Lançamento inicial do **WinPulse Sentinel** (Tauri v2 + Rust + React + `sentinel-wasm`) com Caixa-Preta 60s, assinatura `EvtSubscribe`, correlação `[T - 15s, T + 5s]`, tradução PT-BR embutida e PWA LAN protegido por PIN.
