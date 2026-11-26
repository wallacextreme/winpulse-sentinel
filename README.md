# WinPulse Sentinel

[![Demo Interativa (Recrutadores)](https://img.shields.io/badge/🌐_Demo_Interativa_(PWA)-06b6d4?style=for-the-badge)](https://wallacextreme.github.io/winpulse-sentinel/?demo=1)
[![Tauri v2](https://img.shields.io/badge/Tauri_v2-Rust-orange?style=for-the-badge&logo=tauri)](https://v2.tauri.app/)
[![WebAssembly](https://img.shields.io/badge/WASM-LTTB_60fps-654ff0?style=for-the-badge&logo=webassembly)](https://webassembly.org/)

Aplicativo híbrido de alta performance para Windows 10/11 (**Tauri v2 + Rust**) com **Caixa-Preta de Hardware (Flight Recorder)**, assinatura em tempo real de **Event Logs via Win32 `EvtSubscribe`**, tradução PT-BR embutida (`knowledge_base.json`), **motor de correlação inteligente `[T - 15s, T + 5s]`**, **WebAssembly (`sentinel-wasm`)** para downsampling **LTTB** e busca client-side, e **PWA multi-dispositivo** via servidor **Axum LAN** protegido por PIN efêmero.

> **Demo Online para Recrutadores:** Acesse [https://wallacextreme.github.io/winpulse-sentinel/?demo=1](https://wallacextreme.github.io/winpulse-sentinel/?demo=1) para testar o painel em tempo real com telemetria simulada, detecção de gargalos, correlação `[T - 15s, T + 5s]`, busca Wasm e Guia de Correções sem precisar instalar o executável Windows.

## Arquitetura

- **Backend Nativo (`src-tauri/src/`):**
  - **Módulo A (`telemetry/`):** Coleta assíncrona 1000ms (`sysinfo`, PDH `PhysicalDisk(_Total)` em inglês, probe ICMP `1.1.1.1`), Ring Buffer de 60s em RAM e persistência SQLite WAL apenas quando métricas excedem 90% (ou latência de disco > 100ms) por 5s consecutivos (capturando Top 5 processos ofensores).
  - **Módulo B (`eventlog/`):** `EvtSubscribe` push nos canais `System` e `Application` com filtro XPath nativo + parser `quick-xml`.
  - **Módulo C (`translator.rs`):** `knowledge_base.json` embutido via `include_str!` com fallback e suporte a override externo (limite de 2 MiB).
  - **Módulo D (`correlator.rs`):** Correlação bidirecional na janela `[T - 15s, T + 5s]` entre eventos Windows, snapshots persistidos e Ring Buffer.
  - **Servidor LAN (`server.rs`) & Tray (`tray.rs`):** Axum HTTP/WebSocket opcional em LAN com PIN de 6 dígitos (constant-time `subtle`), tickets WebSocket de uso único, rate-limiting global/por IP, headers de segurança, System Tray e notificações toast nativas.
  - **IA Híbrida, MCP & Executor Assistido (`ai.rs`, `mcp.rs`, `executor.rs`, `sanitizer.rs`, `secrets.rs`):** Diagnóstico inteligente via Proxy Cloudflare gratuito, BYOK Gemini (salvo no Windows Credential Manager) ou Ollama auto-detectado em `127.0.0.1:11434`, com redação automática de PII, servidor MCP loopback (`127.0.0.1:8421` + bridge não-elevado `crates/sentinel-mcp`) e execução PowerShell/CMD exclusivamente após aprovação humana na interface Desktop.
- **Proxy Nuvem (`proxy-worker/`):** Cloudflare Worker `winpulse-ai-proxy` com *System Prompt* travado, schema estrito e rate limit nativo gratuito.
- **WebAssembly (`crates/sentinel-wasm/`):**
  - Downsampling **LTTB (Largest-Triangle-Three-Buckets)** para sparklines a 60fps.
  - Busca instantânea insensível a acentos PT-BR, contagem de facetas e correlação offline.
- **Frontend & PWA (`src/`):**
  - Bun + Vite + React + TypeScript strict + Tailwind CSS v4 + `vite-plugin-pwa`.
  - Adapter pattern automático: `TauriTransport` (IPC) vs `PwaWebSocketTransport` (LAN + cache offline).

## Pré-requisitos

- **Bun** (`>= 1.3`)
- **Rust** (`>= 1.90`) com target `wasm32-unknown-unknown` (`rustup target add wasm32-unknown-unknown`)
- **Visual Studio Build Tools (MSVC)** + **WebView2 Runtime** (Windows 10/11)

## Comandos de Desenvolvimento

```powershell
# Instalar dependências JS/TS e wasm-pack local
bun install

# Compilar o módulo WebAssembly (crates/sentinel-wasm -> src/wasm/pkg)
bun run build:wasm

# Executar frontend web/PWA isolado
bun run dev

# Executar app Desktop Tauri em desenvolvimento
bun run tauri dev

# Executar dev com manifesto UAC requireAdministrator habilitado
$env:WINPULSE_UAC_MANIFEST = "1"; bun run tauri dev
```

## Testes & Auditoria

```powershell
# Testes unitários e de integração Rust (workspace completo)
cargo test --workspace

# Testes unitários TS + Wasm + Transport Adapter
bun test

# Verificação de tipos e build de produção Vite + PWA
bun run build

# Testes E2E Playwright (Desktop PWA 1280x820 e Mobile PWA 390x844)
bun run test:e2e
```

Consulte também o relatório de segurança em [docs/SECURITY_AUDIT_REPORT.md](docs/SECURITY_AUDIT_REPORT.md).

## Empacotamento Windows (NSIS `.exe` / WiX `.msi` + UAC)

Os builds de produção (`release`) incorporam automaticamente o manifesto UAC `requireAdministrator` definido em `src-tauri/winpulse-sentinel.exe.manifest` para acesso completo aos canais protegidos do Event Log do Windows, além de empacotar `dist/` como recurso interno para o servidor PWA LAN.

```powershell
# Gerar instalador NSIS (.exe) — recomendado
bun run tauri:build:nsis

# Gerar instalador WiX (.msi)
bun run tauri:build:msi

# Gerar ambos os instaladores (NSIS + MSI)
bun run tauri:build:all
```

Saídas geradas em `target/release/`:
- Executável principal: `target/release/winpulse-sentinel.exe`
- Instalador NSIS: `target/release/bundle/nsis/WinPulse Sentinel_0.2.1_x64-setup.exe`
- Instalador MSI: `target/release/bundle/msi/WinPulse Sentinel_0.2.1_x64_pt-BR.msi`
- Bridge MCP não-elevado (`stdio`): `cargo build --release -p sentinel-mcp` -> `target/release/winpulse-mcp.exe`
