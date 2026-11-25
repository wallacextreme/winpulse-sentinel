# Relatório de Auditoria de Segurança — WinPulse Sentinel

**Data:** 2026-11-25  
**Escopo:** Comandos IPC Tauri v2 (`src-tauri/src/commands.rs`, `src-tauri/tauri.conf.json`, `src-tauri/capabilities/default.json`), servidor HTTP/WebSocket Axum LAN (`src-tauri/src/server.rs`), carregador de override da Base de Conhecimento (`src-tauri/src/translator.rs`), cliente PWA (`src/transport/pwaTransport.ts`) e superfície de execução elevada (Windows UAC `requireAdministrator`).  
**Metodologia:** Análise estática orientada a fronteiras de confiança (`cloudflare/security-audit`), verificação por testes unitários/integração em Rust (`cargo test --workspace`) e testes E2E Playwright.

---

## 1. Mapa de Fronteiras de Confiança

1. **WebView2 / Frontend ↔ Backend Rust (Tauri IPC):**
   - Comandos expostos via `tauri::generate_handler!`: `health_check`, `get_collector_status`, `get_recent_telemetry`, `get_timeline`, `get_incident_detail`, `set_collection_paused`, `get_remote_server_status`, `toggle_remote_server`, `regenerate_remote_pin`.
   - CSP restritiva em `tauri.conf.json` (`default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`).
   - SQLite parametrizado com `rusqlite::params![]` em todas as consultas (`src-tauri/src/db.rs`).
2. **Dispositivo LAN / Navegador PWA ↔ Servidor Axum (`0.0.0.0:<port>`):**
   - Exposto apenas quando ativado explicitamente pelo usuário (System Tray ou modal no Desktop).
   - Autenticação por PIN efêmero de 6 dígitos (`rand::rng()`, comparação em tempo constante via `subtle::ConstantTimeEq`) trocado por token de sessão Bearer e tickets WebSocket de uso único.
3. **Host Local Windows (UAC `requireAdministrator`) ↔ Arquivos/APIs Win32:**
   - Leitura em tempo real de canais protegidos do Event Log via `EvtSubscribe` (`System` e `Application`), contadores PDH em inglês (`PhysicalDisk(_Total)`), e override opcional de `knowledge_base.json` em `app_data_dir`.

---

## 2. Achados Identificados, Remediações e Evidências

| ID | Severidade Original | Superfície | Descrição do Achado | Correção Aplicada | Status |
|---|---|---|---|---|---|
| **F-01** | **Alta** | `server.rs` (`is_allowed_lan_origin`) | Parsing manual de `Origin` por `split(':')` permitia bypass com userinfo (`http://127.0.0.1:80@evil.com`), possibilitando requisições CORS de origens externas maliciosas quando o servidor LAN estivesse ativo. | Substituído por parsing estrito com `axum::http::Uri`, rejeitando `@`, whitespace, `?`, `#`, caminhos extras e aceitando apenas `http`/`https`/`tauri` para `localhost`, `127.0.0.1`, `tauri.localhost` ou IPv4 RFC1918/loopback. | **CORRIGIDO** |
| **F-02** | **Alta** | `server.rs` (`ws_handler`) & `pwaTransport.ts` | Token Bearer de longa duração (24h) aceito na query string `/ws?token=...`, expondo credencial de sessão em logs/histórico, sem checagem de `Origin` no upgrade WS, sem limite de conexões WS e sem revogação imediata de sockets ativos ao regenerar PIN ou parar servidor. | Implementado endpoint autenticado `POST /api/auth/ws-ticket` emitindo ticket de uso único (TTL 30s, removido após consumo); `ws_handler` valida `Origin`, impõe `MAX_WS_CLIENTS = 16` e usa `watch::Sender<u64>` (`auth_epoch`) para encerrar todos os WebSockets ativos ao regenerar PIN ou desligar o servidor. | **CORRIGIDO** |
| **F-03** | **Média** | `server.rs` (`AuthStore::verify_pin`) | Rate-limiting apenas por `IpAddr` sem teto global e sem limite máximo de entradas no `HashMap` permitia brute-force distribuído/spoofed na LAN ou crescimento ilimitado de memória. | Adicionado teto global (`MAX_GLOBAL_FAILED_ATTEMPTS = 20` / 60s), limpeza contínua de janelas expiradas e limite máximo (`MAX_TRACKED_FAILED_IPS = 256`) em `AuthStore`. | **CORRIGIDO** |
| **F-04** | **Média** | `server.rs` (`build_router`), `commands.rs` | Ausência de `DefaultBodyLimit` explícito, ausência de cabeçalhos de segurança HTTP (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `CSP`) nas respostas Axum e permissão de porta privilegiada `< 1024` em `toggle_remote_server`. | Adicionado `DefaultBodyLimit::max(4096)`, middleware `security_headers_middleware` e validação `validate_remote_port` rejeitando portas `< 1024`. | **CORRIGIDO** |
| **F-05** | **Baixa** | `translator.rs`, `tauri.conf.json` | Carregamento do arquivo opcional `knowledge_base.json` sem limite de tamanho antes de `read_to_string` sob contexto elevado; CSP sem `object-src 'none'`, `frame-ancestors 'none'` e `base-uri 'self'`. | Adicionada checagem de tamanho máximo (`MAX_KB_OVERRIDE_BYTES = 2 MiB`) via `fs::metadata` antes da leitura e diretivas CSP endurecidas em `tauri.conf.json`. | **CORRIGIDO** |

---

## 3. Análise Específica de Elevação Windows (UAC `requireAdministrator`)

- **Justificativa Técnica:** Canais do Event Log do Windows (especialmente eventos de hardware/disco/energia como `Kernel-Power` 41, `WER` 1001 e drivers `storahci`/`nvme`/`Ntfs`) exigem privilégios elevados ou associação explícita ao grupo local *Event Log Readers* em máquinas com endurecimento de ACLs.
- **Controles de Mitigação Aplicados:**
  1. O binário desktop nunca expõe comandos destrutivos, shell execution (`shell` plugin ausente), escrita arbitrária de arquivos ou bind de rede automático: o servidor LAN nasce **desligado** e é somente-leitura para clientes remotos (`set_collection_paused`, `toggle_remote_server` e `regenerate_remote_pin` não existem na API Axum).
  2. Todos os parsers que consomem dados externos sob contexto elevado (`quick-xml` para eventos Win32, `rusqlite` parametrizado, `AuthStore` constant-time, limite de 2 MiB no override JSON) operam sem `unsafe` adicional e sem `.unwrap()`/`.expect()`.
  3. **Alternativa de Menor Privilégio (Hardening Operacional):** Em ambientes corporativos onde UAC elevado contínuo não seja desejado, o administrador pode incluir o usuário no grupo `Event Log Readers` (`net localgroup "Event Log Readers" <usuario> /add`), permitindo leitura de logs sem privilégio integral de Administrador (o aplicativo exibe o indicador `Admin` vs `Padrão` na barra superior).

---

## 4. Resultado Final da Auditoria

- **Achados Críticos Abertos:** `0`
- **Achados Altos Abertos:** `0`
- **Achados Médios/Baixos Abertos:** `0`
- **Verificação Automatizada:** Testes de regressão em `src-tauri/src/server.rs`, `commands.rs` e E2E Playwright (`e2e/pwa.spec.ts`) validam origem CORS, tickets WebSocket de uso único, rate-limiting global/por IP, headers de segurança, path traversal e fluxo completo PWA.
