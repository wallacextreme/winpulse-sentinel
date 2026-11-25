import type { KnowledgeBaseEntry, Severity } from "../types/sentinel";

export interface FixCommand {
  label: string;
  command: string;
  requiresAdmin?: boolean;
}

export interface FixGuideEntry {
  id: string;
  kind: "windows_event" | "exception_code" | "module_dll" | "bsod_stop" | "windows_app";
  codes: string[];
  category: string;
  severity: Severity;
  title: string;
  whatHappened: string;
  probableCauses: string[];
  solutions: string[];
  commands: FixCommand[];
}

export interface AnalyzedErrorDiagnosis {
  headline: string;
  detectedApp: string | null;
  detectedModule: string | null;
  detectedCode: string | null;
  detectedEventId: number | null;
  isStoreApp: boolean;
  whatHappened: string;
  probableCauses: string[];
  solutions: string[];
  commands: FixCommand[];
  matchedGuides: FixGuideEntry[];
}

export const EXTRA_FIX_GUIDES: FixGuideEntry[] = [
  {
    id: "EXC_C0000409",
    kind: "exception_code",
    codes: ["c0000409", "0xc0000409", "MoBEX", "BEX64", "BEX", "STATUS_STACK_BUFFER_OVERRUN"],
    category: "Aplicativos & Runtime",
    severity: "high",
    title: "Erro de proteção de memória / Fast-Fail (c0000409 / MoBEX)",
    whatHappened:
      "O aplicativo detectou uma corrupção interna de pilha ou falha crítica de segurança (STATUS_STACK_BUFFER_OVERRUN / MoBEX) e foi encerrado imediatamente pelo Windows para proteger o sistema.",
    probableCauses: [
      "Arquivos do aplicativo (especialmente apps da Microsoft Store / WindowsApps) corrompidos após atualização.",
      "Biblioteca do sistema (como ucrtbase.dll ou Visual C++ Runtime) inconsistente.",
      "Plugin, extensão ou overlay (Discord, GeForce Experience, RivaTuner) interferindo no processo.",
    ],
    solutions: [
      "Se for app do Windows (Paint, Fotos, Calculadora, etc.), vá em Configurações → Aplicativos → Aplicativos instalados → [Nome do App] → Opções avançadas → clique em Reparar (e depois Redefinir se persistir).",
      "Execute a verificação de arquivos do sistema (sfc /scannow) e reparo da imagem do Windows (DISM) em um Terminal como Administrador.",
      "Reinstale ou atualize o pacote Microsoft Visual C++ Redistributable (x64 e x86) mais recente.",
      "Teste desativar temporariamente overlays de tela ou extensões do programa afetado.",
    ],
    commands: [
      { label: "Verificar arquivos do Windows (SFC)", command: "sfc /scannow", requiresAdmin: true },
      {
        label: "Reparar imagem do sistema (DISM)",
        command: "DISM /Online /Cleanup-Image /RestoreHealth",
        requiresAdmin: true,
      },
    ],
  },
  {
    id: "EXC_C0000005",
    kind: "exception_code",
    codes: ["c0000005", "0xc0000005", "ACCESS_VIOLATION", "APPCRASH"],
    category: "Aplicativos & Runtime",
    severity: "high",
    title: "Violação de Acesso à Memória (0xc0000005 / ACCESS_VIOLATION)",
    whatHappened:
      "O programa tentou ler ou gravar em uma região de memória inválida ou protegida pelo Windows e foi fechado abruptamente.",
    probableCauses: [
      "Bug interno no aplicativo, mod ou extensão desatualizada.",
      "Driver de vídeo ou áudio incompatível ou corrompido.",
      "Instabilidade de memória RAM (perfil XMP/DOCP instável ou módulo com defeito).",
      "Antivírus ou software de proteção bloqueando acesso do executável.",
    ],
    solutions: [
      "Atualize ou reinstale o programa que apresentou o erro.",
      "Atualize o driver da placa de vídeo e desative overlays/mods para isolar o conflito.",
      "Execute o Diagnóstico de Memória do Windows (mdsched.exe) se o erro 0xc0000005 ocorrer em vários programas diferentes.",
      "Execute sfc /scannow como Administrador para reparar DLLs do sistema.",
    ],
    commands: [
      { label: "Diagnóstico de Memória RAM", command: "mdsched.exe", requiresAdmin: true },
      { label: "Verificar integridade do sistema", command: "sfc /scannow", requiresAdmin: true },
    ],
  },
  {
    id: "MOD_UCRTBASE",
    kind: "module_dll",
    codes: ["ucrtbase.dll", "vcruntime140.dll", "msvcp140.dll", "c0000135", "0xc0000135"],
    category: "Bibliotecas C++ / Windows",
    severity: "high",
    title: "Falha no Universal C Runtime / Visual C++ (ucrtbase.dll / vcruntime140.dll)",
    whatHappened:
      "O aplicativo falhou dentro da biblioteca base da linguagem C/C++ do Windows (ucrtbase.dll ou Visual C++ Redistributable), geralmente acionada por erro interno do programa ou arquivos corrompidos do sistema.",
    probableCauses: [
      "Pacote do aplicativo corrompido (comum em apps de WindowsApps como Paint, Snipping Tool e Fotos).",
      "Microsoft Visual C++ Redistributable desatualizado ou danificado.",
      "Arquivos protegidos do Windows corrompidos após desligamento brusco ou Windows Update.",
    ],
    solutions: [
      "Repare ou redefina o programa afetado em Configurações → Aplicativos → Aplicativos instalados → Opções avançadas.",
      "Execute sfc /scannow seguido de DISM /Online /Cleanup-Image /RestoreHealth no Terminal como Administrador.",
      "Baixe e instale a versão mais recente do Microsoft Visual C++ 2015-2022 Redistributable (x64 e x86) e reinicie o PC.",
    ],
    commands: [
      { label: "Reparar DLLs protegidas (SFC)", command: "sfc /scannow", requiresAdmin: true },
      {
        label: "Reparar imagem do Windows (DISM)",
        command: "DISM /Online /Cleanup-Image /RestoreHealth",
        requiresAdmin: true,
      },
    ],
  },
  {
    id: "MOD_NTDLL",
    kind: "module_dll",
    codes: ["ntdll.dll", "kernelbase.dll", "c0000374", "0xc0000374"],
    category: "Bibliotecas C++ / Windows",
    severity: "high",
    title: "Falha em biblioteca central do Windows (ntdll.dll / kernelbase.dll / 0xc0000374)",
    whatHappened:
      "O programa disparou uma corrupção de heap (0xc0000374) ou exceção não tratada dentro das bibliotecas centrais do Windows (ntdll.dll / kernelbase.dll).",
    probableCauses: [
      "Conflito de shell extension, driver de terceiros ou antivírus injetando DLLs no processo.",
      "Corrupção no perfil local/cache do aplicativo.",
      "Arquivos do sistema corrompidos.",
    ],
    solutions: [
      "Limpe o cache do programa ou teste executá-lo com extensões/plugins desativados.",
      "Rode sfc /scannow e DISM /Online /Cleanup-Image /RestoreHealth como Administrador.",
      "Verifique se há atualizações pendentes no Windows Update e nos drivers da placa-mãe/vídeo.",
    ],
    commands: [
      { label: "Verificar arquivos do Windows", command: "sfc /scannow", requiresAdmin: true },
    ],
  },
  {
    id: "MOD_GPU_DRIVERS",
    kind: "module_dll",
    codes: [
      "nvlddmkm.sys",
      "nvlddmkm.dll",
      "amdkmdag.sys",
      "igdkmd64.sys",
      "d3d11.dll",
      "dxgi.dll",
      "VIDEO_TDR_FAILURE",
      "VIDEO_DXGKRNL_FATAL_ERROR",
    ],
    category: "Placa de Vídeo (GPU)",
    severity: "critical",
    title: "Falha de Driver de Vídeo ou DirectX (nvlddmkm / amdkmdag / d3d11.dll)",
    whatHappened:
      "O driver da placa de vídeo (NVIDIA, AMD ou Intel) ou a camada gráfica DirectX parou de responder, derrubando o jogo/aplicativo ou causando tela preta/BSOD (VIDEO_TDR_FAILURE).",
    probableCauses: [
      "Driver de vídeo corrompido ou atualização sobreposta sem instalação limpa.",
      "Superaquecimento da GPU ou overclock/undervolt instável.",
      "Falta de memória de vídeo (VRAM) ou alimentação instável da fonte.",
    ],
    solutions: [
      "Remova o driver atual com o DDU (Display Driver Uninstaller) em Modo de Segurança e instale a versão estável mais recente.",
      "Desative overclock de GPU/VRAM (MSI Afterburner) e monitore a temperatura sob carga.",
      "Em navegadores ou apps de produtividade, teste desativar temporariamente a 'Aceleração de Hardware'.",
    ],
    commands: [
      {
        label: "Abrir Diagnóstico do DirectX",
        command: "dxdiag",
        requiresAdmin: false,
      },
    ],
  },
  {
    id: "APP_WINDOWS_STORE",
    kind: "windows_app",
    codes: [
      "mspaint.exe",
      "Microsoft.Paint",
      "WindowsApps",
      "Photos.exe",
      "SnippingTool.exe",
      "CalculatorApp.exe",
      "Microsoft.WindowsStore",
    ],
    category: "Apps da Microsoft Store",
    severity: "medium",
    title: "Falha em aplicativo nativo da Microsoft Store (WindowsApps / Paint / Fotos)",
    whatHappened:
      "Um aplicativo empacotado do Windows (pasta WindowsApps, como Paint, Fotos, Ferramenta de Captura ou Calculadora) encerrou inesperadamente por falha no pacote ou cache local.",
    probableCauses: [
      "Atualização incompleta do app pela Microsoft Store.",
      "Cache local do pacote UWP/MSIX corrompido.",
      "Inconsistência na biblioteca ucrtbase.dll ou registro do pacote AppX.",
    ],
    solutions: [
      "Vá em Configurações → Aplicativos → Aplicativos instalados → encontre o aplicativo (ex.: Paint) → Opções avançadas → clique em Reparar.",
      "Se continuar fechando, clique em Redefinir na mesma tela (limpa cache corrompido sem afetar seus arquivos pessoais).",
      "Limpe o cache da Microsoft Store executando wsreset.exe e verifique atualizações na Store.",
      "Se o problema persistir em vários apps nativos, rode sfc /scannow no Terminal como Administrador.",
    ],
    commands: [
      { label: "Limpar cache da Microsoft Store", command: "wsreset.exe", requiresAdmin: false },
      { label: "Verificar arquivos do Windows", command: "sfc /scannow", requiresAdmin: true },
    ],
  },
  {
    id: "APP_EXPLORER_SHELL",
    kind: "windows_app",
    codes: ["explorer.exe", "SearchHost.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe"],
    category: "Interface do Windows",
    severity: "medium",
    title: "Travamento do Explorador de Arquivos ou Barra de Tarefas (explorer.exe)",
    whatHappened:
      "A interface gráfica do Windows (Explorador de Arquivos, Menu Iniciar ou Pesquisa) congelou ou reiniciou sozinha.",
    probableCauses: [
      "Extensão de menu de contexto de terceiros (antivírus, compactadores, nuvem) travando o shell.",
      "Acesso a uma pasta de rede desconectada ou HD/SSD com lentidão severa.",
      "Arquivos corrompidos do sistema ou índice de pesquisa danificado.",
    ],
    solutions: [
      "Reinicie o processo explorer.exe pelo Gerenciador de Tarefas (Ctrl+Shift+Esc) ou pelo comando abaixo.",
      "Limpe o histórico do Explorador de Arquivos em Opções de Pasta → Geral → Limpar.",
      "Execute sfc /scannow e DISM /Online /Cleanup-Image /RestoreHealth como Administrador.",
    ],
    commands: [
      {
        label: "Reiniciar Explorer com segurança",
        command: "taskkill /f /im explorer.exe && start explorer.exe",
        requiresAdmin: false,
      },
      { label: "Verificar arquivos do sistema", command: "sfc /scannow", requiresAdmin: true },
    ],
  },
  {
    id: "BSOD_MEMORY_WHEA",
    kind: "bsod_stop",
    codes: [
      "MEMORY_MANAGEMENT",
      "IRQL_NOT_LESS_OR_EQUAL",
      "PAGE_FAULT_IN_NONPAGED_AREA",
      "CRITICAL_PROCESS_DIED",
      "WHEA_UNCORRECTABLE_ERROR",
      "KERNEL_DATA_INPAGE_ERROR",
    ],
    category: "Tela Azul (BSOD)",
    severity: "critical",
    title: "Códigos de Parada Críticos de Kernel / BSOD",
    whatHappened:
      "O kernel do Windows interrompeu o sistema (Tela Azul) devido a falha grave em memória RAM, driver em modo kernel, disco do sistema ou instabilidade de hardware/CPU.",
    probableCauses: [
      "Módulo de memória RAM defeituoso ou overclock (XMP/DOCP/CPU) instável.",
      "Driver de rede, chipset, áudio ou anti-cheat com bug em nível de kernel.",
      "Setores defeituosos no SSD/HD do sistema (especialmente em KERNEL_DATA_INPAGE_ERROR).",
    ],
    solutions: [
      "Execute o Diagnóstico de Memória do Windows (mdsched.exe) e desative perfis XMP/overclock temporariamente.",
      "Execute chkdsk C: /f /r e sfc /scannow como Administrador para verificar disco e arquivos do Windows.",
      "Atualize a BIOS da placa-mãe e os drivers oficiais do chipset e armazenamento (NVMe/SATA).",
    ],
    commands: [
      { label: "Testar memória RAM", command: "mdsched.exe", requiresAdmin: true },
      { label: "Verificar disco C:", command: "chkdsk C: /f", requiresAdmin: true },
      { label: "Reparar sistema (SFC)", command: "sfc /scannow", requiresAdmin: true },
    ],
  },
  {
    id: "ERR_WIN_UPDATE_PERM",
    kind: "exception_code",
    codes: ["0x80070005", "80070005", "0x80070422", "0x800f081f", "ACCESS_DENIED"],
    category: "Windows Update & Permissões",
    severity: "medium",
    title: "Erro de Permissão ou Windows Update (0x80070005 / 0x80070422 / 0x800f081f)",
    whatHappened:
      "O Windows ou um instalador teve acesso negado a uma pasta/registro (0x80070005), encontrou o serviço de atualização desativado (0x80070422) ou não localizou arquivos de origem (0x800f081f).",
    probableCauses: [
      "Antivírus bloqueando gravação em pastas protegidas ou no registro.",
      "Serviço Windows Update (wuauserv) desativado.",
      "Cache do Windows Update ou imagem de componentes corrompida.",
    ],
    solutions: [
      "Execute o programa ou instalador clicando com o botão direito → Executar como administrador.",
      "Rode o comando DISM /Online /Cleanup-Image /RestoreHealth e sfc /scannow como Administrador.",
      "Em Serviços (services.msc), verifique se 'Windows Update' e 'Serviço de Transferência Inteligente em Segundo Plano (BITS)' estão em Manual/Automático.",
    ],
    commands: [
      {
        label: "Reparar componentes (DISM)",
        command: "DISM /Online /Cleanup-Image /RestoreHealth",
        requiresAdmin: true,
      },
      { label: "Abrir Serviços do Windows", command: "services.msc", requiresAdmin: false },
    ],
  },
];

export const FALLBACK_KB_ENTRIES: KnowledgeBaseEntry[] = [
  {
    id: "APP_1000",
    category: "Aplicativos",
    logName: "Application",
    sources: ["Application Error"],
    eventId: 1000,
    severity: "high",
    friendlyTitle: "Um programa fechou sozinho por falha interna (Crash)",
    whatHappened:
      "O aplicativo encontrou um erro grave de código ou tentou acessar uma área inválida da memória e foi encerrado imediatamente pelo Windows.",
    probableCauses: [
      "Bug no próprio programa ou plugin/extensão defeituosa.",
      "Arquivos do programa corrompidos.",
      "Conflito com drivers da placa de vídeo (muito comum em jogos e navegadores).",
      "Falta de bibliotecas do sistema (como Visual C++ Redistributable ou .NET).",
    ],
    solutions: [
      "Verifique o nome do 'Aplicativo com falha' e do 'Módulo com falha' nos detalhes do log.",
      "Atualize o programa para a versão mais recente ou reinstale-o.",
      "Se o módulo com falha mencionar arquivos da placa de vídeo (ex: nvlddmkm.dll, amdkmdag.sys), atualize o driver de vídeo.",
    ],
  },
  {
    id: "APP_1002",
    category: "Aplicativos",
    logName: "Application",
    sources: ["Application Hang"],
    eventId: 1002,
    severity: "medium",
    friendlyTitle: "Um programa congelou e parou de responder",
    whatHappened:
      "O aplicativo ficou preso aguardando uma resposta do processador, do disco ou da rede e parou de atualizar sua janela na tela.",
    probableCauses: [
      "Gargalo momentâneo de 100% de uso de Disco (HD/SSD) ou CPU.",
      "O programa tentou abrir um arquivo muito pesado ou acessar uma pasta na rede que caiu.",
      "Falta de memória RAM disponível no momento.",
    ],
    solutions: [
      "Verifique na linha do tempo do app se houve pico de Disco ou RAM segundos antes deste horário.",
      "Evite abrir múltiplas tarefas pesadas simultaneamente enquanto o disco estiver ocupado.",
      "Se ocorrer sempre no mesmo programa, limpe o cache dele ou verifique se há atualizações.",
    ],
  },
  {
    id: "SYS_41",
    category: "Sistema e Energia",
    logName: "System",
    sources: ["Microsoft-Windows-Kernel-Power"],
    eventId: 41,
    severity: "critical",
    friendlyTitle: "O computador desligou ou reiniciou de forma inesperada",
    whatHappened:
      "O Windows perdeu energia ou travou completamente (tela azul/congelamento total) sem passar pelo processo normal de desligamento.",
    probableCauses: [
      "Queda de energia ou cabo da fonte com mau contato.",
      "Você segurou o botão Power para forçar o desligamento após o PC congelar.",
      "Superaquecimento crítico do processador (desligamento de proteção).",
      "Fonte de alimentação (PSU) defeituosa ou instabilidade de overclock/RAM.",
    ],
    solutions: [
      "Monitore as temperaturas da CPU e GPU sob carga.",
      "Verifique se há logs de 'BugCheck' (Tela Azul) segundos antes deste evento.",
      "Desative perfis de overclock (XMP/DOCP) temporariamente para testar a estabilidade.",
      "Verifique os cabos de força e a saúde da fonte de alimentação.",
    ],
  },
  {
    id: "DISK_129",
    category: "Disco (HD / SSD)",
    logName: "System",
    sources: ["storahci", "nvme", "iaStorA", "iaStorAC"],
    eventId: 129,
    severity: "critical",
    friendlyTitle: "O HD ou SSD travou e precisou ser reiniciado (Pico de 100% de Disco)",
    whatHappened:
      "O controlador do Windows enviou um comando para o disco, mas ele demorou tanto para responder que o sistema precisou resetar a comunicação.",
    probableCauses: [
      "SSD ou HD chegando ao fim da vida útil ou superaquecendo.",
      "Cabo SATA frouxo, dobrado ou defeituoso (em PCs de mesa).",
      "Modo de economia de energia PCIe/SATA desligando o disco agressivamente.",
    ],
    solutions: [
      "Verifique a saúde do disco usando ferramentas S.M.A.R.T. (como CrystalDiskInfo).",
      "Em desktops, reconecte ou troque o cabo SATA e mude a porta na placa-mãe.",
      "Nas Opções de Energia do Windows, desative o 'Gerenciamento de Energia do Estado da Conexão PCI Express'.",
    ],
  },
  {
    id: "GPU_4101",
    category: "Placa de Vídeo (GPU)",
    logName: "System",
    sources: ["Display"],
    eventId: 4101,
    severity: "high",
    friendlyTitle: "O driver de vídeo parou de responder e se recuperou (TDR)",
    whatHappened:
      "A placa de vídeo travou por mais de 2 segundos (tela piscou em preto) e o Windows reiniciou o driver para evitar uma tela azul.",
    probableCauses: [
      "Driver da placa de vídeo corrompido ou desatualizado.",
      "Superaquecimento ou overclock instável na placa de vídeo.",
      "Jogo ou programa gráfico exigindo mais VRAM do que a placa possui.",
    ],
    solutions: [
      "Use o utilitário DDU (Display Driver Uninstaller) em Modo de Segurança para remover o driver atual e instale uma versão limpa.",
      "Monitore a temperatura da placa de vídeo durante jogos ou renderizações.",
      "Reduza as configurações gráficas de texturas para aliviar o uso de VRAM.",
    ],
  },
];

function inferCommandsForKbEntry(entry: KnowledgeBaseEntry): FixCommand[] {
  const cmds: FixCommand[] = [];
  const joined = entry.solutions.join(" ");
  if (joined.includes("sfc /scannow")) {
    cmds.push({
      label: "Verificar arquivos do Windows",
      command: "sfc /scannow",
      requiresAdmin: true,
    });
  }
  if (joined.includes("chkdsk C: /f")) {
    cmds.push({
      label: "Verificar sistema de arquivos NTFS",
      command: "chkdsk C: /f",
      requiresAdmin: true,
    });
  } else if (joined.includes("chkdsk")) {
    cmds.push({
      label: "Verificar setores do disco",
      command: "chkdsk /f /r",
      requiresAdmin: true,
    });
  }
  if (joined.includes("ipconfig /flushdns")) {
    cmds.push({
      label: "Limpar cache DNS",
      command: "ipconfig /flushdns",
      requiresAdmin: false,
    });
  }
  if (entry.eventId === 1000) {
    cmds.push({
      label: "Reparar arquivos do sistema (SFC)",
      command: "sfc /scannow",
      requiresAdmin: true,
    });
  }
  return cmds;
}

export function buildUnifiedFixCatalog(
  kbEntries: KnowledgeBaseEntry[],
): FixGuideEntry[] {
  const sourceEntries = kbEntries.length > 0 ? kbEntries : FALLBACK_KB_ENTRIES;
  const fromKb: FixGuideEntry[] = sourceEntries.map((entry) => ({
    id: entry.id,
    kind: "windows_event",
    codes: [`Event ID ${entry.eventId}`, ...entry.sources],
    category: entry.category,
    severity: entry.severity,
    title: entry.friendlyTitle,
    whatHappened: entry.whatHappened,
    probableCauses: entry.probableCauses,
    solutions: entry.solutions,
    commands: inferCommandsForKbEntry(entry),
  }));

  return [...fromKb, ...EXTRA_FIX_GUIDES];
}

function foldPt(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

function dedupeStrings(items: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of items) {
    const key = foldPt(item).trim();
    if (!seen.has(key)) {
      seen.add(key);
      out.push(item);
    }
  }
  return out;
}

function dedupeCommands(items: FixCommand[]): FixCommand[] {
  const seen = new Set<string>();
  const out: FixCommand[] = [];
  for (const item of items) {
    if (!seen.has(item.command)) {
      seen.add(item.command);
      out.push(item);
    }
  }
  return out;
}

function friendlyAppLabel(appName: string): string {
  const lower = appName.toLowerCase();
  if (lower === "mspaint.exe") return "Paint (mspaint.exe)";
  if (lower === "explorer.exe") return "Explorador de Arquivos (explorer.exe)";
  if (lower === "chrome.exe") return "Google Chrome (chrome.exe)";
  if (lower === "msedge.exe") return "Microsoft Edge (msedge.exe)";
  if (lower === "photos.exe") return "Fotos do Windows (Photos.exe)";
  if (lower === "snippingtool.exe") return "Ferramenta de Captura (SnippingTool.exe)";
  return appName;
}

export function analyzeErrorInput(
  rawInput: string,
  catalog: FixGuideEntry[],
): AnalyzedErrorDiagnosis | null {
  const text = rawInput.trim();
  if (!text) return null;

  const appMatch = text.match(/\b([a-z0-9._-]+\.exe)\b/i);
  const moduleMatch = text.match(/\b([a-z0-9._-]+\.(?:dll|sys))\b/i);
  const hexCodeMatch = text.match(/\b(?:0x)?([c8][0-9a-f]{7})\b/i);
  const werMatch = text.match(
    /\b(MoBEX|APPCRASH|BEX64|BEX|AppHangB1|MoAppHang|VIDEO_TDR_FAILURE|MEMORY_MANAGEMENT|IRQL_NOT_LESS_OR_EQUAL|PAGE_FAULT_IN_NONPAGED_AREA|CRITICAL_PROCESS_DIED|WHEA_UNCORRECTABLE_ERROR|KERNEL_DATA_INPAGE_ERROR)\b/i,
  );
  const eventIdMatch =
    text.match(/<EventID[^>]*>\s*(\d+)\s*<\/EventID>/i) ??
    text.match(/\b(?:event\s*id|id)\s*[:=#]?\s*(\d{1,5})\b/i) ??
    (/^\d{1,5}$/.test(text) ? [text, text] : null);

  const detectedApp = appMatch?.[1] ?? null;
  const detectedModule = moduleMatch?.[1] ?? null;
  const detectedCode = hexCodeMatch?.[1]
    ? hexCodeMatch[1].toLowerCase()
    : werMatch?.[1] ?? null;
  const detectedEventId = eventIdMatch?.[1] ? Number(eventIdMatch[1]) : null;
  const isStoreApp =
    /WindowsApps|Microsoft\.Paint|Microsoft\.Windows|MoBEX|praid:/i.test(text);

  const foldedInput = foldPt(text);
  const matchedGuides: FixGuideEntry[] = [];

  for (const guide of catalog) {
    const codeMatched = guide.codes.some((code) => {
      const clean = foldPt(code).replace(/^event id\s+/, "");
      if (/^\d+$/.test(clean)) {
        return detectedEventId !== null && String(detectedEventId) === clean;
      }
      return clean.length >= 3 && foldedInput.includes(clean);
    });
    if (codeMatched) {
      matchedGuides.push(guide);
    }
  }

  // If still no direct code match, search title/category/whatHappened for plain text queries
  if (matchedGuides.length === 0) {
    const tokens = foldedInput.split(/\s+/).filter((t) => t.length >= 3);
    if (tokens.length > 0) {
      for (const guide of catalog) {
        const hay = foldPt(
          `${guide.title} ${guide.category} ${guide.whatHappened} ${guide.codes.join(" ")}`,
        );
        if (tokens.every((t) => hay.includes(t))) {
          matchedGuides.push(guide);
        }
      }
    }
  }

  if (
    matchedGuides.length === 0 &&
    !detectedApp &&
    !detectedModule &&
    !detectedCode &&
    detectedEventId === null
  ) {
    return null;
  }

  const appDisplay = detectedApp ? friendlyAppLabel(detectedApp) : null;
  const headlineParts = [
    detectedApp,
    detectedModule,
    detectedCode,
    detectedEventId !== null ? `Event ID ${detectedEventId}` : null,
  ].filter((p): p is string => Boolean(p));

  const headline =
    headlineParts.length > 0
      ? `Diagnóstico: ${headlineParts.join(" / ")}`
      : matchedGuides[0]?.title ?? "Diagnóstico do Erro";

  let whatHappened: string;
  if (appDisplay && detectedModule && detectedCode) {
    const codeLabel =
      werMatch?.[1] && hexCodeMatch?.[1]
        ? `${hexCodeMatch[1].toLowerCase()} / ${werMatch[1]}`
        : detectedCode;
    const modDesc =
      detectedModule.toLowerCase() === "ucrtbase.dll"
        ? "ucrtbase.dll (Universal C Runtime do Windows)"
        : detectedModule;
    whatHappened = `O aplicativo ${appDisplay} fechou por falha interna (${codeLabel}) dentro da biblioteca ${modDesc}.`;
  } else if (appDisplay && detectedModule) {
    whatHappened = `O aplicativo ${appDisplay} sofreu um encerramento inesperado dentro do módulo ${detectedModule}.`;
  } else if (matchedGuides[0]) {
    whatHappened = matchedGuides[0].whatHappened;
  } else {
    whatHappened = `Foi identificada uma falha técnica envolvendo ${headlineParts.join(", ")}.`;
  }

  const causes: string[] = [];
  const solutions: string[] = [];
  const commands: FixCommand[] = [];

  if (isStoreApp && appDisplay) {
    solutions.push(
      `Vá em Configurações → Aplicativos → Aplicativos instalados → ${appDisplay.replace(/\s*\([^)]+\)/, "")} → Opções avançadas → clique em Reparar (ou Redefinir se o erro continuar).`,
    );
  }

  for (const guide of matchedGuides) {
    causes.push(...guide.probableCauses);
    solutions.push(...guide.solutions);
    commands.push(...guide.commands);
  }

  if (solutions.length === 0) {
    solutions.push(
      "Atualize ou reinstale o programa afetado para a versão mais recente.",
      "Execute sfc /scannow no Terminal como Administrador para verificar arquivos corrompidos do Windows.",
    );
    commands.push({
      label: "Verificar arquivos do Windows (SFC)",
      command: "sfc /scannow",
      requiresAdmin: true,
    });
  }

  return {
    headline,
    detectedApp,
    detectedModule,
    detectedCode,
    detectedEventId,
    isStoreApp,
    whatHappened,
    probableCauses: dedupeStrings(causes).slice(0, 6),
    solutions: dedupeStrings(solutions).slice(0, 6),
    commands: dedupeCommands(commands).slice(0, 4),
    matchedGuides,
  };
}
