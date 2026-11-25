import { expect, test } from "@playwright/test";

const SAMPLE_SNAPSHOT = {
  id: 501,
  timestampUtc: "2026-11-25T14:00:00.000Z",
  timestampMs: 1_795_615_200_000,
  violatedMetric: "ram",
  peakValue: 94.5,
  thresholdValue: 90.0,
  durationSecs: 5,
  cpuPercent: 34.2,
  ramPercent: 94.5,
  ramFreeGb: 0.88,
  diskActivePercent: 21.0,
  diskLatencyMs: 8.4,
  netRxKbps: 240.0,
  netTxKbps: 64.0,
  netLatencyMs: 14.0,
  netLossPercent: 0.0,
  topProcesses: [
    {
      pid: 4242,
      name: "chrome.exe",
      exePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      cpuPercent: 22.4,
      memoryMb: 6840.0,
      memoryPercent: 42.7,
      diskReadKbps: 120.0,
      diskWriteKbps: 45.0,
    },
    {
      pid: 8112,
      name: "Code.exe",
      exePath: "C:\\Users\\Usu\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
      cpuPercent: 7.5,
      memoryMb: 2150.0,
      memoryPercent: 13.4,
      diskReadKbps: 10.0,
      diskWriteKbps: 5.0,
    },
  ],
  severity: "high",
};

const SAMPLE_EVENT = {
  id: 77,
  recordId: 9012,
  channel: "Application",
  providerName: "Application Hang",
  eventId: 1002,
  level: 2,
  timestampUtc: "2026-11-25T14:00:03.000Z",
  timestampMs: 1_795_615_203_000,
  kbId: "APP_1002",
  category: "Aplicativos",
  severity: "critical",
  friendlyTitle: "Um programa congelou e parou de responder",
  whatHappened:
    "O aplicativo ficou preso aguardando uma resposta do processador, do disco ou da memória.",
  probableCauses: [
    "Falta de memória RAM disponível no momento.",
    "Gargalo momentâneo de 100% de uso de Disco.",
  ],
  solutions: [
    "Verifique na linha do tempo do app se houve pico de Disco ou RAM segundos antes deste horário.",
    "Feche abas ou aplicativos pesados em segundo plano.",
  ],
  rawXml:
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Application Hang"/><EventID>1002</EventID><EventRecordID>9012</EventRecordID></System></Event>',
  correlationSnapshotId: 501,
  diagnosticNote:
    "3 segundos antes deste evento (ID 1002), o processo `chrome.exe` registrou pico de 94% de Memória RAM.",
};

test.describe("WinPulse Sentinel PWA E2E", () => {
  test("serves valid manifest and registers active Service Worker", async ({
    page,
  }) => {
    await page.goto("/");

    const manifestResp = await page.request.get("/manifest.webmanifest");
    expect(manifestResp.status()).toBe(200);
    const manifest = await manifestResp.json();
    expect(manifest.name).toBe("WinPulse Sentinel");
    expect(manifest.display).toBe("standalone");
    expect(Array.isArray(manifest.icons)).toBe(true);
    expect(manifest.icons.length).toBeGreaterThanOrEqual(2);

    const swScope = await page.evaluate(async () => {
      if (!("serviceWorker" in navigator)) return null;
      const reg = await navigator.serviceWorker.ready;
      return reg.active?.scriptURL ?? null;
    });
    expect(swScope).toContain("sw.js");

    await expect(page.getByTestId("pin-overlay")).toBeVisible();
  });

  test("authenticates via PIN, receives mocked WebSocket spike, filters via Wasm, and opens Diagnostic Drawer", async ({
    page,
  }) => {
    let seenTicketUrl = "";

    await page.route("**/api/auth/login", async (route) => {
      const body = route.request().postDataJSON() as { pin?: string };
      if (body.pin === "123456") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ token: "e2e-session-token" }),
        });
      } else {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ error: "unauthorized" }),
        });
      }
    });

    await page.route("**/api/auth/ws-ticket", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ticket: "e2e-ticket-1" }),
      });
    });

    await page.route("**/api/status", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          paused: false,
          uptimeSecs: 120,
          ringBufferLen: 5,
          eventWatcherActive: true,
          isElevated: true,
          healthStatus: "critical",
        }),
      });
    });

    await page.route("**/api/telemetry/recent", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      });
    });

    await page.route("**/api/knowledge-base", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      });
    });

    await page.route("**/api/timeline*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          {
            uid: "event-999",
            itemType: "event",
            sourceId: 999,
            timestampUtc: "2026-11-25T13:50:00.000Z",
            timestampMs: 1_795_614_600_000,
            category: "Rede e Internet",
            severity: "medium",
            title: "Falha DNS temporária",
            summary: "Resolução DNS demorou para responder.",
            eventId: 1014,
            providerName: "Microsoft-Windows-DNS-Client",
            violatedMetric: null,
            peakValue: null,
            hasCorrelation: false,
            diagnosticNote: null,
          },
        ]),
      });
    });

    await page.route("**/api/incidents/event/77", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          itemType: "event",
          event: SAMPLE_EVENT,
          snapshot: SAMPLE_SNAPSHOT,
          correlatedSnapshots: [SAMPLE_SNAPSHOT],
          correlatedEvents: [],
          diagnosticNote: SAMPLE_EVENT.diagnosticNote,
        }),
      });
    });

    await page.routeWebSocket(/\/ws\?ticket=/, (ws) => {
      seenTicketUrl = ws.url();

      for (let i = 0; i < 5; i++) {
        ws.send(
          JSON.stringify({
            type: "telemetry",
            payload: {
              timestampUtc: `2026-11-25T14:00:0${i}.000Z`,
              timestampMs: 1_795_615_196_000 + i * 1000,
              cpuPercent: 31 + i,
              ramPercent: 90.5 + i,
              ramUsedGb: 15.1,
              ramFreeGb: 0.9,
              ramTotalGb: 16.0,
              diskActivePercent: 20,
              diskLatencyMs: 8,
              netRxKbps: 240,
              netTxKbps: 64,
              netLatencyMs: 14,
              netLossPercent: 0,
              healthStatus: "critical",
            },
          }),
        );
      }

      ws.send(JSON.stringify({ type: "snapshot", payload: SAMPLE_SNAPSHOT }));
      ws.send(JSON.stringify({ type: "windows_event", payload: SAMPLE_EVENT }));
    });

    await page.goto("/");

    // Wrong PIN stays on overlay and surfaces error
    await page.getByTestId("pin-input").fill("000000");
    await page.getByTestId("pin-submit").click();
    await expect(page.getByText(/PIN inválido/i)).toBeVisible();

    // Valid PIN authenticates and connects WebSocket using single-use ticket (no Bearer token in URL)
    await page.getByTestId("pin-input").fill("123456");
    await page.getByTestId("pin-submit").click();
    await expect(page.getByTestId("pin-overlay")).toBeHidden();
    expect(seenTicketUrl).toContain("ticket=e2e-ticket-1");
    expect(seenTicketUrl).not.toContain("e2e-session-token");

    // Live telemetry spike & health badge reflected
    await expect(page.getByTestId("metric-card-ram")).toContainText("94.5");
    await expect(page.getByTestId("health-indicator")).toContainText("Crítico");

    // Wasm instant search with Portuguese diacritic folding ("memoria" matches "memória")
    const searchInput = page.getByTestId("timeline-search");
    await searchInput.fill("memoria");
    const matchingItems = page.getByTestId("timeline-item");
    await expect(matchingItems.first()).toBeVisible();
    await expect(page.getByText("Falha DNS temporária")).toHaveCount(0);

    // Click correlated event (ID 1002) and verify Diagnostic Drawer + Checklist + Top 5 + Raw XML
    await page
      .getByTestId("timeline-item")
      .filter({ hasText: "ID 1002" })
      .first()
      .click();

    const drawer = page.getByTestId("diagnostic-drawer");
    await expect(drawer).toBeVisible();
    await expect(page.getByTestId("diagnostic-note")).toContainText("chrome.exe");
    await expect(drawer).toContainText("Top 5 Processos Ofensores");

    const firstCheckbox = drawer.locator('input[type="checkbox"]').first();
    await firstCheckbox.check();
    await expect(firstCheckbox).toBeChecked();

    await page.getByTestId("raw-xml-toggle").click();
    await expect(drawer).toContainText("<EventID>1002</EventID>");

    await page.getByTestId("drawer-close").click();
    await expect(drawer).toBeHidden();

    // Switch to "Como Corrigir" tab and verify analyzer diagnoses mspaint.exe / ucrtbase.dll / c0000409
    await page.getByTestId("tab-fix-guide").click();
    await expect(page.getByTestId("fix-guide-panel")).toBeVisible();
    await page
      .getByTestId("fix-analyzer-input")
      .fill("mspaint.exe MoBEX Microsoft.Paint_11.2609.401.0 ucrtbase.dll c0000409");
    const result = page.getByTestId("fix-analyzer-result");
    await expect(result).toBeVisible();
    await expect(result).toContainText("Paint (mspaint.exe)");
    await expect(result).toContainText("ucrtbase.dll");
    await expect(result).toContainText("sfc /scannow");

    // Responsive check: zero horizontal overflow on desktop and mobile viewports
    const overflow = await page.evaluate(
      () =>
        document.documentElement.scrollWidth > window.innerWidth + 1,
    );
    expect(overflow).toBe(false);
  });
});
