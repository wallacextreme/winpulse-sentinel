import { useState } from "react";
import { Cpu, HardDrive, MemoryStick, Network } from "lucide-react";
import { AlertToastStack } from "./components/AlertToastStack";
import { DiagnosticDrawer } from "./components/DiagnosticDrawer";
import { FixGuidePanel } from "./components/FixGuidePanel";
import { MetricCard } from "./components/MetricCard";
import { PinConnectOverlay } from "./components/PinConnectOverlay";
import { RemoteAccessModal } from "./components/RemoteAccessModal";
import { TimelinePanel } from "./components/TimelinePanel";
import { TopBar, type AppTab } from "./components/TopBar";
import { useSentinelStore } from "./hooks/useSentinelStore";

export default function App() {
  const store = useSentinelStore();
  const [activeTab, setActiveTab] = useState<AppTab>("monitoring");

  const timestamps = store.telemetryHistory.map((s) => s.timestampMs);
  const cpuValues = store.telemetryHistory.map((s) => s.cpuPercent);
  const ramValues = store.telemetryHistory.map((s) => s.ramPercent);
  const diskValues = store.telemetryHistory.map((s) => s.diskActivePercent);
  const netValues = store.telemetryHistory.map(
    (s) => s.netRxKbps + s.netTxKbps,
  );

  const latest = store.latestTelemetry;
  const maxCpu = cpuValues.length > 0 ? Math.max(...cpuValues) : 0;
  const maxRam = ramValues.length > 0 ? Math.max(...ramValues) : 0;
  const maxDiskLat =
    store.telemetryHistory.length > 0
      ? Math.max(...store.telemetryHistory.map((s) => s.diskLatencyMs))
      : 0;
  const maxNet = Math.max(
    netValues.length > 0 ? Math.max(...netValues) : 100,
    100,
  );

  const cpuAlert =
    (latest?.cpuPercent ?? 0) > 90
      ? "critical"
      : (latest?.cpuPercent ?? 0) > 75
        ? "warning"
        : "normal";

  const ramAlert =
    (latest?.ramPercent ?? 0) > 90
      ? "critical"
      : (latest?.ramPercent ?? 0) > 80
        ? "warning"
        : "normal";

  const diskAlert =
    (latest?.diskActivePercent ?? 0) > 90 || (latest?.diskLatencyMs ?? 0) > 100
      ? "critical"
      : (latest?.diskActivePercent ?? 0) > 75 ||
          (latest?.diskLatencyMs ?? 0) > 50
        ? "warning"
        : "normal";

  const netAlert =
    (latest?.netLossPercent ?? 0) > 5
      ? "critical"
      : (latest?.netLatencyMs ?? 0) > 120
        ? "warning"
        : "normal";

  return (
    <div className="min-h-screen bg-[#060911] text-slate-100">
      <TopBar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        mode={store.mode}
        wasmReady={store.wasmReady}
        connectionState={store.connectionState}
        collectorStatus={store.collectorStatus}
        remoteEnabled={store.remoteStatus?.enabled ?? false}
        onTogglePause={() => {
          void store.togglePause();
        }}
        onOpenRemoteModal={() => store.setRemoteModalOpen(true)}
        onRefresh={() => {
          void store.refresh();
        }}
      />

      <main className="mx-auto max-w-7xl space-y-5 px-4 py-5 sm:px-6">
        {activeTab === "fix-guide" ? (
          <FixGuidePanel knowledgeBase={store.knowledgeBase} />
        ) : (
          <>
            <section
              aria-label="Telemetria em Tempo Real"
              className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4"
            >
          <MetricCard
            testId="metric-card-cpu"
            label="Processador (CPU)"
            primaryValue={latest ? latest.cpuPercent.toFixed(1) : "--"}
            unit="%"
            secondaryDetail={
              store.collectorStatus?.paused
                ? "Coleta pausada"
                : "Amostragem 1000ms · Gatilho > 90% (5s)"
            }
            peakLabel={`Pico: ${maxCpu.toFixed(1)}%`}
            icon={<Cpu className="h-4 w-4" />}
            timestamps={timestamps}
            values={cpuValues}
            maxY={100}
            thresholdY={90}
            accentColor="#22d3ee"
            alertState={cpuAlert}
            wasmReady={store.wasmReady}
          />

          <MetricCard
            testId="metric-card-ram"
            label="Memória RAM"
            primaryValue={latest ? latest.ramPercent.toFixed(1) : "--"}
            unit="%"
            secondaryDetail={
              latest
                ? `${latest.ramFreeGb.toFixed(1)} GB livres de ${latest.ramTotalGb.toFixed(1)} GB`
                : "Aguardando telemetria..."
            }
            peakLabel={`Pico: ${maxRam.toFixed(1)}%`}
            icon={<MemoryStick className="h-4 w-4" />}
            timestamps={timestamps}
            values={ramValues}
            maxY={100}
            thresholdY={90}
            accentColor="#a78bfa"
            alertState={ramAlert}
            wasmReady={store.wasmReady}
          />

          <MetricCard
            testId="metric-card-disk"
            label="Disco (PDH)"
            primaryValue={latest ? latest.diskActivePercent.toFixed(1) : "--"}
            unit="%"
            secondaryDetail={
              latest
                ? `Latência: ${latest.diskLatencyMs.toFixed(1)} ms (limite 100 ms)`
                : "Aguardando contadores PDH..."
            }
            peakLabel={`Lat. máx: ${maxDiskLat.toFixed(0)} ms`}
            icon={<HardDrive className="h-4 w-4" />}
            timestamps={timestamps}
            values={diskValues}
            maxY={100}
            thresholdY={90}
            accentColor="#f59e0b"
            alertState={diskAlert}
            wasmReady={store.wasmReady}
          />

          <MetricCard
            testId="metric-card-network"
            label="Rede & Latência"
            primaryValue={
              latest ? (latest.netRxKbps + latest.netTxKbps).toFixed(0) : "--"
            }
            unit="kbps"
            secondaryDetail={
              latest
                ? `RX ${latest.netRxKbps.toFixed(0)} · TX ${latest.netTxKbps.toFixed(0)} kbps · ${
                    latest.netLatencyMs !== null
                      ? `${latest.netLatencyMs.toFixed(0)} ms`
                      : "ICMP n/d"
                  }`
                : "Aguardando interface..."
            }
            peakLabel={`Perda: ${(latest?.netLossPercent ?? 0).toFixed(0)}%`}
            icon={<Network className="h-4 w-4" />}
            timestamps={timestamps}
            values={netValues}
            maxY={maxNet}
            accentColor="#10b981"
            alertState={netAlert}
            wasmReady={store.wasmReady}
          />
        </section>

        <TimelinePanel
          mode={store.mode}
          items={store.filteredTimeline}
          totalUnfilteredCount={store.timeline.length}
          facetCounts={store.facetCounts}
          filter={store.filter}
          selectedUid={store.selectedItem?.uid ?? null}
          wasmReady={store.wasmReady}
          importingHistory={store.importingHistory}
          lastImportMessage={store.lastImportMessage}
          onImportHistory={(days) => {
            void store.importHistory(days);
          }}
          onFilterChange={store.setFilter}
          onSelectItem={(item) => {
            void store.openIncident(item);
          }}
        />
          </>
        )}
      </main>

      <DiagnosticDrawer
        item={store.selectedItem}
        detail={store.selectedDetail}
        knowledgeBase={store.knowledgeBase}
        loading={store.detailLoading}
        error={store.detailError}
        onClose={store.closeDrawer}
      />

      <RemoteAccessModal
        open={store.remoteModalOpen}
        status={store.remoteStatus}
        error={store.remoteActionError}
        onClose={() => store.setRemoteModalOpen(false)}
        onToggle={store.toggleRemoteServer}
        onRegeneratePin={store.regenerateRemotePin}
      />

      <PinConnectOverlay
        open={
          store.mode === "pwa" &&
          (store.connectionState === "auth_required" ||
            store.connectionState === "disconnected")
        }
        defaultServerUrl={store.defaultServerUrl}
        hasOfflineCache={store.hasOfflineCache}
        busy={store.authBusy}
        error={store.authError}
        onAuthenticate={store.authenticateWithPin}
        onContinueOffline={() => {
          store.continueOffline();
        }}
      />

      <AlertToastStack
        toasts={store.toasts}
        onDismiss={store.dismissToast}
        onInspect={(item) => {
          void store.openIncident(item);
        }}
      />
    </div>
  );
}
