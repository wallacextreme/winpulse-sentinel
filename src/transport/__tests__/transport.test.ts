/// <reference types="bun" />
import { describe, expect, it } from "bun:test";
import type { BottleneckSnapshot, WindowsEventRecord } from "../../types/sentinel";
import {
  isWsEnvelope,
  timelineItemFromEvent,
  timelineItemFromSnapshot,
} from "../types";

describe("transport type guards and mappers", () => {
  it("validates well-formed WsEnvelope payloads and rejects invalid ones", () => {
    expect(
      isWsEnvelope({
        type: "telemetry",
        payload: {
          timestampMs: 1000,
          cpuPercent: 45,
          ramPercent: 60,
        },
      }),
    ).toBe(true);

    expect(
      isWsEnvelope({
        type: "windows_event",
        payload: {
          id: 7,
          timestampMs: 2000,
          eventId: 1002,
        },
      }),
    ).toBe(true);

    expect(isWsEnvelope(null)).toBe(false);
    expect(isWsEnvelope({ type: "unknown", payload: {} })).toBe(false);
    expect(isWsEnvelope({ type: "telemetry", payload: "bad" })).toBe(false);
  });

  it("maps WindowsEventRecord and BottleneckSnapshot to TimelineItem", () => {
    const ev: WindowsEventRecord = {
      id: 12,
      recordId: 400,
      channel: "Application",
      providerName: "Application Hang",
      eventId: 1002,
      level: 2,
      timestampUtc: "2026-11-25T13:00:03Z",
      timestampMs: 103_000,
      kbId: "APP_1002",
      category: "Aplicativos",
      severity: "medium",
      friendlyTitle: "Um programa congelou",
      whatHappened: "Ficou sem responder",
      probableCauses: ["Disco 100%"],
      solutions: ["Verificar linha do tempo"],
      rawXml: "<Event/>",
      correlationSnapshotId: 5,
      diagnosticNote: "3 segundos antes deste evento (ID 1002), chrome.exe consumiu 94%.",
    };

    const evItem = timelineItemFromEvent(ev);
    expect(evItem.uid).toBe("event-12");
    expect(evItem.hasCorrelation).toBe(true);
    expect(evItem.eventId).toBe(1002);

    const snap: BottleneckSnapshot = {
      id: 5,
      timestampUtc: "2026-11-25T13:00:00Z",
      timestampMs: 100_000,
      violatedMetric: "ram",
      peakValue: 94.2,
      thresholdValue: 90,
      durationSecs: 5,
      cpuPercent: 32,
      ramPercent: 94.2,
      ramFreeGb: 0.9,
      diskActivePercent: 18,
      diskLatencyMs: 9,
      netRxKbps: 120,
      netTxKbps: 30,
      netLatencyMs: 14,
      netLossPercent: 0,
      topProcesses: [
        {
          pid: 1024,
          name: "chrome.exe",
          exePath: null,
          cpuPercent: 18,
          memoryMb: 6200,
          memoryPercent: 45,
          diskReadKbps: 0,
          diskWriteKbps: 0,
        },
      ],
      severity: "high",
    };

    const snapItem = timelineItemFromSnapshot(snap);
    expect(snapItem.uid).toBe("snapshot-5");
    expect(snapItem.category).toBe("Memória RAM");
    expect(snapItem.providerName).toBe("chrome.exe");
    expect(snapItem.title).toContain("94.2%");
  });
});
