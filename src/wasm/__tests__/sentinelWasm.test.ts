/// <reference types="bun" />
import { beforeAll, describe, expect, it } from "bun:test";
import pkg from "../../../package.json";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { TimelineItem } from "../../types/sentinel";
import {
  createIncidentSearchEngine,
  downsampleSeriesIndices,
  downsampleSeriesXY,
  filterIncidentsStateless,
  getWasmVersion,
  initSentinelWasm,
} from "../sentinelWasm";

beforeAll(async () => {
  const wasmPath = resolve(import.meta.dir, "../pkg/sentinel_wasm_bg.wasm");
  const bytes = readFileSync(wasmPath);
  await initSentinelWasm(bytes);
});

function makeEventItem(
  uid: string,
  timestampMs: number,
  overrides: Partial<TimelineItem> = {},
): TimelineItem {
  return {
    uid,
    itemType: "event",
    sourceId: 1,
    timestampUtc: new Date(timestampMs).toISOString(),
    timestampMs,
    category: "Aplicativos",
    severity: "medium",
    title: "Um programa congelou e parou de responder",
    summary: "Aplicativo travou aguardando disco ou memória",
    eventId: 1002,
    providerName: "Application Hang",
    violatedMetric: null,
    peakValue: null,
    hasCorrelation: false,
    diagnosticNote: null,
    ...overrides,
  };
}

function makeSnapshotItem(
  uid: string,
  timestampMs: number,
  overrides: Partial<TimelineItem> = {},
): TimelineItem {
  return {
    uid,
    itemType: "snapshot",
    sourceId: 10,
    timestampUtc: new Date(timestampMs).toISOString(),
    timestampMs,
    category: "Memória RAM",
    severity: "high",
    title: "Pico de Memória RAM (94.2%) por 5s",
    summary: "Principal ofensor: chrome.exe",
    eventId: null,
    providerName: "chrome.exe",
    violatedMetric: "ram",
    peakValue: 94.2,
    hasCorrelation: false,
    diagnosticNote: null,
    ...overrides,
  };
}

describe("sentinel-wasm", () => {
  it("exposes crate version", () => {
    expect(getWasmVersion()).toBe(pkg.version);
  });

  it("downsamples 10,000 points with LTTB while preserving sharp spike", () => {
    const n = 10_000;
    const xs = new Float64Array(n);
    const ys = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      xs[i] = i * 1000;
      ys[i] = 20;
    }
    ys[4321] = 99.5;

    const indices = downsampleSeriesIndices(xs, ys, 60);
    expect(indices.length).toBe(60);
    expect(indices[0]).toBe(0);
    expect(indices[59]).toBe(n - 1);
    expect(Array.from(indices)).toContain(4321);

    const xy = downsampleSeriesXY(xs, ys, 60);
    expect(xy.length).toBe(120);
    expect(Array.from(xy)).toContain(99.5);
  });

  it("searches 2,000+ incidents with Portuguese diacritic folding, facets, upsert, and offline correlation", () => {
    const engine = createIncidentSearchEngine();
    try {
      const items: TimelineItem[] = [];
      for (let i = 0; i < 2000; i++) {
        items.push(
          makeEventItem(`ev-bulk-${i}`, 1_000_000 + i * 100, {
            title: `Evento rotineiro ${i}`,
            summary: "Registro comum",
            eventId: 1000,
          }),
        );
      }

      items.push(
        makeSnapshotItem("snap-ram-1", 2_000_000),
        makeEventItem("ev-hang-1", 2_003_000, {
          title: "Travamento crítico sem memória RAM",
          category: "Memória RAM",
          severity: "critical",
          hasCorrelation: true,
        }),
      );

      expect(engine.load(items)).toBe(2002);
      expect(engine.size()).toBe(2002);

      // Diacritic-insensitive search
      const memUids = engine.searchUids({
        query: "memoria",
        categories: [],
        severities: [],
        itemTypes: [],
        onlyCorrelated: false,
      });
      expect(memUids).toContain("ev-hang-1");
      expect(memUids).toContain("snap-ram-1");

      // Filtered search
      const critUids = engine.searchUids({
        query: "",
        categories: ["Memória RAM"],
        severities: ["critical"],
        itemTypes: ["event"],
        onlyCorrelated: true,
      });
      expect(critUids).toEqual(["ev-hang-1"]);

      // Live upsert
      const newSize = engine.upsert(
        makeEventItem("ev-disk-1", 2_004_000, {
          category: "Disco (HD / SSD)",
          severity: "high",
          title: "Latência de disco severa",
          eventId: 129,
        }),
      );
      expect(newSize).toBe(2003);

      // Facets serialized as plain JS object
      const facets = engine.facetCounts();
      expect(facets.total).toBe(2003);
      expect(facets.bySeverity.critical).toBe(1);
      expect(facets.byCategory["Disco (HD / SSD)"]).toBe(1);

      // Offline correlation [T - 15s, T + 5s]
      const matches = engine.correlateOffline(15_000, 5_000);
      const matchHang = matches.find((m) => m.eventUid === "ev-hang-1");
      expect(matchHang).toBeDefined();
      expect(matchHang?.snapshotUid).toBe("snap-ram-1");
      expect(matchHang?.deltaMs).toBe(3000);
      expect(matchHang?.diagnosticNote).toContain("chrome.exe");

      // Stateless filter sanity check
      const stateless = filterIncidentsStateless(items.slice(-2), {
        query: "chrome",
        categories: [],
        severities: [],
        itemTypes: [],
        onlyCorrelated: false,
      });
      expect(stateless).toEqual(["snap-ram-1"]);
    } finally {
      engine.dispose();
    }
  });
});
