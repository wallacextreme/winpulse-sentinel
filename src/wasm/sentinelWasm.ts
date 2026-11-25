import type {
  ClientCorrelationMatch,
  IncidentFacetCounts,
  IncidentFilterQuery,
  TimelineItem,
} from "../types/sentinel";
import init, {
  IncidentIndex,
  filter_incidents_stateless,
  lttb_downsample_indices,
  lttb_downsample_xy,
  wasm_version,
} from "./pkg/sentinel_wasm";

let initPromise: Promise<void> | null = null;
let initialized = false;

export async function initSentinelWasm(wasmBytes?: BufferSource): Promise<void> {
  if (initialized) {
    return;
  }
  if (!initPromise) {
    initPromise = (async () => {
      if (wasmBytes) {
        await init({ module_or_path: wasmBytes });
      } else {
        await init();
      }
      initialized = true;
    })().catch((err) => {
      initPromise = null;
      throw err;
    });
  }
  await initPromise;
}

export function getWasmVersion(): string {
  return wasm_version();
}

export function downsampleSeriesIndices(
  xs: Float64Array,
  ys: Float64Array,
  threshold: number,
): Uint32Array {
  return lttb_downsample_indices(xs, ys, threshold);
}

export function downsampleSeriesXY(
  xs: Float64Array,
  ys: Float64Array,
  threshold: number,
): Float64Array {
  return lttb_downsample_xy(xs, ys, threshold);
}

export function filterIncidentsStateless(
  incidents: TimelineItem[],
  filter: IncidentFilterQuery,
): string[] {
  return filter_incidents_stateless(incidents, filter) as string[];
}

export class IncidentSearchEngine {
  private readonly inner: IncidentIndex;

  constructor() {
    this.inner = new IncidentIndex();
  }

  load(incidents: TimelineItem[]): number {
    return this.inner.load_incidents(incidents);
  }

  upsert(incident: TimelineItem): number {
    return this.inner.upsert_incident(incident);
  }

  size(): number {
    return this.inner.len();
  }

  clear(): void {
    this.inner.clear();
  }

  searchUids(filter: IncidentFilterQuery): string[] {
    return this.inner.search_uids(filter) as string[];
  }

  facetCounts(): IncidentFacetCounts {
    return this.inner.facet_counts() as IncidentFacetCounts;
  }

  correlateOffline(
    lookbackMs = 15_000,
    lookaheadMs = 5_000,
  ): ClientCorrelationMatch[] {
    return this.inner.correlate_offline(
      lookbackMs,
      lookaheadMs,
    ) as ClientCorrelationMatch[];
  }

  dispose(): void {
    this.inner.free();
  }
}

export function createIncidentSearchEngine(): IncidentSearchEngine {
  return new IncidentSearchEngine();
}
