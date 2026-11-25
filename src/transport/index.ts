import { DemoTransport } from "./demoTransport";
import { PwaWebSocketTransport } from "./pwaTransport";
import { TauriTransport } from "./tauriTransport";
import { isTauriRuntime, type SentinelTransport } from "./types";

export * from "./types";
export { DemoTransport, PwaWebSocketTransport, TauriTransport };

export function isDemoRuntime(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  const params = new URLSearchParams(window.location.search);
  const demoParam = params.get("demo");
  if (demoParam === "1" || demoParam === "true") {
    return true;
  }
  return window.location.hostname.endsWith("github.io");
}

export function createTransport(): SentinelTransport {
  if (isTauriRuntime()) {
    return new TauriTransport();
  }
  if (isDemoRuntime()) {
    return new DemoTransport();
  }
  return new PwaWebSocketTransport();
}
