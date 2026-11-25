/// <reference types="bun" />
import { describe, expect, it } from "bun:test";
import {
  analyzeErrorInput,
  buildUnifiedFixCatalog,
  FALLBACK_KB_ENTRIES,
} from "../fixCatalog";

describe("fixCatalog and analyzeErrorInput", () => {
  const catalog = buildUnifiedFixCatalog(FALLBACK_KB_ENTRIES);

  it("diagnoses mspaint.exe / ucrtbase.dll / c0000409 / MoBEX signature accurately", () => {
    const pasted = `
      mspaint.exe
      Nome de Evento de Problema: MoBEX
      Nome Completo do Pacote: Microsoft.Paint_11.2609.401.0_x64__8wekyb3d8bbwe
      Nome do Módulo de Falhas: ucrtbase.dll
      Código de Exceção: c0000409
    `;
    const diag = analyzeErrorInput(pasted, catalog);
    expect(diag).not.toBeNull();
    expect(diag?.detectedApp).toBe("mspaint.exe");
    expect(diag?.detectedModule).toBe("ucrtbase.dll");
    expect(diag?.detectedCode).toBe("c0000409");
    expect(diag?.isStoreApp).toBe(true);
    expect(diag?.whatHappened).toContain("Paint (mspaint.exe)");
    expect(diag?.whatHappened).toContain("ucrtbase.dll");
    expect(diag?.solutions[0]).toContain("Opções avançadas");
    expect(diag?.commands.some((c) => c.command === "sfc /scannow")).toBe(true);
  });

  it("diagnoses NVIDIA GPU driver crash and Event ID 129 disk reset", () => {
    const gpu = analyzeErrorInput("nvlddmkm.sys VIDEO_TDR_FAILURE", catalog);
    expect(gpu).not.toBeNull();
    expect(gpu?.detectedModule).toBe("nvlddmkm.sys");
    expect(gpu?.solutions.some((s) => s.includes("DDU"))).toBe(true);

    const disk = analyzeErrorInput("129", catalog);
    expect(disk).not.toBeNull();
    expect(disk?.detectedEventId).toBe(129);
    expect(disk?.matchedGuides.some((g) => g.id === "DISK_129")).toBe(true);
  });
});
