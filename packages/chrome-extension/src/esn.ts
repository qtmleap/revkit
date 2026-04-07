// ── ESN (Equipment Serial Number) 分類・追跡 ──

import { captured } from "./state";

// Android: NFANDROID1-PRV-P-L3-...  / NFANDROID1-PXA-P-L3-...
// Chrome:  NFCDCH-MC-...
const ANDROID_PRV_RE = /^NFANDROID\d+-PRV-/i;
const ANDROID_PXA_RE = /^NFANDROID\d+-PXA-/i;
const CHROME_ESN_RE = /^NFCDCH?[-_]/i;
const GENERIC_NF_RE = /^NF[A-Z0-9]+-/i;

type EsnKind = "prv" | "pxa" | "chrome";

function classifyEsn(value: string): EsnKind | null {
  if (ANDROID_PRV_RE.test(value)) return "prv";
  if (ANDROID_PXA_RE.test(value)) return "pxa";
  if (CHROME_ESN_RE.test(value)) return "chrome";
  if (GENERIC_NF_RE.test(value)) return "chrome";
  return null;
}

let _onEsnUpdate: (() => void) | null = null;

export function setEsnUpdateCallback(cb: () => void): void {
  _onEsnUpdate = cb;
}

function notifyUpdate(): void {
  _onEsnUpdate?.();
}

export function maybeUpdateEsn(value: string): void {
  if (!value) return;
  const kind = classifyEsn(value);
  if (!kind) return;
  const now = new Date().toISOString();

  if (kind === "prv" && captured.esn.prv !== value) {
    captured.esn.prv = value;
    captured.esn.capturedAt = now;
    console.log(`[ESN-Capture] PRV: ${value}`);
    notifyUpdate();
  } else if (kind === "pxa" && captured.esn.pxa !== value) {
    captured.esn.pxa = value;
    captured.esn.capturedAt = now;
    console.log(`[ESN-Capture] PXA: ${value}`);
    notifyUpdate();
  } else if (kind === "chrome") {
    if (!captured.esn.prv || captured.esn.prv !== value) {
      const changed = captured.esn.prv !== value;
      captured.esn.prv = value;
      if (changed) {
        captured.esn.capturedAt = now;
        console.log(`[ESN-Capture] ESN: ${value}`);
        notifyUpdate();
      }
    }
  }
}

export function maybeUpdateEsnFromHeader(value: string): void {
  if (!value) return;
  const kind = classifyEsn(value);
  if (!kind) return;
  const now = new Date().toISOString();

  if ((kind === "chrome" || kind === "pxa") && captured.esn.pxa !== value) {
    captured.esn.pxa = value;
    captured.esn.capturedAt = now;
    console.log(`[ESN-Capture] ESN (header): ${value}`);
    notifyUpdate();
  } else if (kind === "prv" && captured.esn.prv !== value) {
    captured.esn.prv = value;
    captured.esn.capturedAt = now;
    notifyUpdate();
  }
}
