// ── 共有ミュータブルステート ──
// inject.ts の各モジュールから参照される共有状態

import type { CapturedData, ManifestData, ProfileOverrides } from "./types";

export const captured: CapturedData = {
  generateKey: [],
  importKey: [],
  deriveKey: [],
  sign: [],
  encrypt: [],
  decrypt: [],
  mslMessages: [],
  httpCaptures: [],
  aleKeys: [],
  esn: { prv: null, pxa: null, capturedAt: "" },
  eme: {
    sessions: [],
    licenseRequests: [],
    licenseResponses: [],
    keyStatuses: [],
  },
};

export const manifestData: ManifestData = {
  movieId: null,
  duration: null,
  videoTracks: [],
  audioTracks: [],
  textTracks: [],
  servers: [],
  raw: null,
};

export const profileOverrides: ProfileOverrides = {
  enabled: false,
  addProfiles: [],
  replaceProfiles: null,
};

// パネル状態
export let panelElement: HTMLElement | null = null;
export let panelMinimized = false;

export function setPanelElement(el: HTMLElement | null): void {
  panelElement = el;
}

export function setPanelMinimized(val: boolean): void {
  panelMinimized = val;
}
