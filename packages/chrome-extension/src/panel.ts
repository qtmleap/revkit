// ── フローティングパネル UI ──

import type { ManifestData, CapturedData, ProfileOverrides, KIDTableRow, StreamInfo, PanelCallbacks } from "./types";
import { formatSize, safeStringify } from "./utils";
import { ALL_PROFILES, H264_ONLY_PROFILES, VP9_H264_PROFILES, HDR_4K_PROFILES } from "./profiles";
import { SettingsSchema, zodParse } from "./schemas";

const PANEL_CSS = `
#__msl-capture-panel__{position:fixed;top:60px;right:16px;z-index:2147483647;width:380px;max-height:85vh;background:#1a1a2e;color:#e0e0e0;border:1px solid #444;border-radius:8px;font:12px/1.4 "SF Mono",Menlo,Consolas,monospace;box-shadow:0 4px 24px rgba(0,0,0,.6);overflow:hidden;user-select:none}
#__msl-capture-panel__ *{box-sizing:border-box}
#__msl-capture-panel__ .msl-header{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:#16213e;cursor:move;border-bottom:1px solid #333}
#__msl-capture-panel__ .msl-header-title{font-weight:bold;font-size:11px;color:#e94560}
#__msl-capture-panel__ .msl-header-btns{display:flex;gap:4px}
#__msl-capture-panel__ .msl-header-btns button{background:none;border:none;color:#888;cursor:pointer;font-size:14px;padding:0 4px;line-height:1}
#__msl-capture-panel__ .msl-header-btns button:hover{color:#fff}
#__msl-capture-panel__ .msl-body{padding:8px 10px;overflow-y:auto;max-height:calc(85vh - 32px)}
#__msl-capture-panel__ .msl-body.hidden{display:none}
#__msl-capture-panel__ .msl-section{margin-bottom:10px}
#__msl-capture-panel__ .msl-section-title{font-size:10px;text-transform:uppercase;color:#888;margin-bottom:4px;letter-spacing:.5px}
#__msl-capture-panel__ .msl-stat{display:flex;justify-content:space-between;padding:1px 0;font-size:11px}
#__msl-capture-panel__ .msl-stat-val{color:#4fc3f7}
#__msl-capture-panel__ .msl-btn{display:block;width:100%;padding:6px 0;margin:3px 0;background:#0f3460;color:#e0e0e0;border:1px solid #333;border-radius:4px;cursor:pointer;font:11px/1.3 inherit;text-align:center}
#__msl-capture-panel__ .msl-btn:hover{background:#1a4b8c}
#__msl-capture-panel__ .msl-btn.accent{background:#e94560;border-color:#e94560;color:#fff}
#__msl-capture-panel__ .msl-btn.accent:hover{background:#c73e55}
#__msl-capture-panel__ .msl-btn.green{background:#1b8a4e;border-color:#1b8a4e;color:#fff}
#__msl-capture-panel__ .msl-btn.green:hover{background:#22a85e}
#__msl-capture-panel__ .msl-btn.orange{background:#b35a00;border-color:#b35a00;color:#fff}
#__msl-capture-panel__ .msl-btn.orange:hover{background:#d06800}
#__msl-capture-panel__ .msl-btn:disabled{opacity:.4;cursor:not-allowed}
#__msl-capture-panel__ select.msl-select{width:100%;padding:4px 6px;margin:3px 0;background:#0d1b2a;color:#e0e0e0;border:1px solid #333;border-radius:4px;font:11px/1.3 inherit}
#__msl-capture-panel__ select.msl-select[multiple]{height:auto;min-height:60px}
#__msl-capture-panel__ select.msl-select option:checked{background:#1a4b8c;color:#fff}
#__msl-capture-panel__ .msl-toggle{display:flex;align-items:center;gap:6px;font-size:11px;margin:4px 0}
#__msl-capture-panel__ .msl-toggle input[type=checkbox]{accent-color:#e94560}
#__msl-capture-panel__ .msl-divider{border-top:1px solid #333;margin:8px 0}
#__msl-capture-panel__ .msl-badge{display:inline-block;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:bold;margin-left:4px}
#__msl-capture-panel__ .msl-badge.clear{background:#1b8a4e;color:#fff}
#__msl-capture-panel__ .msl-badge.drm{background:#e94560;color:#fff}
#__msl-capture-panel__ .msl-tabs{display:flex;margin-bottom:4px;border-bottom:1px solid #333}
#__msl-capture-panel__ .msl-tab{flex:1;padding:4px 6px;background:none;border:none;border-bottom:2px solid transparent;color:#888;cursor:pointer;font:11px/1.3 inherit;text-align:center}
#__msl-capture-panel__ .msl-tab:hover{color:#e0e0e0}
#__msl-capture-panel__ .msl-tab.active{color:#4fc3f7;border-bottom-color:#4fc3f7}
#__msl-capture-panel__ .msl-tab-panel{display:none}
#__msl-capture-panel__ .msl-tab-panel.active{display:block}
#__msl-capture-panel__ .msl-kid-table{width:100%;border-collapse:collapse;font-size:10px;margin-top:4px}
#__msl-capture-panel__ .msl-kid-table th{background:#0f3460;color:#aaa;text-align:left;padding:3px 4px;border-bottom:1px solid #444;font-weight:normal;white-space:nowrap}
#__msl-capture-panel__ .msl-kid-table td{padding:2px 4px;border-bottom:1px solid #222;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:0}
#__msl-capture-panel__ .msl-kid-table tr.kid-boundary td{border-top:2px solid #e94560}
#__msl-capture-panel__ .msl-kid-table .kid-a{color:#4fc3f7}
#__msl-capture-panel__ .msl-kid-table .kid-b{color:#aed581}
#__msl-capture-panel__ .msl-kid-table .kid-c{color:#ffb74d}
#__msl-capture-panel__ .msl-kid-table .kid-d{color:#f48fb1}
#__msl-capture-panel__ .msl-kid-table .col-res{width:70px}
#__msl-capture-panel__ .msl-kid-table .col-kid{width:90px;font-family:monospace}
#__msl-capture-panel__ .msl-kid-table .col-prof{max-width:120px;color:#888}
#__msl-capture-panel__ .msl-ale-box{background:#0a2540;border:1px solid #1a4b8c;border-radius:4px;padding:6px 8px;margin-top:4px;font-size:10px}
#__msl-capture-panel__ .msl-ale-row{display:flex;justify-content:space-between;padding:1px 0}
#__msl-capture-panel__ .msl-ale-label{color:#888}
#__msl-capture-panel__ .msl-ale-val{color:#aed581;font-family:monospace;font-size:9px;word-break:break-all}
#__msl-capture-panel__ .msl-esn-row{margin:2px 0}
#__msl-capture-panel__ .msl-esn-label{display:inline-block;width:28px;font-size:9px;font-weight:bold;color:#888;background:#0f3460;border-radius:2px;text-align:center;padding:0 2px;margin-right:4px}
#__msl-capture-panel__ .msl-esn-val{font-size:9px;font-family:monospace;color:#4fc3f7;word-break:break-all;cursor:pointer}
#__msl-capture-panel__ .msl-esn-val:hover{color:#fff}
`;

const PANEL_HTML = `
<style>${PANEL_CSS}</style>
<div class="msl-header">
  <span class="msl-header-title">MSL Capture v4</span>
  <div class="msl-header-btns">
    <button id="__msl-panel-min__">_</button>
    <button id="__msl-panel-close__">x</button>
  </div>
</div>
<div class="msl-body" id="__msl-panel-body__">
  <div class="msl-section">
    <div class="msl-section-title">Capture Status</div>
    <div class="msl-stat"><span>MSL messages</span><span class="msl-stat-val" id="__msl-s-msg__">0</span></div>
    <div class="msl-stat"><span>EME events</span><span class="msl-stat-val" id="__msl-s-eme__">0</span></div>
    <div class="msl-stat"><span>HTTP captures</span><span class="msl-stat-val" id="__msl-s-http__">0</span></div>
    <div class="msl-stat"><span>Crypto ops</span><span class="msl-stat-val" id="__msl-s-crypto__">0</span></div>
    <div class="msl-stat"><span>ALE key sets</span><span class="msl-stat-val" id="__msl-s-ale__">0</span></div>
  </div>
  <div class="msl-section" id="__msl-esn-section__">
    <div class="msl-section-title">ESN</div>
    <div class="msl-esn-row" id="__msl-esn-prv-row__" style="display:none">
      <span class="msl-esn-label">PRV</span>
      <span class="msl-esn-val" id="__msl-esn-prv__"></span>
    </div>
    <div class="msl-esn-row" id="__msl-esn-pxa-row__" style="display:none">
      <span class="msl-esn-label">PXA</span>
      <span class="msl-esn-val" id="__msl-esn-pxa__"></span>
    </div>
    <div id="__msl-esn-waiting__" style="color:#555;font-size:10px">-- waiting --</div>
  </div>
  <div class="msl-section">
    <button class="msl-btn accent" id="__msl-btn-save-log__">Save Capture Log</button>
    <button class="msl-btn green" id="__msl-btn-export-zip__">Export All (ZIP)</button>
  </div>
  <div class="msl-divider"></div>
  <div class="msl-section" id="__msl-ale-section__" style="display:none">
    <div class="msl-section-title">ALE Keys <span class="msl-badge clear">CLEAR</span></div>
    <div id="__msl-ale-list__"></div>
    <button class="msl-btn orange" id="__msl-btn-copy-ale__" style="margin-top:4px">Copy ALE Keys JSON</button>
  </div>
  <div class="msl-divider" id="__msl-ale-divider__" style="display:none"></div>
  <div class="msl-section" id="__msl-media-section__">
    <div class="msl-section-title">Media Streams</div>
    <div class="msl-stat"><span>Movie ID</span><span class="msl-stat-val" id="__msl-s-movie__">--</span></div>
    <div class="msl-stat"><span>Video streams</span><span class="msl-stat-val" id="__msl-s-vcount__">0</span></div>
    <div class="msl-stat"><span>Audio tracks</span><span class="msl-stat-val" id="__msl-s-acount__">0</span></div>
    <button class="msl-btn green" id="__msl-btn-dl-manifest__" disabled>Download Manifest JSON</button>
    <div class="msl-tabs" style="margin-top:8px">
      <button class="msl-tab active" data-media-tab="video">Video DL</button>
      <button class="msl-tab" data-media-tab="audio">Audio DL</button>
      <button class="msl-tab" data-media-tab="kidtable">KID Table</button>
    </div>
    <div class="msl-tab-panel active" id="__msl-media-tab-video__">
      <div class="msl-section-title">Video <span class="msl-badge drm">ENCRYPTED</span></div>
      <select class="msl-select" id="__msl-sel-video__"><option value="">-- waiting for manifest --</option></select>
      <button class="msl-btn" id="__msl-btn-dl-video__" disabled>Download Video (encrypted)</button>
    </div>
    <div class="msl-tab-panel" id="__msl-media-tab-audio__">
      <div class="msl-section-title">Audio <span class="msl-badge clear">CLEAR</span></div>
      <select class="msl-select" id="__msl-sel-audio__"><option value="">-- waiting for manifest --</option></select>
      <button class="msl-btn green" id="__msl-btn-dl-audio__" disabled>Download Audio</button>
    </div>
    <div class="msl-tab-panel" id="__msl-media-tab-kidtable__">
      <div class="msl-section-title">KID / Resolution Map <span id="__msl-kid-boundary-count__"></span></div>
      <div style="overflow-x:auto">
        <table class="msl-kid-table">
          <thead><tr><th class="col-res">Resolution</th><th class="col-kid">KID (9-18)</th><th class="col-prof">Profile</th></tr></thead>
          <tbody id="__msl-kid-table-body__"><tr><td colspan="3" style="color:#666;padding:8px 4px">-- waiting for manifest --</td></tr></tbody>
        </table>
      </div>
      <button class="msl-btn" id="__msl-btn-copy-kid-table__" style="margin-top:4px">Copy as Markdown</button>
    </div>
  </div>
  <div class="msl-divider"></div>
  <div class="msl-section">
    <div class="msl-section-title">Profile Override</div>
    <label class="msl-toggle"><input type="checkbox" id="__msl-chk-profile__"><span>Enable (次回再生開始時に反映)</span></label>
    <div style="display:flex;gap:3px;margin:4px 0;flex-wrap:wrap">
      <button class="msl-btn" id="__msl-preset-h264__" style="flex:1;min-width:60px;font-size:10px">H.264 only</button>
      <button class="msl-btn" id="__msl-preset-vp9__" style="flex:1;min-width:60px;font-size:10px">VP9+H264</button>
      <button class="msl-btn" id="__msl-preset-4k__" style="flex:1;min-width:60px;font-size:10px">HDR/4K</button>
      <button class="msl-btn" id="__msl-preset-clear__" style="flex:1;min-width:60px;font-size:10px;color:#888">Clear</button>
    </div>
    <div class="msl-tabs">
      <button class="msl-tab active" data-tab="video">Video</button>
      <button class="msl-tab" data-tab="audio">Audio</button>
      <button class="msl-tab" data-tab="other">Other</button>
    </div>
    <div class="msl-tab-panel active" id="__msl-tab-video__"><select class="msl-select" id="__msl-sel-profiles-video__" multiple size="7"></select></div>
    <div class="msl-tab-panel" id="__msl-tab-audio__"><select class="msl-select" id="__msl-sel-profiles-audio__" multiple size="7"></select></div>
    <div class="msl-tab-panel" id="__msl-tab-other__"><select class="msl-select" id="__msl-sel-profiles-other__" multiple size="7"></select></div>
    <div style="display:flex;gap:4px;margin-top:2px">
      <button class="msl-btn" id="__msl-btn-profile-all__" style="flex:1">All</button>
      <button class="msl-btn" id="__msl-btn-profile-none__" style="flex:1">None</button>
      <button class="msl-btn accent" id="__msl-btn-profile-apply__" style="flex:1.5">Apply &amp; Reload</button>
    </div>
    <div class="msl-stat" style="margin-top:4px"><span>Selected</span><span class="msl-stat-val" id="__msl-s-profiles__">0</span></div>
  </div>
</div>
`;

function q<T extends Element>(panel: HTMLElement, sel: string): T {
  return panel.querySelector<T>(sel)!;
}

export class CapturePanel {
  private el: HTMLElement | null = null;
  private minimized = false;
  private profileSelectors: Record<string, HTMLSelectElement> = {};

  constructor(
    private manifestData: ManifestData,
    private captured: CapturedData,
    private profileOverrides: ProfileOverrides,
    private callbacks: PanelCallbacks,
    private buildKIDRows: () => KIDTableRow[],
    private buildKIDMarkdown: () => string,
  ) {}

  create(): HTMLElement {
    if (this.el) return this.el;

    const panel = document.createElement("div");
    panel.id = "__msl-capture-panel__";
    panel.innerHTML = PANEL_HTML;
    document.documentElement.appendChild(panel);
    this.el = panel;

    this.bindEvents(panel);
    this.update();
    return panel;
  }

  private bindEvents(panel: HTMLElement): void {
    // ESN クリックコピー
    q(panel, "#__msl-esn-prv__").addEventListener("click", () => {
      if (this.captured.esn.prv) navigator.clipboard.writeText(this.captured.esn.prv).catch(() => { /* ignore */ });
    });
    q(panel, "#__msl-esn-pxa__").addEventListener("click", () => {
      if (this.captured.esn.pxa) navigator.clipboard.writeText(this.captured.esn.pxa).catch(() => { /* ignore */ });
    });

    // Drag
    const header = q(panel, ".msl-header");
    let dragging = false;
    let dx = 0;
    let dy = 0;
    header.addEventListener("mousedown", (e: Event) => {
      const me = e as MouseEvent;
      if ((me.target as Element).tagName === "BUTTON") return;
      dragging = true;
      dx = me.clientX - panel.offsetLeft;
      dy = me.clientY - panel.offsetTop;
      me.preventDefault();
    });
    document.addEventListener("mousemove", (e: Event) => {
      if (!dragging) return;
      const me = e as MouseEvent;
      panel.style.left = (me.clientX - dx) + "px";
      panel.style.right = "auto";
      panel.style.top = (me.clientY - dy) + "px";
    });
    document.addEventListener("mouseup", () => { dragging = false; });

    // Minimize / Close
    q(panel, "#__msl-panel-min__").addEventListener("click", () => {
      this.minimized = !this.minimized;
      q(panel, "#__msl-panel-body__").classList.toggle("hidden", this.minimized);
      q<HTMLButtonElement>(panel, "#__msl-panel-min__").textContent = this.minimized ? "+" : "_";
    });
    q(panel, "#__msl-panel-close__").addEventListener("click", () => { panel.style.display = "none"; });

    // Save Log
    q(panel, "#__msl-btn-save-log__").addEventListener("click", () => {
      this.callbacks.onSave();
      const btn = q<HTMLButtonElement>(panel, "#__msl-btn-save-log__");
      btn.textContent = "Saved!";
      setTimeout(() => { btn.textContent = "Save Capture Log"; }, 1500);
    });

    // Export All (ZIP)
    q(panel, "#__msl-btn-export-zip__").addEventListener("click", async () => {
      const btn = q<HTMLButtonElement>(panel, "#__msl-btn-export-zip__");
      btn.textContent = "Building ZIP…";
      btn.disabled = true;
      try {
        await this.callbacks.onExportZip();
        btn.textContent = "Exported!";
      } catch {
        btn.textContent = "Error!";
      }
      setTimeout(() => {
        btn.textContent = "Export All (ZIP)";
        btn.disabled = false;
      }, 1500);
    });

    // Download Manifest
    q(panel, "#__msl-btn-dl-manifest__").addEventListener("click", () => {
      this.callbacks.onDownloadManifest();
      const btn = q<HTMLButtonElement>(panel, "#__msl-btn-dl-manifest__");
      btn.textContent = "Saved!";
      setTimeout(() => { btn.textContent = "Download Manifest JSON"; }, 1500);
    });

    // Media Tabs
    panel.querySelectorAll("[data-media-tab]").forEach((tabBtn) => {
      tabBtn.addEventListener("click", () => {
        panel.querySelectorAll("[data-media-tab]").forEach((b) => b.classList.remove("active"));
        for (const t of ["video", "audio", "kidtable"]) {
          panel.querySelector(`#__msl-media-tab-${t}__`)?.classList.remove("active");
        }
        tabBtn.classList.add("active");
        const tabName = (tabBtn as HTMLElement).dataset.mediaTab;
        panel.querySelector(`#__msl-media-tab-${tabName}__`)?.classList.add("active");
      });
    });

    // Download Video
    q(panel, "#__msl-btn-dl-video__").addEventListener("click", () => {
      const sel = q<HTMLSelectElement>(panel, "#__msl-sel-video__");
      if (!sel.value) return;
      const [ti, si] = sel.value.split(",").map(Number);
      const stream = this.manifestData.videoTracks[ti].streams[si];
      this.callbacks.onDownloadStream(stream, "video");
    });

    // Download Audio
    q(panel, "#__msl-btn-dl-audio__").addEventListener("click", () => {
      const sel = q<HTMLSelectElement>(panel, "#__msl-sel-audio__");
      if (!sel.value) return;
      const [ti, si] = sel.value.split(",").map(Number);
      const track = this.manifestData.audioTracks[ti];
      const stream: StreamInfo = {
        ...track.streams[si],
        kid: null,
        res_w: 0,
        res_h: 0,
        vmaf: undefined,
      };
      this.callbacks.onDownloadStream(stream, "audio", track.language);
    });

    // Copy KID Table
    q(panel, "#__msl-btn-copy-kid-table__").addEventListener("click", () => {
      const md = this.buildKIDMarkdown();
      navigator.clipboard.writeText(md).then(() => {
        const btn = q<HTMLButtonElement>(panel, "#__msl-btn-copy-kid-table__");
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = "Copy as Markdown"; }, 1500);
      }).catch(() => console.log("[MSL-Capture] [KID Table]\n" + this.buildKIDMarkdown()));
    });

    // Copy ALE Keys
    q(panel, "#__msl-btn-copy-ale__").addEventListener("click", () => {
      const json = safeStringify(this.captured.aleKeys);
      navigator.clipboard.writeText(json).then(() => {
        const btn = q<HTMLButtonElement>(panel, "#__msl-btn-copy-ale__");
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = "Copy ALE Keys JSON"; }, 1500);
      }).catch(() => console.log("[MSL-Capture] ALE Keys:", json));
    });

    // Profile Override Toggle
    const chk = q<HTMLInputElement>(panel, "#__msl-chk-profile__");
    chk.checked = this.profileOverrides.enabled;
    chk.addEventListener("change", () => {
      this.profileOverrides.enabled = chk.checked;
      this.syncProfileSelection(panel);
      this.callbacks.onSaveSettings();
    });

    // Profile Presets
    const applyPreset = (profiles: string[]) => {
      this.profileOverrides.replaceProfiles = profiles;
      this.profileOverrides.addProfiles = profiles;
      this.applySelectedToUI(panel, new Set(profiles));
      this.syncProfileSelection(panel);
      this.callbacks.onSaveSettings();
    };
    q(panel, "#__msl-preset-h264__").addEventListener("click", () => applyPreset(H264_ONLY_PROFILES));
    q(panel, "#__msl-preset-vp9__").addEventListener("click", () => applyPreset(VP9_H264_PROFILES));
    q(panel, "#__msl-preset-4k__").addEventListener("click", () => applyPreset(HDR_4K_PROFILES));
    q(panel, "#__msl-preset-clear__").addEventListener("click", () => {
      this.profileOverrides.replaceProfiles = null;
      this.profileOverrides.addProfiles = [];
      this.applySelectedToUI(panel, new Set());
      this.syncProfileSelection(panel);
      this.callbacks.onSaveSettings();
    });

    // Populate profile selects
    this.profileSelectors = {
      video: q<HTMLSelectElement>(panel, "#__msl-sel-profiles-video__"),
      audio: q<HTMLSelectElement>(panel, "#__msl-sel-profiles-audio__"),
      other: q<HTMLSelectElement>(panel, "#__msl-sel-profiles-other__"),
    };
    const byTypeCat: Record<string, Record<string, Array<{ profile: string; label: string }>>> = {};
    for (const [prof, info] of Object.entries(ALL_PROFILES)) {
      if (!byTypeCat[info.type]) byTypeCat[info.type] = {};
      if (!byTypeCat[info.type][info.cat]) byTypeCat[info.type][info.cat] = [];
      byTypeCat[info.type][info.cat].push({ profile: prof, label: info.label });
    }
    for (const [type, cats] of Object.entries(byTypeCat)) {
      const sel = this.profileSelectors[type];
      if (!sel) continue;
      for (const [cat, items] of Object.entries(cats)) {
        const group = document.createElement("optgroup");
        group.label = cat;
        for (const item of items) {
          const opt = document.createElement("option");
          opt.value = item.profile;
          opt.textContent = item.label;
          group.appendChild(opt);
        }
        sel.appendChild(group);
      }
      sel.addEventListener("change", () => {
        this.syncProfileSelection(panel);
        this.callbacks.onSaveSettings();
      });
    }

    // Profile Override Tabs
    panel.querySelectorAll(".msl-tab[data-tab]").forEach((tabBtn) => {
      tabBtn.addEventListener("click", () => {
        panel.querySelectorAll(".msl-tab[data-tab]").forEach((b) => b.classList.remove("active"));
        panel.querySelectorAll(".msl-tab-panel[id^='__msl-tab-']").forEach((p) => p.classList.remove("active"));
        tabBtn.classList.add("active");
        const tabName = (tabBtn as HTMLElement).dataset.tab;
        panel.querySelector(`#__msl-tab-${tabName}__`)?.classList.add("active");
      });
    });

    // Profile All / None / Apply
    const getActiveTabSel = (): HTMLSelectElement => {
      const active = panel.querySelector(".msl-tab[data-tab].active") as HTMLElement | null;
      return this.profileSelectors[active?.dataset.tab ?? "video"];
    };
    q(panel, "#__msl-btn-profile-all__").addEventListener("click", () => {
      Array.from(getActiveTabSel().options).forEach((opt) => { opt.selected = true; });
      this.syncProfileSelection(panel);
      this.callbacks.onSaveSettings();
    });
    q(panel, "#__msl-btn-profile-none__").addEventListener("click", () => {
      Array.from(getActiveTabSel().options).forEach((opt) => { opt.selected = false; });
      this.syncProfileSelection(panel);
      this.callbacks.onSaveSettings();
    });
    q(panel, "#__msl-btn-profile-apply__").addEventListener("click", () => {
      this.syncProfileSelection(panel);
      this.callbacks.onSaveSettings();
      const btn = q<HTMLButtonElement>(panel, "#__msl-btn-profile-apply__");
      btn.textContent = "Saving…";
      btn.disabled = true;
      setTimeout(() => { location.reload(); }, 300);
    });

    // Download result listener
    window.addEventListener("message", (event: MessageEvent) => {
      if (event.source !== window) return;
      const data = event.data as Record<string, unknown> | null;
      if (!data || typeof data !== "object") return;
      if (data.type === "__MSL_CAPTURE_DOWNLOAD_RESULT__") {
        if (data.ok) console.log("[MSL-Capture] [Download] Started:", data.downloadId);
        else console.warn("[MSL-Capture] [Download] Failed:", data.error);
      }
    });
  }

  private syncProfileSelection(panel: HTMLElement): void {
    const selected: string[] = [];
    for (const type of ["video", "audio", "other"]) {
      const sel = this.profileSelectors[type];
      if (sel) {
        Array.from(sel.selectedOptions).forEach((opt) => selected.push(opt.value));
      }
    }
    this.profileOverrides.addProfiles = selected;
    q(panel, "#__msl-s-profiles__").textContent = String(selected.length);
  }

  private applySelectedToUI(panel: HTMLElement, selected: Set<string>): void {
    for (const type of ["video", "audio", "other"]) {
      const sel = this.profileSelectors[type];
      if (sel) {
        Array.from(sel.options).forEach((opt) => { opt.selected = selected.has(opt.value); });
      }
    }
    q(panel, "#__msl-s-profiles__").textContent = String(selected.size);
  }

  show(): void {
    if (this.el) {
      this.el.style.display = "";
      this.minimized = false;
      q(this.el, "#__msl-panel-body__").classList.remove("hidden");
      q<HTMLButtonElement>(this.el, "#__msl-panel-min__").textContent = "_";
    } else {
      this.create();
    }
  }

  applySettings(settings: unknown): void {
    const parsed = zodParse(SettingsSchema, settings);
    if (!parsed) return;
    this.profileOverrides.enabled = parsed.profileOverrideEnabled;
    this.profileOverrides.addProfiles = parsed.profileOverrideAddProfiles;
    this.profileOverrides.replaceProfiles = parsed.profileOverrideReplaceProfiles;

    if (this.el) {
      q<HTMLInputElement>(this.el, "#__msl-chk-profile__").checked = parsed.profileOverrideEnabled;
      this.applySelectedToUI(this.el, new Set(parsed.profileOverrideAddProfiles));
    }
  }

  update(): void {
    const panel = this.el;
    if (!panel) return;

    // Stats
    q(panel, "#__msl-s-msg__").textContent = String(this.captured.mslMessages.length);
    q(panel, "#__msl-s-eme__").textContent = String(
      this.captured.eme.sessions.length + this.captured.eme.licenseRequests.length + this.captured.eme.keyStatuses.length,
    );
    q(panel, "#__msl-s-http__").textContent = String(this.captured.httpCaptures.length);
    q(panel, "#__msl-s-crypto__").textContent = String(
      this.captured.generateKey.length + this.captured.importKey.length +
      this.captured.encrypt.length + this.captured.decrypt.length,
    );
    q(panel, "#__msl-s-ale__").textContent = String(this.captured.aleKeys.length);

    // ESN
    const hasEsn = this.captured.esn.prv || this.captured.esn.pxa;
    q<HTMLElement>(panel, "#__msl-esn-waiting__").style.display = hasEsn ? "none" : "";
    if (this.captured.esn.prv) {
      (q(panel, "#__msl-esn-prv-row__") as HTMLElement).style.display = "";
      q(panel, "#__msl-esn-prv__").textContent = this.captured.esn.prv;
    }
    if (this.captured.esn.pxa) {
      (q(panel, "#__msl-esn-pxa-row__") as HTMLElement).style.display = "";
      q(panel, "#__msl-esn-pxa__").textContent = this.captured.esn.pxa;
    }

    // Media info
    q(panel, "#__msl-s-movie__").textContent = this.manifestData.movieId ?? "--";
    const totalVideo = this.manifestData.videoTracks.reduce((n, t) => n + t.streams.length, 0);
    const totalAudio = this.manifestData.audioTracks.reduce((n, t) => n + t.streams.length, 0);
    q(panel, "#__msl-s-vcount__").textContent = String(totalVideo);
    q(panel, "#__msl-s-acount__").textContent = String(totalAudio);

    // Manifest download button
    q<HTMLButtonElement>(panel, "#__msl-btn-dl-manifest__").disabled = !this.manifestData.raw;

    // Video select
    const vSel = q<HTMLSelectElement>(panel, "#__msl-sel-video__");
    vSel.innerHTML = "";
    if (totalVideo === 0) {
      vSel.innerHTML = '<option value="">-- waiting for manifest --</option>';
      q<HTMLButtonElement>(panel, "#__msl-btn-dl-video__").disabled = true;
    } else {
      this.manifestData.videoTracks.forEach((vt, ti) => {
        vt.streams.forEach((s, si) => {
          const opt = document.createElement("option");
          opt.value = `${ti},${si}`;
          const km = s.kid ? s.kid.slice(9, 18) : "?";
          opt.textContent = `${s.res_w}x${s.res_h} | ${s.bitrate}kbps | VMAF ${s.vmaf ?? "?"} | KID:${km} | ${s.content_profile}`;
          opt.title = s.kid ? `KID: ${s.kid}\n${s.res_w}x${s.res_h} | ${formatSize(s.size)}\n${s.content_profile}` : "";
          vSel.appendChild(opt);
        });
      });
      vSel.selectedIndex = vSel.options.length - 1;
      q<HTMLButtonElement>(panel, "#__msl-btn-dl-video__").disabled = false;
    }

    // Audio select
    const aSel = q<HTMLSelectElement>(panel, "#__msl-sel-audio__");
    aSel.innerHTML = "";
    if (totalAudio === 0) {
      aSel.innerHTML = '<option value="">-- waiting for manifest --</option>';
      q<HTMLButtonElement>(panel, "#__msl-btn-dl-audio__").disabled = true;
    } else {
      this.manifestData.audioTracks.forEach((at, ti) => {
        at.streams.forEach((s, si) => {
          const opt = document.createElement("option");
          opt.value = `${ti},${si}`;
          opt.textContent = `${at.languageDescription ?? at.language} | ${at.channels ?? "?"} | ${s.bitrate}kbps | ${formatSize(s.size)} | ${s.content_profile}`;
          aSel.appendChild(opt);
        });
      });
      q<HTMLButtonElement>(panel, "#__msl-btn-dl-audio__").disabled = false;
    }

    // ALE Keys
    this.updateAleSection(panel);

    // KID Table
    this.updateKIDTable(panel);

    // Profile override sync
    q<HTMLInputElement>(panel, "#__msl-chk-profile__").checked = this.profileOverrides.enabled;
    q(panel, "#__msl-s-profiles__").textContent = String(this.profileOverrides.addProfiles.length);
  }

  private updateAleSection(panel: HTMLElement): void {
    const section = q<HTMLElement>(panel, "#__msl-ale-section__");
    const list = q(panel, "#__msl-ale-list__");
    if (this.captured.aleKeys.length === 0) {
      section.style.display = "none";
      return;
    }
    section.style.display = "";
    list.innerHTML = "";
    this.captured.aleKeys.forEach((ale, i) => {
      const box = document.createElement("div");
      box.className = "msl-ale-box";
      box.innerHTML = `
        <div class="msl-ale-row"><span class="msl-ale-label">#${i + 1} KID</span><span class="msl-ale-val">${ale.kid}</span></div>
        <div class="msl-ale-row"><span class="msl-ale-label">AES-CBC</span><span class="msl-ale-val">${ale.encryptionKey}</span></div>
        <div class="msl-ale-row"><span class="msl-ale-label">HMAC</span><span class="msl-ale-val">${ale.hmacKey}</span></div>
        <div class="msl-ale-row"><span class="msl-ale-label">Scheme</span><span class="msl-ale-val">${ale.scheme}</span></div>
        <div class="msl-ale-row"><span class="msl-ale-label">At</span><span class="msl-ale-val">${ale.capturedAt.slice(11, 19)}</span></div>
      `;
      list.appendChild(box);
    });
  }

  private updateKIDTable(panel: HTMLElement): void {
    const tbody = q(panel, "#__msl-kid-table-body__");
    const rows = this.buildKIDRows();
    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" style="color:#666;padding:8px 4px">-- waiting for manifest --</td></tr>';
      const bc = panel.querySelector("#__msl-kid-boundary-count__");
      if (bc) bc.textContent = "";
      return;
    }

    tbody.innerHTML = "";
    const kidColorMap = new Map<string, string>();
    const kidColors = ["kid-a", "kid-b", "kid-c", "kid-d"];
    let colorIdx = 0;
    for (const r of rows) {
      if (r.kid && !kidColorMap.has(r.kid)) {
        kidColorMap.set(r.kid, kidColors[colorIdx++ % kidColors.length]);
      }
    }

    let boundaries = 0;
    for (const r of rows) {
      const tr = document.createElement("tr");
      if (r.boundary) {
        tr.classList.add("kid-boundary");
        boundaries++;
      }
      const colorClass = kidColorMap.get(r.kid ?? "") ?? "kid-a";
      const is720 = r.res_w === 1280 && r.res_h === 720;
      const resStyle = is720 ? ' style="font-weight:bold;color:#fff"' : "";
      tr.innerHTML =
        `<td class="col-res"${resStyle}>${r.res_w}x${r.res_h}</td>` +
        `<td class="col-kid ${colorClass}">${r.kid_short}</td>` +
        `<td class="col-prof" title="${r.content_profile}">${r.content_profile}</td>`;
      tbody.appendChild(tr);
    }

    const bc = panel.querySelector("#__msl-kid-boundary-count__");
    if (bc) bc.textContent = boundaries > 0 ? `(${boundaries} boundary)` : "";
  }

  /** パネルが最小化されていなければ Stats のみ軽量更新 */
  updateStats(): void {
    const panel = this.el;
    if (!panel || this.minimized) return;
    q(panel, "#__msl-s-msg__").textContent = String(this.captured.mslMessages.length);
    q(panel, "#__msl-s-eme__").textContent = String(
      this.captured.eme.sessions.length + this.captured.eme.licenseRequests.length + this.captured.eme.keyStatuses.length,
    );
    q(panel, "#__msl-s-http__").textContent = String(this.captured.httpCaptures.length);
    q(panel, "#__msl-s-crypto__").textContent = String(
      this.captured.generateKey.length + this.captured.importKey.length +
      this.captured.encrypt.length + this.captured.decrypt.length,
    );
    q(panel, "#__msl-s-ale__").textContent = String(this.captured.aleKeys.length);
  }
}
