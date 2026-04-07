// ── Netflix プロファイル定義 ──

export interface ProfileInfo {
  type: "video" | "audio" | "other";
  cat: string;
  label: string;
}

export const ALL_PROFILES: Record<string, ProfileInfo> = {
  // Video - AV1
  "av1-main-L20-dash-cbcs-prk":          { type: "video", cat: "AV1",      label: "AV1 L2.0 SD" },
  "av1-main-L21-dash-cbcs-prk":          { type: "video", cat: "AV1",      label: "AV1 L2.1 SD" },
  "av1-main-L30-dash-cbcs-prk":          { type: "video", cat: "AV1",      label: "AV1 L3.0 SD" },
  "av1-main-L31-dash-cbcs-prk":          { type: "video", cat: "AV1",      label: "AV1 L3.1 720p" },
  "av1-main-L40-dash-cbcs-prk":          { type: "video", cat: "AV1",      label: "AV1 L4.0 1080p" },
  "av1-main-L41-dash-cbcs-prk":          { type: "video", cat: "AV1",      label: "AV1 L4.1 4K" },
  "av1-main-L50-dash-cbcs-prk":          { type: "video", cat: "AV1",      label: "AV1 L5.0 4K+" },
  "av1-main-L30-dash-cbcs-live":         { type: "video", cat: "AV1",      label: "AV1 L3.0 Live" },
  "av1-main-L31-dash-cbcs-live":         { type: "video", cat: "AV1",      label: "AV1 L3.1 Live" },
  "av1-main-L40-dash-cbcs-live":         { type: "video", cat: "AV1",      label: "AV1 L4.0 Live" },
  "av1-main-L41-dash-cbcs-live":         { type: "video", cat: "AV1",      label: "AV1 L4.1 Live" },
  // Video - HEVC
  "hevc-main10-L30-dash-cenc-prk":       { type: "video", cat: "HEVC",     label: "HEVC Main10 L3.0 SD" },
  "hevc-main10-L31-dash-cenc-prk":       { type: "video", cat: "HEVC",     label: "HEVC Main10 L3.1 720p" },
  "hevc-main10-L40-dash-cenc-prk":       { type: "video", cat: "HEVC",     label: "HEVC Main10 L4.0 1080p" },
  "hevc-main10-L41-dash-cenc-prk":       { type: "video", cat: "HEVC",     label: "HEVC Main10 L4.1 4K" },
  "hevc-main10-L50-dash-cenc-prk":       { type: "video", cat: "HEVC",     label: "HEVC Main10 L5.0 4K+" },
  "hevc-main10-L30-dash-cenc-prk-do":    { type: "video", cat: "HEVC",     label: "HEVC Main10 L3.0 DL" },
  // Video - HEVC HDR10
  "hevc-hdr-main10-L30-dash-cenc-prk":  { type: "video", cat: "HEVC HDR", label: "HEVC HDR10 L3.0 SD" },
  "hevc-hdr-main10-L31-dash-cenc-prk":  { type: "video", cat: "HEVC HDR", label: "HEVC HDR10 L3.1 720p" },
  "hevc-hdr-main10-L40-dash-cenc-prk":  { type: "video", cat: "HEVC HDR", label: "HEVC HDR10 L4.0 1080p" },
  "hevc-hdr-main10-L41-dash-cenc-prk":  { type: "video", cat: "HEVC HDR", label: "HEVC HDR10 L4.1 4K" },
  "hevc-hdr-main10-L30-dash-cenc-prk-do": { type: "video", cat: "HEVC HDR", label: "HEVC HDR10 L3.0 DL" },
  "hevc-hdr-main10-L30-dash-cenc-live": { type: "video", cat: "HEVC HDR", label: "HEVC HDR10 L3.0 Live" },
  // Video - VP9
  "vp9-profile0-L21-dash-cenc":         { type: "video", cat: "VP9",      label: "VP9 L2.1 SD" },
  "vp9-profile0-L30-dash-cenc":         { type: "video", cat: "VP9",      label: "VP9 L3.0 SD" },
  "vp9-profile0-L31-dash-cenc":         { type: "video", cat: "VP9",      label: "VP9 L3.1 720p" },
  "vp9-profile0-L40-dash-cenc":         { type: "video", cat: "VP9",      label: "VP9 L4.0 1080p" },
  "vp9-profile2-L30-dash-cenc-prk":     { type: "video", cat: "VP9",      label: "VP9 P2 L3.0 HDR" },
  "vp9-profile2-L31-dash-cenc-prk":     { type: "video", cat: "VP9",      label: "VP9 P2 L3.1 HDR" },
  "vp9-profile2-L40-dash-cenc-prk":     { type: "video", cat: "VP9",      label: "VP9 P2 L4.0 HDR" },
  // Video - H.264
  "playready-h264mpl30-dash":           { type: "video", cat: "H.264",    label: "H.264 MP L3.0 SD" },
  "playready-h264mpl31-dash":           { type: "video", cat: "H.264",    label: "H.264 MP L3.1 720p" },
  "playready-h264mpl40-dash":           { type: "video", cat: "H.264",    label: "H.264 MP L4.0 1080p" },
  "playready-h264hpl22-dash":           { type: "video", cat: "H.264",    label: "H.264 HP L2.2" },
  "playready-h264hpl30-dash":           { type: "video", cat: "H.264",    label: "H.264 HP L3.0 SD" },
  "playready-h264hpl31-dash":           { type: "video", cat: "H.264",    label: "H.264 HP L3.1 720p" },
  "playready-h264hpl40-dash":           { type: "video", cat: "H.264",    label: "H.264 HP L4.0 1080p" },
  "none-h264mpl30-dash":                { type: "video", cat: "H.264",    label: "H.264 MP L3.0 (no DRM)" },
  "h264hpl22-dash-playready-live":      { type: "video", cat: "H.264",    label: "H.264 HP L2.2 Live" },
  "h264hpl30-dash-playready-live":      { type: "video", cat: "H.264",    label: "H.264 HP L3.0 Live" },
  "h264hpl31-dash-playready-live":      { type: "video", cat: "H.264",    label: "H.264 HP L3.1 Live" },
  "h264hpl40-dash-playready-live":      { type: "video", cat: "H.264",    label: "H.264 HP L4.0 Live" },
  // Audio
  "heaac-2-dash":                       { type: "audio", cat: "AAC",      label: "HE-AAC 2ch" },
  "heaac-2hq-dash":                     { type: "audio", cat: "AAC",      label: "HE-AAC 2ch HQ" },
  "xheaac-dash":                        { type: "audio", cat: "AAC",      label: "xHE-AAC" },
  "dd-5.1-dash":                        { type: "audio", cat: "Dolby",    label: "Dolby Digital 5.1" },
  "ddplus-5.1-dash":                    { type: "audio", cat: "Dolby",    label: "DD+ 5.1" },
  "ddplus-5.1hq-dash":                  { type: "audio", cat: "Dolby",    label: "DD+ 5.1 HQ" },
  "ddplus-atmos-dash":                  { type: "audio", cat: "Dolby",    label: "Dolby Atmos" },
  // Subtitle / Other
  "imsc1.1":                            { type: "other", cat: "Subtitle",  label: "IMSC 1.1" },
  "dfxp-ls-sdh":                        { type: "other", cat: "Subtitle",  label: "DFXP SDH" },
  "simplesdh":                          { type: "other", cat: "Subtitle",  label: "Simple SDH" },
  "nflx-cmisc":                         { type: "other", cat: "Subtitle",  label: "Netflix CMISC" },
  "webvtt-lssdh-ios13":                 { type: "other", cat: "Subtitle",  label: "WebVTT iOS13" },
  "iso_23001_18-dash-live":             { type: "other", cat: "Other",     label: "CMAF Live" },
  "BIF240":                             { type: "other", cat: "Other",     label: "Thumbnails 240" },
  "BIF320":                             { type: "other", cat: "Other",     label: "Thumbnails 320" },
};

/** H.264 のみのプリセット */
export const H264_ONLY_PROFILES = [
  "playready-h264hpl30-dash",
  "playready-h264hpl31-dash",
  "playready-h264hpl40-dash",
  "playready-h264mpl30-dash",
  "playready-h264mpl31-dash",
  "playready-h264mpl40-dash",
  "none-h264mpl30-dash",
];

/** VP9 + H.264 プリセット */
export const VP9_H264_PROFILES = [
  "vp9-profile0-L21-dash-cenc",
  "vp9-profile0-L30-dash-cenc",
  "vp9-profile0-L31-dash-cenc",
  "vp9-profile0-L40-dash-cenc",
  "playready-h264hpl30-dash",
  "playready-h264hpl31-dash",
  "playready-h264hpl40-dash",
];

/** HDCP engaged (4K 想定) プリセット */
export const HDR_4K_PROFILES = [
  "hevc-hdr-main10-L40-dash-cenc-prk",
  "hevc-hdr-main10-L41-dash-cenc-prk",
  "hevc-main10-L40-dash-cenc-prk",
  "hevc-main10-L41-dash-cenc-prk",
  "av1-main-L40-dash-cbcs-prk",
  "av1-main-L41-dash-cbcs-prk",
];
