// ── KID テーブル構築 ──

import type { KIDTableRow } from "./types";
import { manifestData } from "./state";

export function buildKIDTableRows(): KIDTableRow[] {
  const rows: KIDTableRow[] = [];
  for (const vt of manifestData.videoTracks) {
    for (const s of vt.streams) {
      rows.push({
        res_w: s.res_w,
        res_h: s.res_h,
        bitrate: s.bitrate,
        kid: s.kid ?? null,
        kid_short: s.kid ? s.kid.slice(9, 18) : "?",
        content_profile: s.content_profile,
        boundary: false,
      });
    }
  }
  rows.sort((a, b) =>
    a.res_w !== b.res_w
      ? a.res_w - b.res_w
      : a.res_h !== b.res_h
        ? a.res_h - b.res_h
        : a.bitrate - b.bitrate,
  );
  let prevKid: string | null = null;
  for (const r of rows) {
    r.boundary = prevKid !== null && r.kid !== prevKid;
    prevKid = r.kid;
  }
  return rows;
}

export function buildKIDTableMarkdown(): string {
  const rows = buildKIDTableRows();
  if (!rows.length) return "*(no manifest data)*";
  const lines = [
    `## KID / Resolution Map — movieId: ${manifestData.movieId ?? "unknown"}`,
    "",
    "| # | Resolution | KID (9-18) | Content Profile |",
    "|---|-----------|------------|-----------------|",
  ];
  rows.forEach((r, i) => {
    const b = r.boundary ? " ← KID BOUNDARY" : "";
    lines.push(`| ${i + 1} | ${r.res_w}x${r.res_h} | \`${r.kid_short}\` | ${r.content_profile}${b} |`);
  });
  return lines.join("\n");
}
