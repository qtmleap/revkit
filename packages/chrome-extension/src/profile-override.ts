// ── プロファイルオーバーライド ──

import { profileOverrides } from "./state";
import { ManifestRequestPayloadSchema, zodParse } from "./schemas";

const PREFIX = "[MSL-Capture]";

export function rewriteManifestProfiles(payloadJson: unknown): boolean {
  if (!profileOverrides.enabled) return false;

  const parsed = zodParse(ManifestRequestPayloadSchema, payloadJson);
  if (!parsed) return false;
  if (parsed.url !== "licensedManifest" && parsed.url !== "manifest") return false;

  const original = [...parsed.params.profiles];

  if (profileOverrides.replaceProfiles) {
    parsed.params.profiles = profileOverrides.replaceProfiles;
  } else {
    const existing = new Set(original);
    for (const p of profileOverrides.addProfiles) {
      if (!existing.has(p)) {
        parsed.params.profiles.push(p);
        existing.add(p);
      }
    }
  }

  // parsed は payloadJson の参照を持つので、元の params.profiles も更新される
  const target = payloadJson as Record<string, unknown>;
  const params = target.params as Record<string, unknown>;
  params.profiles = parsed.params.profiles;

  console.log(
    `${PREFIX} [Profile Override] ${original.length} → ${parsed.params.profiles.length} profiles`,
    "\n  Added:",
    parsed.params.profiles.filter((p) => !original.includes(p)),
  );
  return true;
}
