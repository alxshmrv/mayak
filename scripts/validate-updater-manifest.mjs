import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const requiredTargets = [
  "darwin-aarch64",
  "darwin-aarch64-app",
  "windows-x86_64",
  "windows-x86_64-nsis",
  "windows-x86_64-msi",
];
const allowedHosts = new Set(["api.github.com", "github.com"]);

export function validateUpdaterManifest(manifest, expectedVersion) {
  if (manifest.version !== expectedVersion) {
    throw new Error(
      `Updater version mismatch: expected ${expectedVersion}, got ${manifest.version}`,
    );
  }

  if (!Number.isFinite(Date.parse(manifest.pub_date))) {
    throw new Error("Updater manifest has an invalid pub_date");
  }

  for (const target of requiredTargets) {
    const entry = manifest.platforms?.[target];
    if (!entry) {
      throw new Error(`Updater manifest is missing ${target}`);
    }
    if (typeof entry.signature !== "string" || entry.signature.length < 64) {
      throw new Error(`Updater signature is invalid for ${target}`);
    }
    const url = new URL(entry.url);
    if (url.protocol !== "https:" || !allowedHosts.has(url.hostname)) {
      throw new Error(`Updater URL is not an allowed HTTPS GitHub URL for ${target}`);
    }
    if (!url.pathname.includes("/alxshmrv/mayak/")) {
      throw new Error(`Updater URL points outside alxshmrv/mayak for ${target}`);
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [, , manifestPath, expectedVersion] = process.argv;
  if (!manifestPath || !expectedVersion) {
    throw new Error(
      "Usage: node scripts/validate-updater-manifest.mjs <latest.json> <version>",
    );
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  validateUpdaterManifest(manifest, expectedVersion);
  console.log(
    `Updater manifest ${expectedVersion} contains all signed macOS and Windows targets.`,
  );
}
