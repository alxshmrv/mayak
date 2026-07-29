import assert from "node:assert/strict";
import test from "node:test";
import { validateUpdaterManifest } from "./validate-updater-manifest.mjs";

const targets = [
  "darwin-aarch64",
  "darwin-aarch64-app",
  "windows-x86_64",
  "windows-x86_64-nsis",
  "windows-x86_64-msi",
];

function manifest() {
  return {
    version: "0.3.0",
    pub_date: "2026-07-29T17:00:00.000Z",
    platforms: Object.fromEntries(targets.map((target, index) => [
      target,
      {
        signature: "s".repeat(80),
        url: `https://api.github.com/repos/alxshmrv/mayak/releases/assets/${index + 1}`,
      },
    ])),
  };
}

test("accepts a complete signed macOS and Windows manifest", () => {
  assert.doesNotThrow(() => validateUpdaterManifest(manifest(), "0.3.0"));
});

test("rejects a missing installer-specific target", () => {
  const value = manifest();
  delete value.platforms["windows-x86_64-nsis"];
  assert.throws(
    () => validateUpdaterManifest(value, "0.3.0"),
    /missing windows-x86_64-nsis/,
  );
});

test("rejects update artifacts outside the project repository", () => {
  const value = manifest();
  value.platforms["darwin-aarch64"].url =
    "https://github.com/another/project/releases/download/v1/app.tar.gz";
  assert.throws(
    () => validateUpdaterManifest(value, "0.3.0"),
    /outside alxshmrv\/mayak/,
  );
});
