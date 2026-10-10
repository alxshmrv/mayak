import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import {
  check,
  type DownloadEvent,
  type Update,
} from "@tauri-apps/plugin-updater";
import packageInfo from "../package.json";

export interface AvailableAppUpdate {
  currentVersion: string;
  version: string;
  date?: string;
  notes?: string;
}

export interface UpdateDownloadProgress {
  downloadedBytes: number;
  totalBytes?: number;
  phase: "downloading" | "installing";
}

const isTauri =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

let pendingUpdate: Update | undefined;

export async function getInstalledVersion(): Promise<string> {
  return isTauri ? getVersion() : packageInfo.version;
}

export async function checkForAppUpdate(): Promise<AvailableAppUpdate | null> {
  if (!isTauri) return null;

  if (pendingUpdate) {
    const previousUpdate = pendingUpdate;
    pendingUpdate = undefined;
    try {
      await previousUpdate.close();
    } catch (cause) {
      console.warn("Unable to close the previous updater resource", cause);
    }
  }

  const update = await check({ timeout: 15_000 });
  if (!update) return null;

  pendingUpdate = update;
  return {
    currentVersion: update.currentVersion,
    version: update.version,
    date: update.date,
    notes: update.body,
  };
}

export async function installPendingUpdate(
  onProgress: (progress: UpdateDownloadProgress) => void,
): Promise<void> {
  if (!pendingUpdate) {
    throw new Error("The update is no longer available. Check for updates again.");
  }

  let downloadedBytes = 0;
  let totalBytes: number | undefined;

  await pendingUpdate.downloadAndInstall((event: DownloadEvent) => {
    if (event.event === "Started") {
      totalBytes = event.data.contentLength;
      onProgress({ downloadedBytes, totalBytes, phase: "downloading" });
      return;
    }
    if (event.event === "Progress") {
      downloadedBytes += event.data.chunkLength;
      onProgress({ downloadedBytes, totalBytes, phase: "downloading" });
      return;
    }
    onProgress({ downloadedBytes, totalBytes, phase: "installing" });
  });

  await relaunch();
}
