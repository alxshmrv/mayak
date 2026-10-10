import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { detectLanguage, resolveLanguage } from "./i18n";
import { createMockReport, createMockSnapshot, mockHistory, mockScanPhases } from "./mock";
import type {
  AppSettings,
  AppSnapshot,
  HistoryEntry,
  PermissionStatus,
  ScanMode,
  ScanReport,
  TrustState,
} from "./types";

const isTauri =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

type LocalListener = (payload: unknown) => void;
const localListeners = new Map<string, Set<LocalListener>>();

const localEmit = (event: string, payload: unknown) => {
  localListeners.get(event)?.forEach((listener) => listener(payload));
};

let previewSnapshot: AppSnapshot | undefined;

function preview(): AppSnapshot {
  previewSnapshot ??= createMockSnapshot(detectLanguage());
  return previewSnapshot;
}

export async function getAppSnapshot(): Promise<AppSnapshot> {
  return isTauri
    ? invoke<AppSnapshot>("get_app_snapshot")
    : { ...structuredClone(preview()), systemLanguage: detectLanguage() };
}

export async function runScan(mode: ScanMode): Promise<ScanReport> {
  if (isTauri) {
    return invoke<ScanReport>("run_scan", { mode });
  }
  const snapshot = preview();
  const language = resolveLanguage(snapshot.settings.language, detectLanguage());
  const phases = mockScanPhases(language);
  for (const phase of phases) {
    localEmit("scan-progress", phase);
    await new Promise((resolve) => window.setTimeout(resolve, 280));
  }
  const report = {
    ...createMockReport(language),
    id: crypto.randomUUID(),
    mode,
    completedAt: new Date().toISOString(),
  };
  previewSnapshot = { ...snapshot, network: report.network, latestReport: report };
  localEmit("scan-complete", report);
  return report;
}

export async function getHistory(limit = 50): Promise<HistoryEntry[]> {
  return isTauri
    ? invoke<HistoryEntry[]>("get_history", { limit })
    : structuredClone(mockHistory.slice(0, limit));
}

export async function saveSettings(
  settings: AppSettings,
): Promise<AppSettings> {
  if (isTauri) {
    return invoke<AppSettings>("save_settings", { settings });
  }
  preview().settings = structuredClone(settings);
  return structuredClone(settings);
}

export async function setDeviceTrust(
  networkId: string,
  identityKey: string,
  trustState: TrustState,
): Promise<void> {
  if (isTauri) {
    await invoke("set_device_trust", { networkId, identityKey, trustState });
    return;
  }
  const device = preview().latestReport?.devices.find(
    (item) => item.identityKey === identityKey,
  );
  if (device) device.trustState = trustState;
}

export async function requestLocationPermission(): Promise<PermissionStatus> {
  if (isTauri) {
    return invoke<PermissionStatus>("request_location_permission");
  }
  preview().permissions.location = "allowed";
  return structuredClone(preview().permissions);
}

export async function requestNotificationPermission(): Promise<boolean> {
  return isTauri
    ? invoke<boolean>("request_notification_permission")
    : true;
}

export async function openPrivacySettings(
  section: "location" | "localNetwork",
): Promise<void> {
  if (isTauri) {
    await invoke("open_privacy_settings", { section });
  }
}

export async function listenAppEvent<T>(
  event: string,
  handler: (payload: T) => void,
): Promise<UnlistenFn> {
  if (isTauri) {
    return listen<T>(event, ({ payload }) => handler(payload));
  }
  const listener: LocalListener = (payload) => handler(payload as T);
  const listeners = localListeners.get(event) ?? new Set<LocalListener>();
  listeners.add(listener);
  localListeners.set(event, listeners);
  return () => listeners.delete(listener);
}
