import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { mockHistory, mockReport, mockSnapshot } from "./mock";
import type {
  AppSettings,
  AppSnapshot,
  HistoryEntry,
  PermissionStatus,
  ScanMode,
  ScanProgress,
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

let previewSnapshot = structuredClone(mockSnapshot);

export async function getAppSnapshot(): Promise<AppSnapshot> {
  return isTauri
    ? invoke<AppSnapshot>("get_app_snapshot")
    : structuredClone(previewSnapshot);
}

export async function runScan(mode: ScanMode): Promise<ScanReport> {
  if (isTauri) {
    return invoke<ScanReport>("run_scan", { mode });
  }
  const phases: ScanProgress[] = [
    {
      phase: "network",
      title: "Читаем параметры Wi-Fi",
      detail: "Системный Wi-Fi API, маршруты и DNS",
      completed: 0,
      total: 1,
    },
    {
      phase: "tcp",
      title: "Ищем отвечающие устройства",
      detail: "Проверено 128 из 253 адресов",
      completed: 128,
      total: 253,
    },
    {
      phase: "neighbors",
      title: "Сверяем соседей",
      detail: "ARP, Bonjour, SSDP и ONVIF",
      completed: 253,
      total: 253,
    },
  ];
  for (const phase of phases) {
    localEmit("scan-progress", phase);
    await new Promise((resolve) => window.setTimeout(resolve, 280));
  }
  const report = {
    ...structuredClone(mockReport),
    id: crypto.randomUUID(),
    mode,
    completedAt: new Date().toISOString(),
  };
  previewSnapshot = { ...previewSnapshot, network: report.network, latestReport: report };
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
  previewSnapshot.settings = structuredClone(settings);
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
  const device = previewSnapshot.latestReport?.devices.find(
    (item) => item.identityKey === identityKey,
  );
  if (device) device.trustState = trustState;
}

export async function requestLocationPermission(): Promise<PermissionStatus> {
  if (isTauri) {
    return invoke<PermissionStatus>("request_location_permission");
  }
  previewSnapshot.permissions.location = "allowed";
  return structuredClone(previewSnapshot.permissions);
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
