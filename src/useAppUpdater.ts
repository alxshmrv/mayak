import { useCallback, useEffect, useRef, useState } from "react";
import {
  checkForAppUpdate,
  getInstalledVersion,
  installPendingUpdate,
  type AvailableAppUpdate,
  type UpdateDownloadProgress,
} from "./updater";

const AUTO_CHECK_DELAY_MS = 4_000;
const PERIODIC_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1_000;

export type UpdatePhase =
  | "idle"
  | "checking"
  | "current"
  | "available"
  | "downloading"
  | "installing"
  | "restarting"
  | "failed";

export interface AppUpdateState {
  phase: UpdatePhase;
  installedVersion?: string;
  available?: AvailableAppUpdate;
  downloadedBytes: number;
  totalBytes?: number;
  lastCheckedAt?: string;
  /** The last check or install failed; the interface shows a localized message. */
  error?: boolean;
  dialogOpen: boolean;
}

const initialState: AppUpdateState = {
  phase: "idle",
  downloadedBytes: 0,
  dialogOpen: false,
};

function reportUpdateError(cause: unknown) {
  console.warn("Mayak updater failed", cause);
  return true;
}

export function useAppUpdater() {
  const [state, setState] = useState<AppUpdateState>(initialState);
  const checkingRef = useRef(false);
  const installingRef = useRef(false);
  const availableRef = useRef(false);

  useEffect(() => {
    let active = true;
    void getInstalledVersion()
      .then((installedVersion) => {
        if (active) setState((current) => ({ ...current, installedVersion }));
      })
      .catch((cause: unknown) => {
        console.warn("Unable to read Mayak version", cause);
      });
    return () => {
      active = false;
    };
  }, []);

  const checkNow = useCallback(async (showCurrentResult = true) => {
    if (checkingRef.current || installingRef.current || availableRef.current) return;
    checkingRef.current = true;
    setState((current) => ({
      ...current,
      phase: "checking",
      error: undefined,
    }));
    try {
      const available = await checkForAppUpdate();
      const lastCheckedAt = new Date().toISOString();
      if (available) {
        availableRef.current = true;
        setState((current) => ({
          ...current,
          phase: "available",
          installedVersion: available.currentVersion,
          available,
          downloadedBytes: 0,
          totalBytes: undefined,
          lastCheckedAt,
          dialogOpen: true,
        }));
      } else {
        availableRef.current = false;
        setState((current) => ({
          ...current,
          phase: showCurrentResult ? "current" : "idle",
          available: undefined,
          downloadedBytes: 0,
          totalBytes: undefined,
          lastCheckedAt,
          error: undefined,
        }));
      }
    } catch (cause) {
      availableRef.current = false;
      setState((current) => ({
        ...current,
        phase: "failed",
        available: undefined,
        dialogOpen: false,
        error: reportUpdateError(cause),
        lastCheckedAt: new Date().toISOString(),
      }));
    } finally {
      checkingRef.current = false;
    }
  }, []);

  useEffect(() => {
    const initialCheck = window.setTimeout(
      () => void checkNow(false),
      AUTO_CHECK_DELAY_MS,
    );
    const periodicCheck = window.setInterval(
      () => void checkNow(false),
      PERIODIC_CHECK_INTERVAL_MS,
    );
    return () => {
      window.clearTimeout(initialCheck);
      window.clearInterval(periodicCheck);
    };
  }, [checkNow]);

  const install = useCallback(async () => {
    if (!state.available || installingRef.current) return;
    installingRef.current = true;
    setState((current) => ({
      ...current,
      phase: "downloading",
      downloadedBytes: 0,
      totalBytes: undefined,
      error: undefined,
      dialogOpen: true,
    }));
    try {
      await installPendingUpdate((progress: UpdateDownloadProgress) => {
        setState((current) => ({
          ...current,
          phase: progress.phase,
          downloadedBytes: progress.downloadedBytes,
          totalBytes: progress.totalBytes,
        }));
      });
      setState((current) => ({ ...current, phase: "restarting" }));
    } catch (cause) {
      installingRef.current = false;
      setState((current) => ({
        ...current,
        phase: "failed",
        error: reportUpdateError(cause),
        dialogOpen: true,
      }));
    }
  }, [state.available]);

  const dismissDialog = useCallback(() => {
    setState((current) => {
      if (
        current.phase === "downloading" ||
        current.phase === "installing" ||
        current.phase === "restarting"
      ) {
        return current;
      }
      return { ...current, dialogOpen: false };
    });
  }, []);

  const openDialog = useCallback(() => {
    setState((current) =>
      current.available ? { ...current, dialogOpen: true } : current,
    );
  }, []);

  return { state, checkNow, install, dismissDialog, openDialog };
}
