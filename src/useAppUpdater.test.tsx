import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAppUpdater } from "./useAppUpdater";

type Progress = {
  downloadedBytes: number;
  totalBytes?: number;
  phase: "downloading" | "installing";
};

const updaterMock = vi.hoisted(() => ({
  getInstalledVersion: vi.fn<() => Promise<string>>(),
  checkForAppUpdate: vi.fn(),
  installPendingUpdate: vi.fn<
    (onProgress: (progress: Progress) => void) => Promise<void>
  >(),
}));

vi.mock("./updater", () => updaterMock);

describe("useAppUpdater", () => {
  beforeEach(() => {
    updaterMock.getInstalledVersion.mockReset().mockResolvedValue("0.3.0");
    updaterMock.checkForAppUpdate.mockReset().mockResolvedValue(null);
    updaterMock.installPendingUpdate.mockReset().mockResolvedValue();
  });

  it("показывает найденную версию и устанавливает её с прогрессом", async () => {
    updaterMock.checkForAppUpdate.mockResolvedValue({
      currentVersion: "0.3.0",
      version: "0.3.1",
      date: "2026-07-30T10:00:00Z",
      notes: "Исправления безопасности",
    });
    updaterMock.installPendingUpdate.mockImplementation(async (onProgress) => {
      onProgress({
        downloadedBytes: 512,
        totalBytes: 1_024,
        phase: "downloading",
      });
      onProgress({
        downloadedBytes: 1_024,
        totalBytes: 1_024,
        phase: "installing",
      });
    });

    const { result } = renderHook(() => useAppUpdater());

    await waitFor(() => {
      expect(result.current.state.installedVersion).toBe("0.3.0");
    });

    await act(async () => {
      await result.current.checkNow();
    });
    expect(result.current.state).toMatchObject({
      phase: "available",
      dialogOpen: true,
      available: { version: "0.3.1" },
    });

    await act(async () => {
      await result.current.install();
    });
    expect(updaterMock.installPendingUpdate).toHaveBeenCalledOnce();
    expect(result.current.state).toMatchObject({
      phase: "restarting",
      downloadedBytes: 1_024,
      totalBytes: 1_024,
    });
  });

  it("не открывает диалог, если установлена последняя версия", async () => {
    const { result } = renderHook(() => useAppUpdater());

    await act(async () => {
      await result.current.checkNow();
    });

    expect(result.current.state).toMatchObject({
      phase: "current",
      dialogOpen: false,
      available: undefined,
    });
  });
});
