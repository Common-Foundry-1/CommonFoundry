import { vi } from "vitest";

import type { UpdateStatus, UpdateTransport } from "../api/updateClient";

export function updateStatus(overrides: Partial<UpdateStatus> = {}): UpdateStatus {
  return {
    build: "release",
    current_version: "1.0.16",
    automatic: true,
    disabled_by_launch_option: false,
    status: { state: "up_to_date" },
    last_checked_at: null,
    check_failures: 0,
    check_failed_since: null,
    fallback: null,
    restart_failed: null,
    old_versions: [],
    ...overrides,
  };
}

/** Every command answers with `status` unless a test says otherwise. */
export function fakeUpdateTransport(status: UpdateStatus) {
  return {
    getUpdateStatus: vi.fn<UpdateTransport["getUpdateStatus"]>().mockResolvedValue(status),
    setUpdateAutomatic: vi.fn<UpdateTransport["setUpdateAutomatic"]>().mockResolvedValue(status),
    checkForUpdates: vi.fn<UpdateTransport["checkForUpdates"]>().mockResolvedValue(status),
    downloadUpdate: vi.fn<UpdateTransport["downloadUpdate"]>().mockResolvedValue(status),
    restartToUpdate: vi.fn<UpdateTransport["restartToUpdate"]>().mockResolvedValue(undefined),
    retryUpdate: vi.fn<UpdateTransport["retryUpdate"]>().mockResolvedValue(undefined),
    runOlderAnyway: vi.fn<UpdateTransport["runOlderAnyway"]>().mockResolvedValue(status),
    removeOldVersions: vi.fn<UpdateTransport["removeOldVersions"]>().mockResolvedValue(status),
  } satisfies UpdateTransport;
}

/** What the wallet answers when it refuses a command. */
export function refusal(code: string, message: string) {
  return { code, message, status: 409, retryable: true };
}
