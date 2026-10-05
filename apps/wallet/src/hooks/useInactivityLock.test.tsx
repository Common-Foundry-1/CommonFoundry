import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useInactivityLock } from "./useInactivityLock";

describe("useInactivityLock", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("locks after the timeout, and activity restarts the clock", () => {
    const onLock = vi.fn();
    renderHook(() => useInactivityLock(true, onLock, 60_000));
    vi.advanceTimersByTime(45_000);
    window.dispatchEvent(new Event("keydown"));
    vi.advanceTimersByTime(45_000);
    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(30_000);
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("does nothing while disabled", () => {
    const onLock = vi.fn();
    renderHook(() => useInactivityLock(false, onLock, 60_000));
    vi.advanceTimersByTime(600_000);
    expect(onLock).not.toHaveBeenCalled();
  });
});
