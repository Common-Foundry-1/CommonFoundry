import { useEffect, useRef } from "react";

export const INACTIVITY_LOCK_MS = 15 * 60_000;
const ACTIVITY_EVENTS = ["pointerdown", "keydown", "touchstart"] as const;

/** Calls onLock once `timeoutMs` passes without pointer or keyboard activity while `enabled`. */
export function useInactivityLock(
  enabled: boolean,
  onLock: () => Promise<void> | void,
  timeoutMs = INACTIVITY_LOCK_MS,
) {
  const lockRef = useRef(onLock);
  lockRef.current = onLock;

  useEffect(() => {
    if (!enabled) return;
    let lastActivity = Date.now();
    const touch = () => { lastActivity = Date.now(); };
    for (const name of ACTIVITY_EVENTS) window.addEventListener(name, touch, { passive: true });
    const timer = window.setInterval(() => {
      if (Date.now() - lastActivity < timeoutMs) return;
      void Promise.resolve(lockRef.current()).catch(() => undefined);
    }, Math.min(30_000, timeoutMs));
    return () => {
      for (const name of ACTIVITY_EVENTS) window.removeEventListener(name, touch);
      window.clearInterval(timer);
    };
  }, [enabled, timeoutMs]);
}
