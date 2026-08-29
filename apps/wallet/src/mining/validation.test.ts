import { describe, expect, it } from "vitest";
import { poolUrlError, workerNameError } from "./validation";

const pin = "aB".repeat(32);

describe("pool configuration validation", () => {
  it.each([
    `cmfd+tls://127.0.0.1:443?pin=${pin}`,
    `cmfd+tls://10.24.1.9:18181?pin=${pin}`,
    `cmfd+tls://172.16.0.2:65535?pin=${pin}`,
    `cmfd+tls://192.168.50.12:1?pin=${pin}`,
    `cmfd+tls://107.214.187.2:22445?pin=${pin}`,
    `cmfd+tls://8.8.8.8:443?pin=${pin}`,
    `cmfd+tls://[::1]:443?pin=${pin}`,
    `cmfd+tls://[fd12:3456::9]:8443?pin=${pin}`,
    `cmfd+tls://[2001:db8::20]:22445?pin=${pin}`,
  ])("accepts a pinned numeric endpoint: %s", (value) => {
    expect(poolUrlError(value)).toBeNull();
  });

  it.each([
    `stratum+tcp://192.168.1.2:443?pin=${pin}`,
    `cmfd+tls://pool.example:443?pin=${pin}`,
    `cmfd+tls://192.168.1.2:0?pin=${pin}`,
    `cmfd+tls://192.168.1.2:65536?pin=${pin}`,
    "cmfd+tls://192.168.1.2:443?pin=abcd",
    `cmfd+tls://192.168.1.2:443/path?pin=${pin}`,
    `cmfd+tls://192.168.1.2:443?pin=${pin}&extra=1`,
    `cmfd+tls://[fd12:::1]:443?pin=${pin}`,
  ])("rejects an endpoint outside the exact pinned-numeric format: %s", (value) => {
    expect(poolUrlError(value)).not.toBeNull();
  });

  it.each(["worker", "rig-01", "foundry.worker_2", "A".repeat(32)])(
    "accepts a valid worker name: %s",
    (value) => expect(workerNameError(value)).toBeNull(),
  );

  it.each(["", "worker name", "rig/01", "A".repeat(33)])(
    "rejects an invalid worker name: %s",
    (value) => expect(workerNameError(value)).not.toBeNull(),
  );
});
