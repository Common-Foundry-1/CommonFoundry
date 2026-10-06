export const shortHash = (value: string, head = 10, tail = 8) =>
  value.length <= head + tail + 1 ? value : `${value.slice(0, head)}…${value.slice(-tail)}`;

export const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
};

export const formatAtoms = (atoms: string) => {
  const value = BigInt(atoms || "0");
  const whole = value / 100_000_000n;
  const fraction = (value % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return `${whole.toLocaleString()}${fraction ? `.${fraction}` : ""} CMFD`;
};

/** Whole CMFD, for headline figures. */
export const formatSupply = (atoms: string) => `${(BigInt(atoms) / 100_000_000n).toLocaleString()} CMFD`;

// Consensus TARGET_SPACING_SECONDS; one Forge Work (FW) is one complete nonce evaluation.
const TARGET_SPACING_SECONDS = 60;
const compactNumber = new Intl.NumberFormat("en-US", { notation: "compact", maximumSignificantDigits: 3 });

/** Expected FW per block for a target (`floor(2^256 / (target + 1))`, as in consensus `block_work`). */
export const blockWork = (target: string) => (1n << 256n) / (BigInt(`0x${target}`) + 1n);

export const formatBlockWork = (target: string) => `${compactNumber.format(Number(blockWork(target)))} FW per block`;

/** Network FW/s implied by the next block's difficulty at the 60-second target spacing. */
export const formatNetworkWorkRate = (target: string) =>
  `${compactNumber.format(Number(blockWork(target)) / TARGET_SPACING_SECONDS)} FW/s`;

export const formatAge = (timestamp: number) => {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - timestamp);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
};
