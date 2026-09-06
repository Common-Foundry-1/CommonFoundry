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

export const formatAge = (timestamp: number) => {
  const difference = Math.floor(Date.now() / 1000) - timestamp;
  const seconds = Math.abs(difference);
  const duration = seconds < 60 ? `${seconds}s`
    : seconds < 3600 ? `${Math.floor(seconds / 60)}m`
    : seconds < 86400 ? `${Math.floor(seconds / 3600)}h`
    : `${Math.floor(seconds / 86400)}d`;
  return difference < 0 ? `in ${duration}` : `${duration} ago`;
};
