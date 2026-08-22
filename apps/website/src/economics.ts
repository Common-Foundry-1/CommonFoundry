export const ATOMIC_UNITS_PER_CMFD = 100_000_000n;
export const INITIAL_EMISSION_BLOCKS = 2_628_000n;
export const TAIL_HEIGHT = INITIAL_EMISSION_BLOCKS + 1n;
export const INITIAL_SUBSIDY = 500n * ATOMIC_UNITS_PER_CMFD;
export const TAIL_SUBSIDY = 5n * ATOMIC_UNITS_PER_CMFD;

export function emissionAtHeight(height: number | bigint): bigint {
  const normalized = typeof height === "bigint" ? height : BigInt(height);

  if (normalized < 0n) {
    throw new RangeError("height must be non-negative");
  }

  if (normalized >= TAIL_HEIGHT) {
    return TAIL_SUBSIDY;
  }

  const elapsed = normalized > 0n ? normalized - 1n : 0n;
  const remaining = INITIAL_EMISSION_BLOCKS - elapsed;
  return (INITIAL_SUBSIDY * remaining) / INITIAL_EMISSION_BLOCKS;
}

export function formatCmfd(atomicUnits: bigint): string {
  const whole = atomicUnits / ATOMIC_UNITS_PER_CMFD;
  const fraction = atomicUnits % ATOMIC_UNITS_PER_CMFD;

  if (fraction === 0n) {
    return whole.toLocaleString("en-US");
  }

  const fractionText = fraction.toString().padStart(8, "0").replace(/0+$/, "");
  return `${whole.toLocaleString("en-US")}.${fractionText}`;
}

export function heightToYear(height: number): number {
  if (height >= Number(TAIL_HEIGHT)) {
    return 5;
  }

  return Math.max(0, (height - 1) / (365 * 24 * 60));
}
