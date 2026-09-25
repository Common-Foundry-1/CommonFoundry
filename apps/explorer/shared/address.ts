export const ADDRESS_HASH = /^[0-9a-fA-F]{64}$/;
export const ADDRESS_PAGE_SIZE = 20;
const CURSOR = /^([0-9a-fA-F]{64})\.([1-9][0-9]{0,19})\.(0|[1-9][0-9]{0,3})$/;

export function isAddressCursor(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = CURSOR.exec(value);
  return match !== null && BigInt(match[2]) <= 18_446_744_073_709_551_615n && Number(match[3]) <= 1024;
}

export function isAddressApiPath(path: string): boolean {
  const match = /^\/v1\/explorer\/address\/([0-9a-fA-F]{64})(?:\/([^/]+))?$/.exec(path);
  return match !== null && (match[2] === undefined || isAddressCursor(match[2]));
}
