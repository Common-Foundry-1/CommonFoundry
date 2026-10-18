import { hrpForNetwork } from "./addressCodec";

/**
 * The address prefix for the network a wallet reports. Wallet snapshots and
 * custody status carry the profile name ("CommonFoundry Mainnet"); node status
 * carries the short name ("Mainnet").
 */
export function walletAddressHrp(network: string | undefined): string {
  return hrpForNetwork((network ?? "").replace(/^Common\s?Foundry\s+/i, ""));
}
