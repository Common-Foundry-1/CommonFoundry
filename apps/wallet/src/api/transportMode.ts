/** Hosted web wallet: keys live in this browser and chain data comes from the wallet edge API. */
export const usesBrowserKeys = import.meta.env.VITE_CMFD_TRANSPORT === "web";
