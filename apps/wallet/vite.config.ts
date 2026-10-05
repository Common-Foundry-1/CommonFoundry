import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const nodeProxy = {
  "/rpc": {
    target: "http://127.0.0.1:18443",
    changeOrigin: true,
    rewrite: (path: string) => path.replace(/^\/rpc/, ""),
  },
  // Web mode: the wallet edge Worker (`npm run dev` in apps/wallet-edge).
  "/v1": {
    target: "http://127.0.0.1:8787",
    changeOrigin: true,
  },
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: nodeProxy,
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
    proxy: nodeProxy,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: true,
  },
});
