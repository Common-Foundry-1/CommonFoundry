import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const nodeProxy = {
  "/v1": {
    target: "http://127.0.0.1:22443",
    changeOrigin: true,
  },
};

export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5175, strictPort: true, proxy: nodeProxy },
  preview: { host: "127.0.0.1", port: 4175, strictPort: true, proxy: nodeProxy },
  test: { environment: "jsdom", setupFiles: ["./src/test/setup.ts"], css: true },
});
