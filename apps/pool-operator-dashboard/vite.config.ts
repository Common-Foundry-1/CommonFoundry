import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const operatorProxy = {
  "/api": {
    target: "http://127.0.0.1:19448",
    changeOrigin: true,
  },
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5176,
    strictPort: true,
    proxy: operatorProxy,
  },
  preview: {
    host: "127.0.0.1",
    port: 4176,
    strictPort: true,
    proxy: operatorProxy,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: true,
  },
});
