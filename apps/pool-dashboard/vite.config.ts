import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const dashboardProxy = {
  "/api": {
    target: "http://127.0.0.1:19446",
    changeOrigin: true,
  },
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5174,
    strictPort: true,
    proxy: dashboardProxy,
  },
  preview: {
    host: "127.0.0.1",
    port: 4174,
    strictPort: true,
    proxy: dashboardProxy,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: true,
  },
});
