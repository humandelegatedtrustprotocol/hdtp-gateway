import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The build lands in dist/, which go:embed compiles into the binary (embed.go).
// The dev server proxies the data plane to a locally running node, so `npm run
// dev` gives hot reload against real endpoints.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", assetsDir: "assets", sourcemap: false, target: "es2022" },
  server: {
    proxy: Object.fromEntries(
      ["/api", "/login", "/setup", "/logout", "/contacts", "/messages", "/threads",
       "/invites", "/requests", "/identity", "/integrations", "/owners", "/settings",
       "/media", "/events", "/card.vcf", "/oauth", "/i"].map((p) => [
        p, { target: "http://127.0.0.1:8080", changeOrigin: false },
      ]),
    ),
  },
});
