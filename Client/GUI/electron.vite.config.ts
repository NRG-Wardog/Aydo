import { defineConfig } from "electron-vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const sharedAlias = {
  "@shared": path.resolve(__dirname, "src/shared")
};

export default defineConfig({
  main: {
    entry: path.resolve(__dirname, "src/main/main.ts"),
    resolve: {
      alias: sharedAlias
    },
    build: {
      outDir: path.resolve(__dirname, "dist/main"),
      rollupOptions: {
        output: {
          entryFileNames: "index.js"
        }
      }
    },
    define: {
      __VITE_DEV_SERVER_URL__: JSON.stringify(process.env.VITE_DEV_SERVER_URL || "")
    }
  },
  preload: {
    entry: path.resolve(__dirname, "src/preload/preload.ts"),
    resolve: {
      alias: sharedAlias
    },
    build: {
      outDir: path.resolve(__dirname, "dist/preload"),
      rollupOptions: {
        output: {
          entryFileNames: "index.mjs"
        }
      }
    }
  },
  renderer: {
    root: path.resolve(__dirname, "src/renderer"),
    build: {
      outDir: path.resolve(__dirname, "dist/renderer"),
      emptyOutDir: true
    },
    resolve: {
      alias: {
        "@renderer": path.resolve(__dirname, "src/renderer"),
        ...sharedAlias
      }
    },
    plugins: [react()]
  }
});
