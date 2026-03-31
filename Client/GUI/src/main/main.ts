import { app, BrowserWindow, ipcMain, shell, dialog } from "electron";
import fs from "node:fs";
import path from "node:path";
import { AntivirusBridge } from "./antivirus/bridge";
import { createAntivirusEngine } from "./antivirus/engineFactory";
import type {
  AvEventEnvelope,
  AvSettings,
  ScanRequest,
} from "@shared/antivirus";

const DEV_SERVER_PORTS = [5173, 5174, 5175, 5176];
const DEV_SERVER_PING_TIMEOUT_MS = 1000;
const WINDOW_DEFAULT_WIDTH = 1280;
const WINDOW_DEFAULT_HEIGHT = 820;
const WINDOW_MIN_WIDTH = 1080;
const WINDOW_MIN_HEIGHT = 720;

const sendToRenderer = (channel: string, payload: AvEventEnvelope) => {
  for (const window of BrowserWindow.getAllWindows()) {
    window.webContents.send(channel, payload);
  }
};

const resolveAuthSession = async (): Promise<AuthSessionResponse> => {
  const snapshot = bridge.getSnapshot();
  const serverUrl = normalizeServerUrl(snapshot.settings.serverUrl ?? "");
  const accessToken = snapshot.settings.accessToken?.trim() ?? "";

  if (!serverUrl || !accessToken) {
    return { ok: false, message: "No authenticated service session" };
  }

  try {
    const meResponse = await fetch(`${serverUrl}/api/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!meResponse.ok) {
      return {
        ok: false,
        message: `Session validation failed (${meResponse.status})`,
      };
    }

    const meData = await meResponse.json().catch(() => null);
    const mePayload =
      meData &&
      typeof meData === "object" &&
      meData.data &&
      typeof meData.data === "object"
        ? (meData.data as Record<string, unknown>)
        : (meData as Record<string, unknown> | null);
    const email =
      mePayload && typeof mePayload.email === "string" ? mePayload.email : "";
    const nickname =
      mePayload && typeof mePayload.nickname === "string"
        ? mePayload.nickname
        : undefined;

    if (!email) {
      return { ok: false, message: "Session user payload is invalid" };
    }

    return {
      ok: true,
      message: "Session restored",
      email,
      nickname,
    };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Failed to resolve session";
    return { ok: false, message, offline: true };
  }
};

const bridge = new AntivirusBridge(sendToRenderer, createAntivirusEngine());
bridge.init();

type AuthResponse = {
  ok: boolean;
  message: string;
  accessToken?: string;
  refreshToken?: string;
  nickname?: string;
  offline?: boolean;
};

type AuthSessionResponse = {
  ok: boolean;
  message: string;
  email?: string;
  nickname?: string;
  offline?: boolean;
};

const normalizeServerUrl = (raw: string): string => {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  return trimmed.replace(/\/+$/, "");
};

const performAuth = async (
  mode: "login" | "register",
  payload: {
    email: string;
    password: string;
    nickname?: string;
    serverUrl: string;
  },
): Promise<AuthResponse> => {
  if (process.env.AYDO_AUTH_OFFLINE === "1") {
    return {
      ok: false,
      message:
        "Authentication is disabled in offline mode. Connect to the server or continue as guest.",
      offline: true,
    };
  }

  const serverUrl = normalizeServerUrl(payload.serverUrl);
  if (!serverUrl) {
    return { ok: false, message: "Server URL is required" };
  }

  const endpoint = mode === "login" ? "/api/auth/login" : "/api/auth/register";
  const body =
    mode === "login"
      ? { email: payload.email, password: payload.password }
      : {
          email: payload.email,
          nickname: payload.nickname ?? payload.email,
          password: payload.password,
        };

  try {
    const response = await fetch(`${serverUrl}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const data = await response.json().catch(() => null);
    if (!response.ok) {
      return {
        ok: false,
        message: data?.message ?? `Auth failed (${response.status})`,
      };
    }

    const accessToken = data?.accessToken as string | undefined;
    const refreshToken = data?.refreshToken as string | undefined;
    let nickname = payload.nickname;

    if (accessToken) {
      try {
        const meResponse = await fetch(`${serverUrl}/api/auth/me`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (meResponse.ok) {
          const meData = await meResponse.json().catch(() => null);
          const mePayload =
            meData &&
            typeof meData === "object" &&
            meData.data &&
            typeof meData.data === "object"
              ? (meData.data as Record<string, unknown>)
              : (meData as Record<string, unknown> | null);
          if (mePayload && typeof mePayload.nickname === "string") {
            nickname = mePayload.nickname;
          }
        }
      } catch {
        // Ignore profile errors; login is still valid.
      }
    }

    return {
      ok: true,
      message: data?.message ?? "Authenticated",
      accessToken,
      refreshToken,
      nickname,
    };
  } catch (error) {
    const nickname =
      payload.nickname ?? payload.email.split("@")[0] ?? "Analyst";
    const message = error instanceof Error ? error.message : "Network error";
    return {
      ok: true,
      message: `Server offline. Offline session enabled. (${message})`,
      nickname,
      offline: true,
    };
  }
};

const resolvePreloadPath = (): string => {
  const candidates = [
    path.join(__dirname, "../preload/preload.mjs"),
    path.join(process.cwd(), "dist/preload/preload.mjs"),
    path.join(process.cwd(), "out/preload/preload.mjs"),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return candidates[0];
};

const findDevServer = async (): Promise<string | undefined> => {
  // Try common dev server ports
  for (const port of DEV_SERVER_PORTS) {
    try {
      const url = `http://localhost:${port}`;
      const response = await fetch(url, {
        method: "HEAD",
        signal: AbortSignal.timeout(DEV_SERVER_PING_TIMEOUT_MS),
      });
      // if the dev server is fine (304 or 2xx)
      if (response.ok || response.status === 304) {
        return url;
      }
    } catch {
      // Port not responding, try next
    }
  }

  return undefined;
};

const createWindow = async (): Promise<void> => {
  const preloadPath = resolvePreloadPath();

  // Detect dev server URL
  let devServerUrl = process.env.VITE_DEV_SERVER_URL;
  if (!devServerUrl) {
    devServerUrl = await findDevServer();
  }

  const mainWindow = new BrowserWindow({
    width: WINDOW_DEFAULT_WIDTH,
    height: WINDOW_DEFAULT_HEIGHT,
    minWidth: WINDOW_MIN_WIDTH,
    minHeight: WINDOW_MIN_HEIGHT,
    backgroundColor: "#0c1219",
    frame: false,
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      preload: preloadPath,
    },
  });

  // Ensure developer tools are never opened automatically
  mainWindow.webContents.on("devtools-opened", () => {
    mainWindow.webContents.closeDevTools();
  });

  // Show window only after it's ready to prevent flicker
  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http")) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "allow" };
  });

  if (devServerUrl) {
    mainWindow.loadURL(devServerUrl);
  } else {
    mainWindow.loadFile(path.join(__dirname, "../renderer/index.html"));
  }
};

ipcMain.handle("av:connect", async () => bridge.connect());
ipcMain.handle("av:disconnect", async () => bridge.disconnect());
ipcMain.handle("av:snapshot", async () => bridge.getSnapshot());
ipcMain.handle("av:start-scan", async (_event, request: ScanRequest) =>
  bridge.startScan(request),
);
ipcMain.handle("av:set-settings", async (_event, settings: AvSettings) =>
  bridge.setSettings(settings),
);
ipcMain.handle("av:pick-scan-target", async () => {
  const result = await dialog.showOpenDialog({
    title: "Select file to scan",
    properties: ["openFile"],
  });
  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0] ?? null;
});

ipcMain.handle("fs:read-directory", async (_event, dirPath: string) => {
  try {
    const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
    const mapped = await Promise.all(
      entries.map(async (entry) => {
        const fullPath = path.join(dirPath, entry.name);
        const isDirectory = entry.isDirectory();
        let size: number | undefined;
        let extension: string | undefined;

        if (!isDirectory) {
          try {
            const stat = await fs.promises.stat(fullPath);
            size = stat.size;
          } catch {
            // ignore stat errors
          }
          const ext = path.extname(entry.name);
          if (ext) extension = ext;
        }

        return {
          name: entry.name,
          path: fullPath,
          isDirectory,
          size,
          extension,
        };
      }),
    );

    return { ok: true, entries: mapped };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Failed to read directory",
    };
  }
});

// Window controls
ipcMain.handle("window:close", () => {
  const window = BrowserWindow.getFocusedWindow();
  if (window) window.close();
});

ipcMain.handle("window:minimize", () => {
  const window = BrowserWindow.getFocusedWindow();
  if (window) window.minimize();
});

ipcMain.handle("window:maximize", () => {
  const window = BrowserWindow.getFocusedWindow();
  if (window) {
    if (window.isMaximized()) {
      window.unmaximize();
    } else {
      window.maximize();
    }
  }
});

ipcMain.handle(
  "auth:login",
  async (
    _event,
    payload: { email: string; password: string; serverUrl: string },
  ) => performAuth("login", payload),
);
ipcMain.handle(
  "auth:register",
  async (
    _event,
    payload: {
      email: string;
      password: string;
      nickname: string;
      serverUrl: string;
    },
  ) => performAuth("register", payload),
);
ipcMain.handle("auth:session", async () => resolveAuthSession());

app.whenReady().then(async () => {
  await createWindow();
  bridge.connect();

  app.on("activate", async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
