import { contextBridge, ipcRenderer } from "electron";
import type {
  AvEventEnvelope,
  AvSettings,
  AvSnapshot,
  ScanRequest,
} from "@shared/antivirus";

type AuthResult = {
  ok: boolean;
  message: string;
  accessToken?: string;
  refreshToken?: string;
  nickname?: string;
  offline?: boolean;
};

type AuthSessionResult = {
  ok: boolean;
  message: string;
  email?: string;
  nickname?: string;
  offline?: boolean;
};

type AvBridgeApi = {
  connect: () => Promise<{ ok: boolean; message: string }>;
  disconnect: () => Promise<{ ok: boolean; message: string }>;
  getSnapshot: () => Promise<AvSnapshot>;
  startScan: (
    request: ScanRequest,
  ) => Promise<{ ok: boolean; message: string }>;
  setSettings: (settings: AvSettings) => Promise<void>;
  onEvent: (handler: (payload: AvEventEnvelope) => void) => () => void;
  pickScanTarget: () => Promise<string | null>;
  readDirectory: (dirPath: string) => Promise<{
    ok: boolean;
    entries?: {
      name: string;
      path: string;
      isDirectory: boolean;
      size?: number;
      extension?: string;
    }[];
    error?: string;
  }>;
  authLogin: (payload: {
    email: string;
    password: string;
    serverUrl: string;
  }) => Promise<AuthResult>;
  authRegister: (payload: {
    email: string;
    password: string;
    nickname: string;
    serverUrl: string;
  }) => Promise<AuthResult>;
  authSession: () => Promise<AuthSessionResult>;
  closeWindow: () => void;
  minimizeWindow: () => void;
  maximizeWindow: () => void;
};

const preloadStatus = {
  ok: true,
  error: null as string | null,
  sandboxed:
    typeof process !== "undefined" ? Boolean(process.sandboxed) : false,
};

try {
  const api: AvBridgeApi = {
    connect: () => ipcRenderer.invoke("av:connect"),
    disconnect: () => ipcRenderer.invoke("av:disconnect"),
    getSnapshot: () => ipcRenderer.invoke("av:snapshot"),
    startScan: (request) => ipcRenderer.invoke("av:start-scan", request),
    setSettings: (settings) => ipcRenderer.invoke("av:set-settings", settings),
    pickScanTarget: () => ipcRenderer.invoke("av:pick-scan-target"),
    readDirectory: (dirPath: string) =>
      ipcRenderer.invoke("fs:read-directory", dirPath),
    authLogin: (payload) => ipcRenderer.invoke("auth:login", payload),
    authRegister: (payload) => ipcRenderer.invoke("auth:register", payload),
    authSession: () => ipcRenderer.invoke("auth:session"),
    closeWindow: () => ipcRenderer.invoke("window:close"),
    minimizeWindow: () => ipcRenderer.invoke("window:minimize"),
    maximizeWindow: () => ipcRenderer.invoke("window:maximize"),
    onEvent: (handler) => {
      const listener = (
        _event: Electron.IpcRendererEvent,
        payload: AvEventEnvelope,
      ) => handler(payload);
      ipcRenderer.on("av:event", listener);
      return () => ipcRenderer.removeListener("av:event", listener);
    },
  };

  contextBridge.exposeInMainWorld("avBridge", api);
} catch (error) {
  preloadStatus.ok = false;
  preloadStatus.error =
    error instanceof Error ? error.message : "Unknown preload error";
}

contextBridge.exposeInMainWorld("__preloadStatus", preloadStatus);
