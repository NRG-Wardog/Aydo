/// <reference types="vite/client" />

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

declare global {
  interface Window {
    avBridge: {
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
    };
    __preloadStatus?: { ok: boolean; error: string | null; sandboxed: boolean };
  }
}

export {};
