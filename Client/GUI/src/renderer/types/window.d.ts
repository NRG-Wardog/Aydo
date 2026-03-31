/// <reference types="vite/client" />

interface Window {
  avBridge: {
    connect: () => Promise<{ ok: boolean; message: string }>;
    disconnect: () => Promise<{ ok: boolean; message: string }>;
    getSnapshot: () => any;
    startScan: (request: any) => Promise<{ ok: boolean; message: string }>;
    setSettings: (settings: any) => Promise<void>;
    onEvent: (handler: (payload: any) => void) => () => void;
    pickScanTarget: () => Promise<string | null>;
    authLogin: (payload: {
      email: string;
      password: string;
      serverUrl: string;
    }) => Promise<any>;
    authRegister: (payload: {
      email: string;
      password: string;
      nickname: string;
      serverUrl: string;
    }) => Promise<any>;
    authSession: () => Promise<any>;
    closeWindow: () => void;
    minimizeWindow: () => void;
    maximizeWindow: () => void;
  };
}
