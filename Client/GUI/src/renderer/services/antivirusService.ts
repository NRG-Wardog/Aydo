import { useSyncExternalStore } from "react";
import type {
  AvEventEnvelope,
  AvSettings,
  AvSnapshot,
  ScanRequest,
  ScanDepth,
} from "@shared/antivirus";

const SERVER_DEFAULT_URL = "http://192.168.56.1";
const DEFAULT_KILL_THRESHOLD = 150;
const DEFAULT_ENTROPY_THRESHOLD = 7.0;
const DEFAULT_RUNTIME = 60;
const DEFAULT_SCAN_TARGET = "System";

export type AntivirusState = AvSnapshot & {
  loading: boolean;
  error: string | null;
};

class AntivirusService {
  private state: AntivirusState = {
    engineType: "simulator",
    connectionState: "disconnected",
    statusMessage: "Awaiting engine",
    stats: {
      dailyActivity: 0,
      detections: 0,
      quarantined: 0,
      lastScanAt: null,
      lastScanDurationSec: null,
    },
    activity: [],
    breakdown: [],
    recentEvents: [],
    settings: {
      sensitivity: "balanced",
      realtime: true,
      startupScan: true,
      scanDepth: "standard",
      telemetry: true,
      serverUrl: SERVER_DEFAULT_URL,
      accessToken: "",
      refreshToken: "",
      killThreshold: DEFAULT_KILL_THRESHOLD,
      entropyThreshold: DEFAULT_ENTROPY_THRESHOLD,
      runtime: DEFAULT_RUNTIME,
      infectedFileAction: "none",
    },
    scan: { inProgress: false, progress: 0, target: null },
    capabilities: {
      driver: false,
      hashdb: false,
      yara: false,
      entropy: false,
      cloud: false,
    },
    loading: true,
    error: null,
  };

  private listeners = new Set<() => void>();
  private eventListeners = new Set<(event: AvEventEnvelope) => void>();
  private initialized = false;

  private getBridge() {
    return typeof window !== "undefined" ? window.avBridge : undefined;
  }

  async init(): Promise<void> {
    if (this.initialized) {
      return;
    }
    this.initialized = true;

    try {
      const bridge = this.getBridge();
      if (!bridge) {
        this.update({ loading: false, error: "Bridge unavailable" });
        return;
      }
      const snapshot = await bridge.getSnapshot();
      this.update({ ...snapshot, loading: false, error: null });
    } catch (error) {
      this.update({
        loading: false,
        error: error instanceof Error ? error.message : "Failed to load",
      });
    }

    const bridge = this.getBridge();
    if (bridge) {
      bridge.onEvent((payload) => this.handleEvent(payload));
    }
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  onEvent(listener: (event: AvEventEnvelope) => void): () => void {
    this.eventListeners.add(listener);
    return () => this.eventListeners.delete(listener);
  }

  getState(): AntivirusState {
    return this.state;
  }

  async connect(): Promise<{ ok: boolean; message: string }> {
    this.update({
      connectionState: "connecting",
      statusMessage: "Negotiating secure channel",
    });
    const bridge = this.getBridge();
    if (!bridge) {
      this.update({
        connectionState: "disconnected",
        statusMessage: "Bridge unavailable",
      });
      return { ok: false, message: "Bridge unavailable" };
    }
    const result = await bridge.connect();
    if (!result.ok) {
      this.update({
        connectionState: "disconnected",
        statusMessage: result.message,
      });
    }
    return result;
  }

  async disconnect(): Promise<{ ok: boolean; message: string }> {
    const bridge = this.getBridge();
    if (!bridge) {
      this.update({
        connectionState: "disconnected",
        statusMessage: "Bridge unavailable",
      });
      return { ok: false, message: "Bridge unavailable" };
    }
    const result = await bridge.disconnect();
    this.update({
      connectionState: "disconnected",
      statusMessage: "Engine offline",
    });
    return result;
  }

  async startScan(
    request: ScanRequest,
  ): Promise<{ ok: boolean; message: string }> {
    this.update({
      scan: {
        inProgress: true,
        progress: 0,
        target: request.paths?.[0] ?? DEFAULT_SCAN_TARGET,
      },
    });
    const bridge = this.getBridge();
    if (!bridge) {
      this.update({
        scan: { inProgress: false, progress: 0, target: null },
        error: "Bridge unavailable",
      });
      return { ok: false, message: "Bridge unavailable" };
    }
    try {
      return await bridge.startScan(request);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Scan failed";
      this.update({
        scan: { inProgress: false, progress: 0, target: null },
        error: message,
      });
      return { ok: false, message };
    }
  }

  async requestScan(
    depth: ScanDepth,
  ): Promise<{ ok: boolean; message: string }> {
    const bridge = this.getBridge();
    if (!bridge) {
      this.update({ error: "Bridge unavailable" });
      return { ok: false, message: "Bridge unavailable" };
    }

    if (this.state.engineType === "client") {
      const target = await bridge.pickScanTarget();
      if (!target) {
        return { ok: false, message: "No file selected" };
      }
      return this.startScan({ depth, paths: [target] });
    }

    return this.startScan({ depth });
  }

  async updateSettings(settings: AvSettings): Promise<void> {
    this.update({ settings: { ...settings } });
    const bridge = this.getBridge();
    if (!bridge) {
      this.update({ error: "Bridge unavailable" });
      return;
    }
    await bridge.setSettings(settings);
  }

  private handleEvent(payload: AvEventEnvelope): void {
    this.update({ ...payload.snapshot, loading: false, error: null });
    this.eventListeners.forEach((listener) => listener(payload));
  }

  private update(partial: Partial<AntivirusState>): void {
    this.state = { ...this.state, ...partial };
    this.listeners.forEach((listener) => listener());
  }
}

export const antivirusService = new AntivirusService();

export const useAntivirus = (): AntivirusState =>
  useSyncExternalStore(
    (listener) => antivirusService.subscribe(listener),
    () => antivirusService.getState(),
    () => antivirusService.getState(),
  );
