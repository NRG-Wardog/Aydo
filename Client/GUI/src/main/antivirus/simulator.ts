import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import type {
  AvEvent,
  AvSettings,
  HandshakeRequest,
  HandshakeResponse,
  ScanRequest
} from "@shared/antivirus";
import { AV_PROTOCOL_VERSION } from "@shared/antivirus";
import type { AntivirusEngine } from "./engine";

const isFastSim = process.env.AYDO_SIM_FAST === "1";
const HEARTBEAT_INTERVAL_MS = isFastSim ? 1200 : 4500;
const AMBIENT_INTERVAL_MS = isFastSim ? 3200 : 11000;

const defaultSettings: AvSettings = {
  sensitivity: "balanced",
  realtime: true,
  startupScan: true,
  scanDepth: "standard",
  telemetry: true,
  serverUrl: "http://192.168.56.1",
  accessToken: "",
  refreshToken: "",
  killThreshold: 150,
  entropyThreshold: 6.0,
  runtime: 60
};

export class AntivirusSimulator extends EventEmitter implements AntivirusEngine {
  private connected = false;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private ambientTimer: NodeJS.Timeout | null = null;
  private scanTimer: NodeJS.Timeout | null = null;
  private progress = 0;
  private settings: AvSettings = { ...defaultSettings };

  async handshake(request: HandshakeRequest): Promise<HandshakeResponse> {
    await delay(320);

    if (request.protocolVersion !== AV_PROTOCOL_VERSION) {
      return {
        ok: false,
        engineVersion: "sim-1.0.0",
        serverTime: new Date().toISOString(),
        message: "Protocol mismatch"
      };
    }

    if (!request.token) {
      return {
        ok: false,
        engineVersion: "sim-1.0.0",
        serverTime: new Date().toISOString(),
        message: "Missing token"
      };
    }

    return {
      ok: true,
      engineVersion: "sim-1.0.0",
      serverTime: new Date().toISOString()
    };
  }

  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }

    this.connected = true;
    this.emitEvent("status", "low", "Simulator connected", { state: "connected" });

    this.heartbeatTimer = setInterval(() => {
      this.emitEvent("heartbeat", "low", "Engine heartbeat", {
        pingMs: 18 + Math.round(Math.random() * 15),
        engineVersion: "sim-1.0.0"
      });
    }, HEARTBEAT_INTERVAL_MS);

    this.ambientTimer = setInterval(() => {
      if (!this.connected || this.scanTimer) {
        return;
      }

      const roll = Math.random();
      if (roll > 0.82) {
        this.emitEvent("threat_detected", "high", "Suspicious behavior blocked", {
          family: "Ransomware.Generic",
          action: "blocked"
        });
      } else if (roll > 0.55) {
        this.emitEvent("info", "low", "Realtime shield recalibrated", {
          module: "behavioral"
        });
      }
    }, AMBIENT_INTERVAL_MS);
  }

  async disconnect(): Promise<void> {
    if (!this.connected) {
      return;
    }

    this.connected = false;
    this.progress = 0;
    this.clearTimers();
    this.emitEvent("status", "medium", "Simulator disconnected", { state: "disconnected" });
  }

  async startScan(request: ScanRequest): Promise<void> {
    if (!this.connected) {
      throw new Error("Engine not connected");
    }

    if (this.scanTimer) {
      return;
    }

    this.progress = 0;
    const scanTarget = request.paths?.[0] ?? "System";

    this.emitEvent("info", "low", `Scan started (${request.depth})`, {
      target: scanTarget,
      depth: request.depth
    });

    const scanInterval = isFastSim ? 240 : 720;
    this.scanTimer = setInterval(() => {
      this.progress = Math.min(100, this.progress + 6 + Math.round(Math.random() * 10));

      if (Math.random() > this.thresholdForThreat()) {
        this.emitEvent("threat_detected", "high", "Threat neutralized", {
          file: "C:/Windows/Temp/trace.tmp",
          family: "Trojan.Injector",
          action: "quarantined"
        });
      }

      this.emitEvent("scan_progress", "low", "Scanning", {
        progress: this.progress,
        itemsScanned: 320 + Math.round(Math.random() * 180),
        target: scanTarget
      });

      if (this.progress >= 100) {
        this.finishScan(scanTarget);
      }
    }, scanInterval);
  }

  setSettings(settings: AvSettings): void {
    this.settings = { ...settings };
    this.emitEvent("info", "low", "Settings applied", { settings: this.settings });
  }

  getSettings(): AvSettings {
    return { ...this.settings };
  }

  getType(): "simulator" {
    return "simulator";
  }

  onEvent(listener: (event: AvEvent) => void): () => void {
    this.on("event", listener);
    return () => this.off("event", listener);
  }

  isConnected(): boolean {
    return this.connected;
  }

  private finishScan(target: string): void {
    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = null;
    }

    this.emitEvent("scan_complete", "low", "Scan completed", {
      target,
      durationSec: 68 + Math.round(Math.random() * 40),
      threatsFound: Math.round(Math.random() * 3)
    });
  }

  private thresholdForThreat(): number {
    switch (this.settings.sensitivity) {
      case "low":
        return 0.98;
      case "aggressive":
        return 0.7;
      default:
        return 0.85;
    }
  }

  private emitEvent(
    type: AvEvent["type"],
    severity: AvEvent["severity"],
    message: string,
    data?: Record<string, unknown>
  ): void {
    const event: AvEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type,
      severity,
      message,
      data
    };

    this.emit("event", event);
  }

  private clearTimers(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    if (this.ambientTimer) {
      clearInterval(this.ambientTimer);
      this.ambientTimer = null;
    }

    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = null;
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
