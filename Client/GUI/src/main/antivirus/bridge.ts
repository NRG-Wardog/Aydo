import { randomUUID } from "node:crypto";
import type {
  AvActivityPoint,
  AvBreakdownItem,
  AvConnectionState,
  AvEvent,
  AvEventEnvelope,
  AvSettings,
  AvSnapshot,
  AvStats,
  ScanRequest,
  AvEngineType,
  AvCapabilities,
  HandshakeResponse,
} from "@shared/antivirus";
import { AV_PROTOCOL_VERSION } from "@shared/antivirus";
import type { AntivirusEngine } from "./engine";
import { AntivirusSimulator } from "./simulator";

const CONNECT_TIMEOUT_MS = 2400;
const RECONNECT_DELAY_MS = 4000;
const HEARTBEAT_TIMEOUT_MS = 14000;
const MAX_EVENTS = 120;

const SERVER_DEFAULT_URL = "http://192.168.56.1";
const DEFAULT_KILL_THRESHOLD = 150;
const DEFAULT_ENTROPY_THRESHOLD = 7.0;
const DEFAULT_RUNTIME = 60;
const DEFAULT_SCAN_TARGET = "System";
const WATCHDOG_INTERVAL_MS = 6000;
const MAX_POINTS = 720;
const ACTIVITY_INTERVAL_MS = 5000; // 5s heartbeat
const ACTIVITY_INCREMENT_BASE = 1;
const ACTIVITY_INCREMENT_VARIANCE = 1;
const BUMP_ACTIVITY_MIN = 2;
const BUMP_ACTIVITY_VARIANCE = 3;
const MAX_PROGRESS = 100;
const BUMP_ACTIVITY_ON_COMPLETE = 5;

const defaultSettings: AvSettings = {
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
};

const defaultStats: AvStats = {
  dailyActivity: 0,
  detections: 0,
  quarantined: 0,
  lastScanAt: null,
  lastScanDurationSec: null,
};

const defaultBreakdown: AvBreakdownItem[] = [
  { label: "Clean", value: 0 },
  { label: "Blocked", value: 0 },
  { label: "Quarantined", value: 0 },
];

type Sender = (channel: string, payload: AvEventEnvelope) => void;

export class AntivirusBridge {
  private engine: AntivirusEngine;
  private sender: Sender;
  private engineType: AvEngineType;
  private connectionState: AvConnectionState = "disconnected";
  private statusMessage = "Engine offline";
  private settings: AvSettings = { ...defaultSettings };
  private stats: AvStats = { ...defaultStats };
  private activity: AvActivityPoint[] = seedActivity();
  private breakdown: AvBreakdownItem[] = [...defaultBreakdown];
  private recentEvents: AvEvent[] = [];
  private scan = {
    inProgress: false,
    progress: 0,
    target: null as string | null,
  };
  private capabilities: AvCapabilities = {
    driver: false,
    hashdb: false,
    yara: false,
    entropy: false,
    cloud: false,
  };
  private lastHeartbeatAt: number | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private watchdogTimer: NodeJS.Timeout | null = null;
  private clientId = randomUUID();
  private userRequestedDisconnect = false;
  private unsubscribe: (() => void) | null = null;

  constructor(
    sender: Sender,
    engine: AntivirusEngine = new AntivirusSimulator(),
  ) {
    this.sender = sender;
    this.engine = engine;
    this.engineType = engine.getType();
    this.settings = engine.getSettings();
  }

  init(): void {
    if (this.unsubscribe) {
      return;
    }

    this.unsubscribe = this.engine.onEvent((event) => this.handleEvent(event));
    this.settings = this.engine.getSettings();
    this.watchdogTimer = setInterval(
      () => this.monitorHeartbeat(),
      WATCHDOG_INTERVAL_MS,
    );
  }

  async connect(): Promise<{ ok: boolean; message: string }> {
    if (
      this.connectionState === "connected" ||
      this.connectionState === "connecting"
    ) {
      return { ok: true, message: "Already connected" };
    }

    this.userRequestedDisconnect = false;
    this.setStatus("connecting", "Negotiating secure channel");
    this.pushEvent("status", "low", "Negotiating secure channel", {
      state: "connecting",
    });

    const handshake = await withTimeout(
      this.engine.handshake({
        protocolVersion: AV_PROTOCOL_VERSION,
        clientId: this.clientId,
        token: "local-sim-token",
      }),
      CONNECT_TIMEOUT_MS,
    ).catch((error) => {
      const message =
        error instanceof Error ? error.message : "Handshake failed";
      this.setStatus("disconnected", message);
      return { ok: false, message } as HandshakeResponse;
    });

    if (!handshake || !handshake.ok) {
      this.setStatus(
        "disconnected",
        handshake?.message ?? "Handshake rejected",
      );
      return { ok: false, message: handshake?.message ?? "Handshake rejected" };
    }

    const connectError = await withTimeout(
      this.engine.connect(),
      CONNECT_TIMEOUT_MS,
    ).catch((error) => error);
    if (connectError) {
      const message =
        connectError instanceof Error
          ? connectError.message
          : "Connection failed";
      this.setStatus("disconnected", message);
      return { ok: false, message };
    }

    if (!this.engine.isConnected()) {
      this.setStatus("disconnected", "Engine unavailable");
      return { ok: false, message: "Engine unavailable" };
    }

    this.setStatus("connected", "Live protection active");
    this.pushEvent("status", "low", "Engine connected", {
      engineVersion: handshake.engineVersion,
    });
    return { ok: true, message: "Connected" };
  }

  async disconnect(): Promise<{ ok: boolean; message: string }> {
    this.userRequestedDisconnect = true;
    await this.engine.disconnect();
    this.setStatus("disconnected", "Engine offline");
    this.pushEvent("status", "medium", "Engine disconnected", {
      reason: "user",
    });
    return { ok: true, message: "Disconnected" };
  }

  async startScan(
    request: ScanRequest,
  ): Promise<{ ok: boolean; message: string }> {
    if (this.connectionState !== "connected") {
      return { ok: false, message: "Engine not connected" };
    }

    this.scan.inProgress = true;
    this.scan.progress = 0;
    this.scan.target = request.paths?.[0] ?? DEFAULT_SCAN_TARGET;
    await this.engine.startScan(request);
    return { ok: true, message: "Scan started" };
  }

  setSettings(settings: AvSettings): void {
    this.engine.setSettings(settings);
    this.settings = this.engine.getSettings();
    this.pushEvent("info", "low", "Settings updated", {
      settings: this.settings,
    });
  }

  getSnapshot(): AvSnapshot {
    return {
      engineType: this.engineType,
      connectionState: this.connectionState,
      statusMessage: this.statusMessage,
      stats: { ...this.stats },
      activity: [...this.activity],
      breakdown: [...this.breakdown],
      recentEvents: [...this.recentEvents],
      settings: { ...this.settings },
      scan: { ...this.scan },
      capabilities: { ...this.capabilities },
    };
  }

  private handleEvent(event: AvEvent): void {
    if (event.type === "heartbeat") {
      this.lastHeartbeatAt = Date.now();
      const activityValue =
        ACTIVITY_INCREMENT_BASE +
        Math.round(Math.random() * ACTIVITY_INCREMENT_VARIANCE);
      this.bumpActivity(activityValue);
      this.stats.dailyActivity += 1; // Increment on each heartbeat check
      this.setStatus("connected", "Live protection active");
    }

    if (event.type === "scan_progress") {
      const progress =
        typeof event.data?.progress === "number" ? event.data?.progress : 0;
      this.scan.inProgress = true;
      this.scan.progress = Math.min(MAX_PROGRESS, progress);
      this.scan.target =
        typeof event.data?.target === "string"
          ? event.data?.target
          : this.scan.target;
      this.bumpActivity(
        BUMP_ACTIVITY_MIN + Math.round(Math.random() * BUMP_ACTIVITY_VARIANCE),
      );
    }

    if (event.type === "threat_detected" || event.type === "quarantine") {
      this.stats.detections += 1;
      const isQuarantine =
        event.type === "quarantine" || event.data?.action === "quarantined";
      const action = isQuarantine ? "Quarantined" : "Blocked";
      this.incrementBreakdown(action);
      if (isQuarantine) {
        this.stats.quarantined += 1;
      }
      if (event.type === "threat_detected") {
        this.scan.inProgress = false;
        this.scan.progress = MAX_PROGRESS;
        this.scan.target = null;
        this.stats.lastScanAt = event.timestamp;
      }
    }

    if (event.type === "scan_complete") {
      this.scan.inProgress = false;
      this.scan.progress = MAX_PROGRESS;
      this.scan.target = null;
      this.stats.lastScanAt = event.timestamp;
      this.stats.lastScanDurationSec =
        typeof event.data?.durationSec === "number"
          ? event.data?.durationSec
          : null;
      this.bumpActivity(BUMP_ACTIVITY_ON_COMPLETE);
      this.incrementBreakdown("Clean"); // Most scanned files are clean in summary
    }

    if (event.type === "status") {
      const state =
        event.data?.state === "connected" ||
        event.data?.state === "disconnected"
          ? event.data?.state
          : undefined;
      const fatal = event.data?.fatal === true;
      if (state === "disconnected" && !this.userRequestedDisconnect && !fatal) {
        this.setStatus("reconnecting", "Connection lost, retrying");
        this.scheduleReconnect();
      } else if (state === "disconnected" && fatal) {
        this.setStatus("disconnected", event.message);
      }
    }

    if (event.type === "capabilities_update") {
      this.capabilities = { ...this.capabilities, ...(event.data as any) };
    }

    this.statusMessage = event.message;
    this.pushEvent(event.type, event.severity, event.message, event.data);
  }

  private pushEvent(
    type: AvEvent["type"],
    severity: AvEvent["severity"],
    message: string,
    data?: Record<string, unknown>,
  ): void {
    const event: AvEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type,
      severity,
      message,
      data,
    };

    this.recentEvents = [event, ...this.recentEvents].slice(0, MAX_EVENTS);
    this.sender("av:event", { event, snapshot: this.getSnapshot() });
  }

  private setStatus(state: AvConnectionState, message: string): void {
    this.connectionState = state;
    this.statusMessage = message;
  }

  private bumpActivity(value: number): void {
    const now = new Date();
    const label = now.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    // Keep 360 points (1 hour total at 10s interval, but heartbeat is 5s,
    // so 720 points for 1 hour at 5s interval)
    const next =
      this.activity.length >= MAX_POINTS
        ? this.activity.slice(1)
        : [...this.activity];
    next.push({
      time: label,
      value: value,
    });
    this.activity = next;
  }

  private incrementBreakdown(label: string): void {
    this.breakdown = this.breakdown.map((item) =>
      item.label === label ? { ...item, value: item.value + 1 } : item,
    );
  }

  private monitorHeartbeat(): void {
    if (this.connectionState !== "connected") {
      return;
    }

    if (
      this.lastHeartbeatAt &&
      Date.now() - this.lastHeartbeatAt > HEARTBEAT_TIMEOUT_MS
    ) {
      this.setStatus("reconnecting", "Heartbeat lost, reconnecting");
      this.pushEvent("status", "medium", "Heartbeat lost, reconnecting", {
        state: "reconnecting",
      });
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.userRequestedDisconnect || this.reconnectTimer) {
      return;
    }

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      await this.connect();
    }, RECONNECT_DELAY_MS);
  }
}

function seedActivity(): AvActivityPoint[] {
  const now = Date.now();
  const points: AvActivityPoint[] = [];
  for (let i = MAX_POINTS - 1; i >= 0; i -= 1) {
    const time = new Date(now - i * ACTIVITY_INTERVAL_MS);
    points.push({
      time: time.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
      value: 0, // Real data starts at 0
    });
  }
  return points;
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("Operation timed out")),
      ms,
    );
    promise
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}
