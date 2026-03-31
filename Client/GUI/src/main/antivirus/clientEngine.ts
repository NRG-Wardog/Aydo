import { EventEmitter } from "node:events";
import { createConnection, Socket } from "node:net";
import { randomUUID } from "node:crypto";
import { createInterface } from "node:readline";
import fs from "node:fs";
import path from "node:path";
import type {
  AvEvent,
  AvSettings,
  HandshakeRequest,
  HandshakeResponse,
  ScanRequest,
  ScanDepth,
  Sensitivity,
} from "@shared/antivirus";
import { AV_PROTOCOL_VERSION } from "@shared/antivirus";
import type { AntivirusEngine } from "./engine";

const PIPE_NAME = "\\\\.\\pipe\\AydoServicePipe";
const RECONNECT_DELAY_MS = 3000;
const CONNECT_TIMEOUT_MS = 2200;

// Configurable defaults and thresholds
const SERVER_DEFAULT_URL = "http://192.168.56.1";
const DEFAULT_KILL_THRESHOLD = 150;
const DEFAULT_ENTROPY_THRESHOLD = 7.0;
const DEFAULT_RUNTIME = 60;
const MIN_KILL_THRESHOLD = 120;
const MAX_KILL_THRESHOLD = 190;
const MIN_RUNTIME = 35;
const MAX_RUNTIME = 100;

// Heartbeat ping generation
const PING_BASE_MS = 10; // base ping
const PING_VARIANCE_MS = 12; // additional random variance
const STATUS_COMMAND_PAYLOAD = `${JSON.stringify({ command: "status" })}\n`;

const ENGINE_VERSION = "client-1.0.0";

// Persistent config mapping for infected file actions
const INFECTED_ACTION_NONE = 0;
const INFECTED_ACTION_QUARANTINE = 1;
const INFECTED_ACTION_DELETE = 2;

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

const HEARTBEAT_INTERVAL_MS = 5000;

export type ClientEngineOptions = {
  binaryPath?: string;
  workingDir?: string;
  env?: NodeJS.ProcessEnv;
};

export class ClientEngine extends EventEmitter implements AntivirusEngine {
  private socket: Socket | null = null;
  private connected = false;
  private connectInFlight: Promise<void> | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private scanTimer: NodeJS.Timeout | null = null;
  private manualScanStartedAt: number | null = null;
  private manualScanTarget: string | null = null;
  private settings: AvSettings;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private userRequestedDisconnect = false;
  private workingDir: string;

  constructor(options: ClientEngineOptions = {}) {
    super();
    // Working dir logic is kept for config loading, even if we don't spawn
    this.workingDir = resolveWorkingDir(
      resolveBinaryPath(options.binaryPath),
      options.workingDir,
    );
    const config = readConfig(this.workingDir);
    const killThreshold = config.killThreshold ?? defaultSettings.killThreshold;
    const runtime = config.runtime ?? defaultSettings.runtime;
    this.settings = normalizeSettings({
      ...defaultSettings,
      ...config,
      sensitivity: deriveSensitivity(killThreshold),
      scanDepth: deriveScanDepth(runtime),
    });
  }

  isAvailable(): boolean {
    return true; // Always attempt to connect
  }

  async handshake(request: HandshakeRequest): Promise<HandshakeResponse> {
    if (request.protocolVersion !== AV_PROTOCOL_VERSION) {
      return {
        ok: false,
        engineVersion: "client-unknown",
        serverTime: new Date().toISOString(),
        message: "Protocol mismatch",
      };
    }

    return {
      ok: true,
      engineVersion: ENGINE_VERSION,
      serverTime: new Date().toISOString(),
    };
  }

  async connect(): Promise<void> {
    if (this.connected || this.socket) {
      return;
    }

    if (this.connectInFlight) {
      return this.connectInFlight;
    }

    this.userRequestedDisconnect = false;
    this.connectInFlight = this.attemptConnection().finally(() => {
      this.connectInFlight = null;
    });

    return this.connectInFlight;
  }

  private attemptConnection(): Promise<void> {
    if (this.socket) {
      return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
      this.emitEvent("status", "low", "Connecting to service...", {
        state: "connecting",
      });

      const socket = createConnection(PIPE_NAME, () => {
        this.socket = socket;
        this.connected = true;
        this.emitEvent("status", "low", "Connected to local service", {
          state: "connected",
        });
        this.startHeartbeat();
        socket.write(STATUS_COMMAND_PAYLOAD);

        // Setup line reader
        const rl = createInterface({ input: socket });
        rl.on("line", (line) => this.handleLine(line));
        resolve();
      });

      const connectTimeout = setTimeout(() => {
        socket.destroy();
        reject(new Error("Connection timed out"));
      }, CONNECT_TIMEOUT_MS);

      socket.once("connect", () => {
        clearTimeout(connectTimeout);
      });

      socket.on("error", (err) => {
        clearTimeout(connectTimeout);
        // If we are already connected, this is a drop.
        // If we are connecting, this is a failure.
        const msg = err.message;
        if (!this.connected) {
          reject(new Error(msg));
        } else {
          this.emitEvent("status", "medium", "Connection lost: " + msg, {
            state: "disconnected",
          });
        }
        this.cleanup();
        this.scheduleReconnect();
      });

      socket.on("close", () => {
        clearTimeout(connectTimeout);
        if (this.connected) {
          this.emitEvent("status", "medium", "Service disconnected", {
            state: "disconnected",
          });
        }
        this.cleanup();
        this.scheduleReconnect();
      });

      // We store temporary socket reference to allow cleanup on immediate error
      // But we don't assign to this.socket until 'connect' fires to avoid using half-open socket
      // actually, socket.on('error') might fire before connect.
    });
  }

  private scheduleReconnect() {
    if (this.userRequestedDisconnect || this.reconnectTimer) return;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.attemptConnection().catch(() => {});
    }, RECONNECT_DELAY_MS);
  }

  async disconnect(): Promise<void> {
    this.userRequestedDisconnect = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.socket) {
      this.socket.destroy(); // Force close
      this.socket = null;
    }
    this.connected = false;
    this.emitEvent("status", "medium", "Client engine disconnected", {
      state: "disconnected",
    });
    this.cleanup();
  }

  async startScan(request: ScanRequest): Promise<void> {
    if (!this.connected || !this.socket) {
      throw new Error("Engine not connected");
    }

    const target = request.paths?.[0];
    if (!target) {
      throw new Error("Scan target required");
    }

    if (this.manualScanStartedAt) {
      return;
    }

    this.manualScanStartedAt = Date.now();
    this.manualScanTarget = target;

    this.emitEvent("scan_progress", "low", "Manual scan started", {
      progress: 0,
      target,
    });

    this.socket.write(
      JSON.stringify({
        command: "scan",
        path: target,
        depth: request.depth,
      }) + "\n",
    );
  }

  setSettings(settings: AvSettings): void {
    const normalized = normalizeSettings(settings);
    this.settings = { ...normalized };
    ensureConfig(this.workingDir, this.settings);
    if (this.connected && this.socket) {
      this.socket.write(STATUS_COMMAND_PAYLOAD);
    }
    this.emitEvent("info", "low", "Client engine settings updated", {
      settings: this.settings,
    });
  }

  getSettings(): AvSettings {
    return { ...this.settings };
  }

  getType(): "client" {
    return "client";
  }

  onEvent(listener: (event: AvEvent) => void): () => void {
    this.on("event", listener);
    return () => this.off("event", listener);
  }

  isConnected(): boolean {
    return this.connected;
  }

  private startHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    this.heartbeatTimer = setInterval(() => {
      if (!this.connected || !this.socket) {
        return;
      }
      this.socket.write(JSON.stringify({ command: "ping" }) + "\n");

      this.emitEvent("heartbeat", "low", "Client heartbeat", {
        engineVersion: ENGINE_VERSION,
        pingMs: PING_BASE_MS + Math.round(Math.random() * PING_VARIANCE_MS),
      });
    }, HEARTBEAT_INTERVAL_MS);
  }

  private handleLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }

    try {
      const eventJson = JSON.parse(trimmed);

      // If it's a structured Protocol::Event
      if (eventJson.type && eventJson.severity) {
        const type = eventJson.type as AvEvent["type"];
        const severity = eventJson.severity as AvEvent["severity"];
        const message = eventJson.message || "";
        const data = eventJson.data || {};

        if (type === "capabilities_update") {
          this.emitEvent(type, severity, "Engine capabilities updated", data);
          return;
        }

        // Special handling for scan progress to ensure internal state is updated
        if (type === "scan_progress" && data.target) {
          this.manualScanTarget = data.target as string;
          if (!this.manualScanStartedAt) this.manualScanStartedAt = Date.now();
        }

        // Map complete/threat to reset state
        if (type === "scan_complete" || type === "threat_detected") {
          this.manualScanStartedAt = null;
          this.manualScanTarget = null;
        }

        this.emitEvent(type, severity, message, data);
        return;
      }
    } catch (e) {
      // Fallback for legacy or raw logs
      const lower = trimmed.toLowerCase();
      const logSeverity: AvEvent["severity"] =
        lower.includes("fatal") ||
        lower.includes("error") ||
        lower.includes("failed")
          ? "high"
          : lower.includes("warning")
            ? "medium"
            : "low";

      this.emitEvent("info", logSeverity, trimmed);
    }
  }

  private emitEvent(
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

    this.emit("event", event);
  }

  private cleanup(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = null;
    }

    // Do NOT clear socket here, it's cleared in disconnect/error logic carefully
    if (this.socket && this.socket.destroyed) {
      this.socket = null;
    }

    this.manualScanStartedAt = null;
    this.manualScanTarget = null;
    this.connected = false;
  }
}

// Helpers
const resolveBinaryPath = (explicitPath?: string): string | null => {
  const envPath = explicitPath ?? process.env.AYDO_ENGINE_PATH;
  if (envPath && fs.existsSync(envPath)) {
    return envPath;
  }

  const repoRoot = path.resolve(process.cwd(), "..", "..");
  const candidates = [
    path.join(repoRoot, "x64", "Release", "Service.exe"),
    path.join(repoRoot, "x64", "Debug", "Service.exe"),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
};

const resolveWorkingDir = (
  binaryPath: string | null,
  explicitDir?: string,
): string => {
  const envDir = explicitDir ?? process.env.AYDO_ENGINE_CWD;
  if (envDir) {
    return envDir;
  }

  if (binaryPath) {
    return path.resolve(path.dirname(binaryPath), "..", "..");
  }

  return process.cwd();
};

const readConfig = (workingDir: string): Partial<AvSettings> => {
  try {
    const configPath = path.join(workingDir, "..", "config.json");
    if (!fs.existsSync(configPath)) {
      return {};
    }
    const raw = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    return {
      serverUrl: typeof raw.serverUrl === "string" ? raw.serverUrl : undefined,
      accessToken:
        typeof raw.accessToken === "string" ? raw.accessToken : undefined,
      refreshToken:
        typeof raw.refreshToken === "string" ? raw.refreshToken : undefined,
      killThreshold: Number.isFinite(raw.killThreshold)
        ? raw.killThreshold
        : undefined,
      entropyThreshold: Number.isFinite(raw.entropyThreshold)
        ? raw.entropyThreshold
        : undefined,
      runtime: Number.isFinite(raw.runtime) ? raw.runtime : undefined,
      infectedFileAction:
        raw.infectedFileAction === INFECTED_ACTION_QUARANTINE
          ? "quarantine"
          : raw.infectedFileAction === INFECTED_ACTION_DELETE
            ? "delete"
            : "none",
    };
  } catch {
    return {};
  }
};

const deriveSensitivity = (killThreshold: number): Sensitivity => {
  if (killThreshold <= MIN_KILL_THRESHOLD) {
    return "aggressive";
  }
  if (killThreshold >= MAX_KILL_THRESHOLD) {
    return "low";
  }
  return "balanced";
};

const deriveScanDepth = (runtime: number): ScanDepth => {
  if (runtime <= MIN_RUNTIME) {
    return "quick";
  }
  if (runtime >= MAX_RUNTIME) {
    return "deep";
  }
  return "standard";
};

const normalizeSettings = (settings: AvSettings): AvSettings => {
  const killThreshold = Number.isFinite(settings.killThreshold)
    ? settings.killThreshold
    : defaultSettings.killThreshold;
  const entropyThreshold = Number.isFinite(settings.entropyThreshold)
    ? settings.entropyThreshold
    : defaultSettings.entropyThreshold;
  const runtime = Number.isFinite(settings.runtime)
    ? settings.runtime
    : defaultSettings.runtime;
  return {
    ...defaultSettings,
    ...settings,
    serverUrl: settings.serverUrl?.trim() || defaultSettings.serverUrl,
    accessToken: settings.accessToken ?? "",
    refreshToken: settings.refreshToken ?? "",
    killThreshold,
    entropyThreshold,
    runtime,
    infectedFileAction: settings.infectedFileAction || "none",
    sensitivity: deriveSensitivity(killThreshold),
    scanDepth: deriveScanDepth(runtime),
  };
};

const ensureConfig = (workingDir: string, settings: AvSettings): void => {
  try {
    const normalized = normalizeSettings(settings);
    fs.mkdirSync(workingDir, { recursive: true });
    const configPath = path.join(workingDir, "..", "config.json");
    const current = fs.existsSync(configPath)
      ? JSON.parse(fs.readFileSync(configPath, "utf-8"))
      : {};

    const next = {
      ...current,
      serverUrl: normalized.serverUrl,
      accessToken: normalized.accessToken,
      refreshToken: normalized.refreshToken,
      killThreshold: normalized.killThreshold,
      entropyThreshold: normalized.entropyThreshold,
      runtime: normalized.runtime,
      infectedFileAction:
        normalized.infectedFileAction === "quarantine"
          ? INFECTED_ACTION_QUARANTINE
          : normalized.infectedFileAction === "delete"
            ? INFECTED_ACTION_DELETE
            : INFECTED_ACTION_NONE,
    };

    fs.writeFileSync(configPath, JSON.stringify(next));
  } catch (error) {
    // Ignore config errors; engine will use defaults.
  }
};

const extractAfterColon = (value: string): string | null => {
  const index = value.indexOf(":");
  if (index === -1) {
    return null;
  }
  const target = value.slice(index + 1).trim();
  return target.length > 0 ? target : null;
};
