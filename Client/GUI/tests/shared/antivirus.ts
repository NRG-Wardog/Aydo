export const AV_PROTOCOL_VERSION = 1;

export type AvConnectionState = "disconnected" | "connecting" | "connected" | "reconnecting";
export type AvSeverity = "low" | "medium" | "high";
export type AvEventType =
  | "heartbeat"
  | "scan_progress"
  | "scan_complete"
  | "threat_detected"
  | "quarantine"
  | "status"
  | "info";

export type AvEngineType = "client" | "simulator";
export type Sensitivity = "low" | "balanced" | "aggressive";
export type ScanDepth = "quick" | "standard" | "deep";

export interface AvSettings {
  sensitivity: Sensitivity;
  realtime: boolean;
  startupScan: boolean;
  scanDepth: ScanDepth;
  telemetry: boolean;
  serverUrl: string;
  accessToken: string;
  refreshToken: string;
  killThreshold: number;
  entropyThreshold: number;
  runtime: number;
}

export interface AvStats {
  dailyActivity: number;
  detections: number;
  quarantined: number;
  lastScanAt: string | null;
  lastScanDurationSec: number | null;
}

export interface AvActivityPoint {
  time: string;
  value: number;
}

export interface AvBreakdownItem {
  label: string;
  value: number;
}

export interface AvEvent {
  id: string;
  timestamp: string;
  type: AvEventType;
  severity: AvSeverity;
  message: string;
  data?: Record<string, unknown>;
}

export interface AvScanState {
  inProgress: boolean;
  progress: number;
  target?: string | null;
}

export interface AvSnapshot {
  engineType: AvEngineType;
  connectionState: AvConnectionState;
  statusMessage: string;
  stats: AvStats;
  activity: AvActivityPoint[];
  breakdown: AvBreakdownItem[];
  recentEvents: AvEvent[];
  settings: AvSettings;
  scan: AvScanState;
}

export interface AvEventEnvelope {
  event: AvEvent;
  snapshot: AvSnapshot;
}

export interface HandshakeRequest {
  protocolVersion: number;
  clientId: string;
  token: string;
}

export interface HandshakeResponse {
  ok: boolean;
  engineVersion: string;
  serverTime: string;
  message?: string;
}

export interface ScanRequest {
  depth: ScanDepth;
  paths?: string[];
}
