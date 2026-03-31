import type { AvEvent, AvSettings, HandshakeRequest, HandshakeResponse, ScanRequest, AvEngineType } from "@shared/antivirus";

export interface AntivirusEngine {
  handshake(request: HandshakeRequest): Promise<HandshakeResponse>;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  startScan(request: ScanRequest): Promise<void>;
  setSettings(settings: AvSettings): void;
  getSettings(): AvSettings;
  getType(): AvEngineType;
  onEvent(listener: (event: AvEvent) => void): () => void;
  isConnected(): boolean;
}
