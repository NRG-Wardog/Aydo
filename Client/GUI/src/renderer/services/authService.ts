import { useSyncExternalStore } from "react";
import { antivirusService } from "./antivirusService";

export type UserProfile = {
  name: string;
  email: string;
  role: string;
  avatarUrl?: string | null;
};

type AuthState = {
  user: UserProfile | null;
  loading: boolean;
  error: string | null;
};

const SERVER_DEFAULT_URL = "http://192.168.56.1";
const MIN_PASSWORD_LENGTH = 6;
const GUEST_SIM_DELAY_MS = 600;

class AuthService {
  private state: AuthState = {
    user: null,
    loading: true,
    error: null,
  };
  private listeners = new Set<() => void>();

  constructor() {
    void this.restoreSessionFromService();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  getState(): AuthState {
    return this.state;
  }

  getStoredServerUrl(): string {
    const configured = antivirusService.getState().settings.serverUrl?.trim();
    return configured && configured.length > 0
      ? configured
      : SERVER_DEFAULT_URL;
  }

  async login(
    email: string,
    password: string,
    serverUrl: string,
  ): Promise<{ ok: boolean; message: string }> {
    this.update({ loading: true, error: null });

    if (!email.includes("@") || password.length < MIN_PASSWORD_LENGTH) {
      this.update({
        loading: false,
        error:
          "Invalid credentials. Try a valid email and a stronger password.",
      });
      return { ok: false, message: "Invalid credentials" };
    }

    const bridge = typeof window !== "undefined" ? window.avBridge : undefined;
    if (!bridge) {
      const message =
        "Desktop bridge unavailable. Run the Electron app (bun run dev) instead of the browser URL.";
      this.update({ loading: false, error: message });
      return { ok: false, message };
    }

    const authResult = await bridge.authLogin({
      email,
      password,
      serverUrl,
    });

    if (!authResult.ok) {
      this.update({ loading: false, error: authResult.message });
      return { ok: false, message: authResult.message };
    }

    const hasAccessToken =
      typeof authResult.accessToken === "string" &&
      authResult.accessToken.trim().length > 0;
    const hasRefreshToken =
      typeof authResult.refreshToken === "string" &&
      authResult.refreshToken.trim().length > 0;
    if (authResult.offline || !hasAccessToken || !hasRefreshToken) {
      const message =
        "Authentication requires an online server session. Connect to the server or continue as guest.";
      this.update({ loading: false, error: message });
      return { ok: false, message };
    }

    const name = authResult.nickname ?? this.toDisplayName(email);

    this.update({
      loading: false,
      error: null,
      user: {
        name,
        email,
        role: "Sigma Rizzler",
        avatarUrl: null,
      },
    });

    await antivirusService.init();
    const currentSettings = antivirusService.getState().settings;
    await antivirusService.updateSettings({
      ...currentSettings,
      serverUrl,
      accessToken: authResult.accessToken,
      refreshToken: authResult.refreshToken,
    });
    await antivirusService.connect();

    return { ok: true, message: authResult.message };
  }

  async register(
    name: string,
    email: string,
    password: string,
    serverUrl: string,
  ): Promise<{ ok: boolean; message: string }> {
    this.update({ loading: true, error: null });

    if (!name.trim()) {
      this.update({ loading: false, error: "Please enter your name." });
      return { ok: false, message: "Missing name" };
    }

    if (!email.includes("@") || password.length < MIN_PASSWORD_LENGTH) {
      this.update({
        loading: false,
        error: "Invalid details. Use a valid email and at least 6 characters.",
      });
      return { ok: false, message: "Invalid details" };
    }

    const bridge = typeof window !== "undefined" ? window.avBridge : undefined;
    if (!bridge) {
      const message =
        "Desktop bridge unavailable. Run the Electron app (bun run dev) instead of the browser URL.";
      this.update({ loading: false, error: message });
      return { ok: false, message };
    }

    const authResult = await bridge.authRegister({
      email,
      password,
      nickname: name,
      serverUrl,
    });

    if (!authResult.ok) {
      this.update({ loading: false, error: authResult.message });
      return { ok: false, message: authResult.message };
    }

    const hasAccessToken =
      typeof authResult.accessToken === "string" &&
      authResult.accessToken.trim().length > 0;
    const hasRefreshToken =
      typeof authResult.refreshToken === "string" &&
      authResult.refreshToken.trim().length > 0;
    if (authResult.offline || !hasAccessToken || !hasRefreshToken) {
      const message =
        "Registration requires an online server session. Connect to the server or continue as guest.";
      this.update({ loading: false, error: message });
      return { ok: false, message };
    }

    this.update({
      loading: false,
      error: null,
      user: {
        name: authResult.nickname ?? name,
        email,
        role: "Sigma Rizzler",
        avatarUrl: null,
      },
    });

    await antivirusService.init();
    const currentSettings = antivirusService.getState().settings;
    await antivirusService.updateSettings({
      ...currentSettings,
      serverUrl,
      accessToken: authResult.accessToken,
      refreshToken: authResult.refreshToken,
    });
    await antivirusService.connect();

    return { ok: true, message: authResult.message };
  }

  setAvatar(avatarUrl: string | null): void {
    if (!this.state.user) {
      return;
    }

    this.update({
      user: {
        ...this.state.user,
        avatarUrl,
      },
    });
  }

  async continueAsGuest(): Promise<{ ok: boolean }> {
    this.update({ loading: true, error: null });

    // Simulate a short delay for premium feel
    await new Promise((resolve) => setTimeout(resolve, GUEST_SIM_DELAY_MS));

    this.update({
      loading: false,
      error: null,
      user: {
        name: "Smooth Operator",
        email: "guest@aydo.ontop",
        role: "SKIBIDI!!!",
        avatarUrl: null,
      },
    });

    await antivirusService.init();
    const currentSettings = antivirusService.getState().settings;
    await antivirusService.updateSettings({
      ...currentSettings,
      accessToken: "",
      refreshToken: "",
    });
    await antivirusService.connect();

    return { ok: true };
  }

  logout(): void {
    this.update({ user: null, loading: false, error: null });
    antivirusService.disconnect();
    antivirusService.updateSettings({
      ...antivirusService.getState().settings,
      accessToken: "",
      refreshToken: "",
    });
  }

  private update(partial: Partial<AuthState>): void {
    this.state = { ...this.state, ...partial };
    this.listeners.forEach((listener) => listener());
  }

  private async restoreSessionFromService(): Promise<void> {
    const bridge = typeof window !== "undefined" ? window.avBridge : undefined;
    if (!bridge?.authSession) {
      this.update({ loading: false });
      return;
    }

    const session = await bridge.authSession();
    if (!session.ok || !session.email) {
      this.update({ loading: false });
      return;
    }

    this.update({
      loading: false,
      user: {
        name: session.nickname ?? this.toDisplayName(session.email),
        email: session.email,
        role: "Sigma Rizzler",
        avatarUrl: null,
      },
      error: null,
    });
  }

  private toDisplayName(email: string): string {
    return email
      .split("@")[0]
      .replace(/\./g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }
}

export const authService = new AuthService();

export const useAuth = (): AuthState =>
  useSyncExternalStore(
    (listener) => authService.subscribe(listener),
    () => authService.getState(),
    () => authService.getState(),
  );
