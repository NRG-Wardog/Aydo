# Aydo Desktop (Electron + Bun)

Premium desktop console for Aydo Security. UI, service layer, Electron main process, and antivirus engine are explicitly separated to keep the renderer clean and production-ready.

## Requirements

- Bun (only package manager / runner)

## Setup

```bash
cd apps/desktop
bun install
```

## Development

```bash
bun run dev
```

## Build

```bash
bun run build
```

## Package (Distribution)

```bash
bun run package
```

The package step uses `electron-builder` via `bunx` and writes artifacts to `apps/desktop/release`.

## Run With the Native Client Engine

### 1) Build the native client

Open `Aydo.sln` in Visual Studio and build **x64 Release** (or Debug). The desktop app auto-detects one of:

- `x64/Release/Service.exe`
- `x64/Debug/Service.exe`
- `x64/Release/ProcessMonitor.exe`
- `x64/Debug/ProcessMonitor.exe`

### 2) Configure runtime (optional)

Create or edit `config.json` in the repo root. Example:

```json
{
  "serverUrl": "http://127.0.0.1",
  "accessToken": "token-if-available",
  "refreshToken": "token-if-available",
  "killThreshold": 150,
  "entropyThreshold": 6,
  "runtime": 60
}
```

- If the server is offline, the app signs in **offline** and still allows **static file scans**.
- Tokens are optional for offline scanning; cloud sync is disabled without them.

### 3) Start the desktop app

```bash
cd apps/desktop
AYDO_ENGINE=client bun run dev
```

Optional overrides:

- `AYDO_ENGINE_PATH` – explicit path to `Service.exe` / `ProcessMonitor.exe`
- `AYDO_ENGINE_CWD` – working directory containing `config.json` and data files

The login screen no longer asks for a server IP; it uses `config.json` or the engine defaults.

## E2E Smoke Tests

```bash
bun run test:e2e
```

The test runner uses Playwright. Install browsers once:

```bash
bunx playwright install
```

## Architecture Overview

- `src/renderer/`
  - React + TypeScript UI
  - **No direct IPC access**
  - Talks only to the service layer
- `src/renderer/services/`
  - Renderer-side service layer
  - Minimal state cache + event-driven updates
  - Only place that calls the preload API
- `src/preload/`
  - Minimal, explicit API exposed with `contextBridge`
- `src/main/`
  - Electron main process
  - IPC handlers and antivirus bridge
- `src/main/antivirus/`
  - Engine interface, simulator, and bridge
  - Protocol handshake and auto-reconnect logic

## Branding Assets

App icon sources live in `assets/brand`:

- `icon.png` – 1024×1024 PNG
- `icon.ico` – Windows icon for packaging

## Antivirus Engine Pipeline

The bridge exposes a message-driven protocol with:

- Versioned handshake (`AV_PROTOCOL_VERSION`)
- Timeout protection (`CONNECT_TIMEOUT_MS`)
- Basic authorization token
- Auto-reconnect on heartbeat loss

### Engine Selection (Dev)

Control which engine runs behind the UI:

- `AYDO_ENGINE=simulator` – always use the simulator
- `AYDO_ENGINE=client` – force the native client engine
- default (`auto`) – use the client engine if the binary is found, otherwise fallback to simulator

Optional paths:

- `AYDO_ENGINE_PATH` – explicit path to `Service.exe` / `ProcessMonitor.exe`
- `AYDO_ENGINE_CWD` – working directory containing `config.json` and data files

Auto-detect checks (in order) `x64/Release/Service.exe`, `x64/Debug/Service.exe`,
`x64/Release/ProcessMonitor.exe`, `x64/Debug/ProcessMonitor.exe` at the repo root.

To speed up simulator events (used by E2E tests):

```bash
AYDO_SIM_FAST=1 bun run dev
```

### Swap Simulator With Real Engine

1. Create a new engine class implementing `AntivirusEngine` in `src/main/antivirus/`.
2. Replace the `AntivirusSimulator` in `AntivirusBridge` with your real engine.
3. Keep the protocol shape (`HandshakeRequest`, `ScanRequest`, events) to avoid UI changes.

## Bun-Only Guarantee

All commands are `bun run` or `bunx`. No npm, yarn, or pnpm scripts are used.
