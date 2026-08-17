# Aydo Endpoint Protection Platform

Aydo is a Windows endpoint protection platform (EPP) that combines local
prevention, endpoint telemetry, static and dynamic analysis, and a desktop
management experience. The repository contains the endpoint service and kernel
driver, an Electron desktop application, a C++ backend, and an isolated VMware
sandbox pipeline.

## Main Components

| Path | Component | Purpose |
| --- | --- | --- |
| `Client/KernelDriver` | Kernel driver | Process protection and kernel-to-service communication |
| `Client/Service` | Endpoint service | Static scanning, real-time monitoring, server communication, and scan orchestration |
| `Client/GUI` | Desktop application | Electron, React, and TypeScript user interface |
| `server/Server` | Backend API | Drogon-based authentication, uploads, scan scheduling, and sandbox coordination |
| `server/VM/VMRunner` | Sandbox runner | VMware lifecycle, warm-VM pooling, payload execution, and result collection |
| `server/VM/ProcessMonitor` | VM telemetry | ETW collection, behavioral detections, and SQLite findings |
| `server/VM/ProcessRunner*` | Payload runner | Guest-side process launch and injection support |
| `Installer` | Windows installer | WiX installer and bootstrapper projects |

## Requirements

- Windows 10 or Windows 11, x64
- Visual Studio 2022 with the Desktop development with C++ workload
- Windows 10/11 SDK and WDK for the kernel driver
- C++20-capable MSVC toolchain (`v143`)
- VMware Workstation with `vmrun.exe` for dynamic analysis
- PostgreSQL for the backend
- Drogon and the native dependencies referenced by the Visual Studio projects
- Bun 1.1 or newer for the desktop application
- WiX Toolset 6 for installer builds
- Python 3 for database and rule update scripts

Some project files currently contain machine-specific native include and
library paths. Adjust them for your local vcpkg/SDK installation before building.

## Build the Native Solution

Open `Aydo.sln` in Visual Studio, select `x64` and the required configuration,
then build the solution. From a Visual Studio Developer PowerShell, the same can
be done with:

```powershell
msbuild .\Aydo.sln /m /p:Configuration=Release /p:Platform=x64
```

Build outputs are written under the solution's `x64/Release` or `x64/Debug`
directories, with some VM projects retaining project-local output folders.

## Desktop Application

```powershell
cd Client\GUI
bun install
bun run dev
```

Create a production bundle with `bun run build`, or package the application
with `bun run package`. The desktop client automatically uses a native engine
build when one is available and otherwise falls back to its simulator. See
[`Client/GUI/README.md`](Client/GUI/README.md) for engine overrides and E2E test
instructions.

## Backend Configuration

Copy the example configuration and replace every placeholder:

```powershell
Copy-Item server\Server\config.example.json server\Server\config.json
```

Configure at least:

- the PostgreSQL connection
- a strong JWT secret
- upload and scan-processing limits
- `custom_config.sandbox` paths and VMware guest settings

Do not commit production credentials or machine-specific secrets. The full
sandbox configuration contract is documented in
[`server/Server/config.example.json`](server/Server/config.example.json).

## Dynamic Analysis and Warm VM Pool

The backend launches `VMRunner.exe` with sandbox settings supplied through the
server configuration. VMRunner can preload reusable sandbox copies to reduce
scan startup time:

```powershell
.\x64\Release\VMRunner.exe --prepare-warm-pool
```

The server starts the preloader during startup and replenishes the pool after a
scan. VM state is stored below the configured sandbox directory. Run the
backend and VMware processes with only the permissions required by the target
environment.

Available diagnostics include:

```powershell
.\x64\Release\VMRunner.exe --self-test
.\x64\Release\Server.exe --self-test
```

The first command validates VM lifecycle and shared-folder behavior. The second
validates sandbox configuration parsing and result-path resolution.

## Endpoint Data and Rules

Generated databases and rule sets belong in `data/` and are intentionally not
stored in Git. Update them from the repository root:

```powershell
python scripts\update_file_hashes_db.py -d -e -p
python scripts\update_file_signatures_db.py -d -e -p
python scripts\update_yara_rules.py
python scripts\update_sigma_rules.py
```

The hash/signature source may require a manual ClamAV database download when
the upstream service blocks automated retrieval.

## Tests and Validation

- Build `Aydo.sln` for `x64` in Visual Studio or with MSBuild.
- Run `VMRunner.exe --self-test` and `Server.exe --self-test`.
- Run the ProcessMonitor deterministic and live tests described in
  [`server/VM/ProcessMonitor/README.md`](server/VM/ProcessMonitor/README.md).
- Run `bun run test:e2e` from `Client/GUI` for the desktop smoke tests.
- Run `python -m unittest discover -s tests/python -v` for update-script tests.
- Run `scripts/ci/run_native_tests.ps1` after a native Release build to execute
  all deterministic native self-tests.

VM integration tests require a configured VMware guest and cannot run safely
without the paths and credentials from the local server configuration.

## CI/CD

GitHub Actions runs the following checks for pull requests and pushes to the
release branches:

- Python update-script unit tests and bytecode compilation
- desktop TypeScript checks, production build, and Playwright Electron E2E tests
- Windows user-mode builds backed by the repository vcpkg manifest
- VMRunner, backend configuration, and ProcessMonitor self-tests
- kernel-driver project validation and WiX source validation

The endpoint service project is structurally validated in hosted CI, but its
binary build still requires the separately supplied YARA-X C API library. Run
`scripts/ci/run_native_tests.ps1` without `-SkipEndpointService` on a fully
provisioned build machine to include its deterministic self-test.

Tags matching `v*` run the release workflow, package the Windows desktop app,
upload the build artifact, and publish it to the matching GitHub Release. The
kernel driver requires the WDK and production signing credentials; signed
driver and full MSI publication should only be enabled after those secrets are
configured in the repository environment.

## Branch Promotion

Feature branches merge into `v4.0.0`, release changes are promoted to
`develop`, and validated releases are then promoted to `production`. Keep the
same tested commits throughout that sequence and do not force-push shared
branches.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).
