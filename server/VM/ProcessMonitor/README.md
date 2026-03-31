# ProcessMonitor

## What It Does

ProcessMonitor is an ETW-based telemetry and detection component for Windows.

It does 4 things continuously:
1. Captures kernel + user ETW events.
2. Normalizes events into Sigma-friendly columns.
3. Stores normalized events in SQLite (`Events` table).
4. Runs detection heuristics and stores detections in SQLite (`Findings` table).

Sysmon will implemented later.

## Detection Coverage

Current detector outputs (`Findings.Type`):
1. `RemoteThreadCreation`
2. `AsynchronousProcedureCallQueueing`
3. `ThreadHijackHeuristic`
4. `ThreatIntelInjection`
5. `RegistryRunKeyPersistence`
6. `ScheduledTaskPersistence`
7. `ServicePersistence`
8. `LsassCredentialAccess`

ATT&CK + prevention metadata is attached to both event rows and finding rows:
1. `AttackTactic`
2. `AttackTechnique`
3. `AttackSubTechnique`
4. `AttackReference`
5. `Prevention`

## Providers

User-session analyst provider profile:
1. `Microsoft-Windows-Kernel-Audit-API-Calls`
2. `Microsoft-Windows-Threat-Intelligence`
3. `Microsoft-Windows-TaskScheduler`
4. `Microsoft-Windows-Services`
5. `Microsoft-Windows-WMI-Activity`
6. `Microsoft-Windows-PowerShell`
7. `Microsoft-Windows-Bits-Client`
8. `Microsoft-Windows-CodeIntegrity`
9. `Microsoft-Windows-Windows Defender`
10. `Microsoft-Windows-DNS-Client`
11. `Microsoft-Windows-WinHTTP`

Missing providers are non-fatal (monitor continues).

## Build

From repo root:

```powershell
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64 -HostArch amd64
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" `
  "server\VM\ProcessMonitor\ProcessMonitor.vcxproj" `
  /nologo /m /p:Configuration=Debug /p:Platform=x64 /t:Build
```

Binary:

`server\VM\ProcessMonitor\x64\Debug\ProcessMonitor.exe`

## Run

CLI:

```text
ProcessMonitor.exe <exefile> <logFile> [TraceTime]
ProcessMonitor.exe --self-test
ProcessMonitor.exe --self-test-live
```

Parameters:
1. `exefile`: target executable file name (example: `notepad.exe`).
2. `logFile`: output SQLite DB path.
3. `TraceTime`: optional total runtime in seconds. Default is `60`.

Example:

```powershell
.\server\VM\ProcessMonitor\x64\Debug\ProcessMonitor.exe notepad.exe .\server\VM\ProcessMonitor\artifacts\notepad.sqlite 90
```

Notes:
1. x64 build has `requireAdministrator` manifest, so run elevated when needed.
2. If target process is not found before deadline, run exits with failure.

## Tests

Deterministic self-test:

```powershell
cmd /c "server\VM\ProcessMonitor\x64\Debug\ProcessMonitor.exe --self-test & echo EXITCODE:%ERRORLEVEL%"
```

Live smoke test:

```powershell
cmd /c "server\VM\ProcessMonitor\x64\Debug\ProcessMonitor.exe --self-test-live & echo EXITCODE:%ERRORLEVEL%"
```

`EXITCODE:0` means pass.

## Data Model (SQLite)

Main tables:
1. `Events`: normalized ETW events.
2. `Findings`: detector outputs.

Important `Events` columns:
1. Identity/time: `EventId`, `EventRecordId`, `EventTime`, `pid`, `tid`, `Provider`.
2. Process context: `Image`, `ProcessName`, `SourceImage`, `TargetImage`, `CommandLine`.
3. Security context: `ObjectName`, `TaskName`, `ServiceName`, `GrantedAccess`, `Status`.
4. ATT&CK metadata: `AttackTactic`, `AttackTechnique`, `AttackSubTechnique`, `AttackReference`, `Prevention`.

Important `Findings` columns:
1. `EventTime`, `Type`, `Severity`, `Confidence`.
2. `SourcePid`, `TargetPid`, `Tid`.
3. `EvidenceJson`.
4. `AttackTactic`, `AttackTechnique`, `AttackSubTechnique`, `AttackReference`, `Prevention`.

Schema migration is additive and idempotent for missing ATT&CK columns in legacy DB files.

## Real-Time Data View

Run monitor in terminal A, then in terminal B run:

```powershell
@'
import os
import sqlite3
import time

DB = r".\server\VM\ProcessMonitor\artifacts\notepad.sqlite"  # change path as needed
last_event = 0
last_finding = 0

while True:
    if not os.path.exists(DB):
        print(f"[wait] db not found: {DB}")
        time.sleep(1)
        continue

    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute("""
        SELECT rowid, EventTime, Provider, EventId, pid, tid, ProcessName, TaskName,
               ObjectName, SourceImage, TargetImage, GrantedAccess, AttackTechnique
        FROM Events
        WHERE rowid > ?
        ORDER BY rowid ASC
        LIMIT 200
    """, (last_event,))
    for row in cur.fetchall():
        last_event = row[0]
        print("[EVENT]", row)

    cur.execute("""
        SELECT rowid, EventTime, Type, Severity, Confidence, SourcePid, TargetPid,
               AttackTechnique, AttackSubTechnique
        FROM Findings
        WHERE rowid > ?
        ORDER BY rowid ASC
        LIMIT 200
    """, (last_finding,))
    for row in cur.fetchall():
        last_finding = row[0]
        print("[FINDING]", row)

    con.close()
    time.sleep(1)
'@ | python -
```

Quick one-shot queries:

```sql
SELECT EventTime, Provider, EventId, ProcessName, SourceImage, TargetImage, GrantedAccess, AttackTechnique
FROM Events
ORDER BY EventRecordId DESC
LIMIT 20;
```

```sql
SELECT EventTime, Type, Severity, Confidence, SourcePid, TargetPid, AttackTechnique, AttackSubTechnique
FROM Findings
ORDER BY EventTime DESC
LIMIT 20;
```
