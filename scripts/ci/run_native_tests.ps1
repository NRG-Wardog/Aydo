param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$SkipEndpointService
)

$ErrorActionPreference = "Stop"

function Find-Binary {
    param([string[]]$Candidates)
    foreach ($candidate in $Candidates) {
        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }
    throw "Required binary was not found. Checked: $($Candidates -join ', ')"
}

function Invoke-SelfTest {
    param([string]$Name, [string]$Executable)
    Write-Host "::group::$Name self-test"
    & $Executable --self-test
    if ($LASTEXITCODE -ne 0) {
        throw "$Name self-test failed with exit code $LASTEXITCODE"
    }
    Write-Host "::endgroup::"
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$solutionOutput = Join-Path $root "x64\$Configuration"

$vmRunner = Find-Binary @(
    (Join-Path $solutionOutput "VMRunner.exe"),
    (Join-Path $root "server\VM\VMRunner\x64\$Configuration\VMRunner.exe")
)
$server = Find-Binary @(
    (Join-Path $solutionOutput "Server.exe"),
    (Join-Path $root "server\Server\x64\$Configuration\Server.exe")
)
$processMonitor = Find-Binary @(
    (Join-Path $solutionOutput "ProcessMonitor.exe"),
    (Join-Path $root "server\VM\ProcessMonitor\bin\x64\$Configuration\ProcessMonitor.exe")
)

Invoke-SelfTest "VMRunner" $vmRunner
if (-not $SkipEndpointService) {
    $service = Find-Binary @(
        (Join-Path $solutionOutput "Service.exe"),
        (Join-Path $root "Client\Service\x64\$Configuration\Service.exe")
    )
    Invoke-SelfTest "Endpoint service" $service
}
Invoke-SelfTest "Server configuration" $server
Invoke-SelfTest "ProcessMonitor" $processMonitor
