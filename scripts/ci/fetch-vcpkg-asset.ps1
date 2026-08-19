param(
    [Parameter(Mandatory = $true)]
    [string]$Url,
    [Parameter(Mandatory = $true)]
    [string]$Sha512,
    [Parameter(Mandatory = $true)]
    [string]$Destination
)

$ErrorActionPreference = "Stop"
$uri = [Uri]$Url
$githubHosts = @("github.com", "api.github.com", "codeload.github.com")
$arguments = @(
    "--fail",
    "--location",
    "--retry", "5",
    "--retry-all-errors",
    "--output", $Destination
)

if ($githubHosts -contains $uri.Host -and $env:GITHUB_TOKEN) {
    $arguments += @("--header", "Authorization: Bearer $env:GITHUB_TOKEN")
}

$arguments += $Url
& curl.exe @arguments

if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
    exit $LASTEXITCODE
}

