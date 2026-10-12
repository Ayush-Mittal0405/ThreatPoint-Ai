<#
.SYNOPSIS
    One-time enrollment of this machine as an AegisX endpoint agent.
.DESCRIPTION
    Exchanges a one-time enrollment token (issued by the SOC admin) for a
    permanent agent identity + credential, stored under the agent state
    directory. Run this once before starting the agent/service.
.PARAMETER Insecure
    Accept a self-signed server TLS certificate (demo/lab only).
.EXAMPLE
    .\enroll.ps1 -Token "PASTE-ENROLLMENT-TOKEN" -Server "https://aegisx.example.com:8008"
.EXAMPLE
    .\enroll.ps1 -Token "TOKEN" -Server "https://192.168.1.10:8008" -Insecure
#>
param(
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$Server,
    [switch]$Insecure,
    [string]$Config = "$PSScriptRoot\..\config\agent.yaml",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$AgentRoot = Resolve-Path "$PSScriptRoot\.."
$Venv = Join-Path $AgentRoot ".venv"
if (-not (Test-Path $Venv)) { & $Python -m venv $Venv }
$VenvPy = Join-Path $Venv "Scripts\python.exe"
& $VenvPy -m pip install --upgrade pip | Out-Null
& $VenvPy -m pip install -e $AgentRoot | Out-Null

$serverArgs = @()
if ($Server) {
    $serverArgs = @("--server", $Server)
    # Also set the env override so the URL applies even if the config file is
    # missing or wasn't saved.
    $env:AEGISX_AGENT_SERVER_URL = $Server
}
if ($Insecure) { $env:AEGISX_AGENT_VERIFY_TLS = "false" }

if (-not (Test-Path $Config)) {
    Write-Warning "No config at $Config - using defaults plus any -Server/-Insecure overrides."
}

Write-Host "Enrolling with AegisX server ..."
& $VenvPy -m aegisx_agent --enroll --config $Config --token $Token @serverArgs
if ($LASTEXITCODE -eq 0) {
    Write-Host "Enrollment complete. Verify with:  .\status.ps1" -ForegroundColor Green
    & $VenvPy -m aegisx_agent --status --config $Config
} else {
    Write-Error "Enrollment failed (exit $LASTEXITCODE). Check the token, server URL, and TLS settings."
}
