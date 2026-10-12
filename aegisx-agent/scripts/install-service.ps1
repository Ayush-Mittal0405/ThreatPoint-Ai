<#
.SYNOPSIS
    Install (or remove) the AegisX agent as a background auto-start task.
.DESCRIPTION
    Registers a Scheduled Task named "AegisXAgent" that runs the agent at system
    startup under the SYSTEM account with highest privileges (required for the
    Windows Security event-log and network collectors). This is the development
    "service" mechanism; a packaged Windows Service (via pywin32 or NSSM) is the
    next step documented in the installation guide.

    Enroll the machine first with enroll.ps1 so the agent has a credential.
.PARAMETER Uninstall
    Remove the scheduled task instead of installing it.
.EXAMPLE
    .\install-service.ps1
    .\install-service.ps1 -Uninstall
#>
param(
    [switch]$Uninstall,
    [string]$Config = "$PSScriptRoot\..\config\agent.yaml",
    [string]$Python = "python",
    [string]$TaskName = "AegisXAgent"
)

$ErrorActionPreference = "Stop"

# Require elevation — creating a SYSTEM startup task needs admin rights.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run this script from an elevated (Administrator) PowerShell."
    exit 1
}

if ($Uninstall) {
    schtasks /Delete /TN $TaskName /F
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Yellow
    exit 0
}

$AgentRoot = (Resolve-Path "$PSScriptRoot\..").Path
$Venv = Join-Path $AgentRoot ".venv"
if (-not (Test-Path $Venv)) { & $Python -m venv $Venv }
$VenvPy = Join-Path $Venv "Scripts\python.exe"
& $VenvPy -m pip install --upgrade pip | Out-Null
& $VenvPy -m pip install -e $AgentRoot | Out-Null

$ConfigFull = (Resolve-Path $Config).Path
$Action = "`"$VenvPy`" -m aegisx_agent --config `"$ConfigFull`""

Write-Host "Registering scheduled task '$TaskName' (runs at startup as SYSTEM) ..."
schtasks /Create /TN $TaskName /TR $Action /SC ONSTART /RU "SYSTEM" /RL HIGHEST /F

Write-Host "Starting task now ..."
schtasks /Run /TN $TaskName

Write-Host "Installed. Check status with:  schtasks /Query /TN $TaskName" -ForegroundColor Green
Write-Host "Agent logs: (state_dir)\logs\aegisx-agent.log"
