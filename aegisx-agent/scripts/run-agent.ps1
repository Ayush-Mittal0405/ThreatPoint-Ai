<#
.SYNOPSIS
    Set up dependencies and run the AegisX endpoint agent in the foreground.
.DESCRIPTION
    Creates a local virtual environment under the agent folder, installs the
    agent (editable) and its dependencies, then runs it against the given config.
    Use this for development / verification. For unattended startup use
    install-service.ps1.
.EXAMPLE
    .\run-agent.ps1 -Config ..\config\agent.yaml
#>
param(
    [string]$Config = "$PSScriptRoot\..\config\agent.yaml",
    [string]$Server,
    [switch]$Insecure,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$AgentRoot = Resolve-Path "$PSScriptRoot\.."
$Venv = Join-Path $AgentRoot ".venv"

if (-not (Test-Path $Venv)) {
    Write-Host "Creating virtual environment at $Venv ..."
    & $Python -m venv $Venv
}

$VenvPy = Join-Path $Venv "Scripts\python.exe"
Write-Host "Installing agent and dependencies ..."
& $VenvPy -m pip install --upgrade pip | Out-Null
& $VenvPy -m pip install -e $AgentRoot | Out-Null

if (-not (Test-Path $Config)) {
    Write-Warning "Config not found at $Config. Copy config\agent.example.yaml to config\agent.yaml and edit it."
    exit 1
}

if ($Server)   { $env:AEGISX_AGENT_SERVER_URL = $Server }
if ($Insecure) { $env:AEGISX_AGENT_VERIFY_TLS = "false" }

Write-Host "Starting AegisX agent (Ctrl+C to stop) ..."
& $VenvPy -m aegisx_agent --config $Config
